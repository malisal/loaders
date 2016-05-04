// References:
// https://github.com/stephenfewer/ReflectiveDLLInjection/blob/master/dll/src/ReflectiveLoader.c
// https://github.com/blole/injectory/blob/master/injectory/manualmap.cpp
// http://www.cultdeadcow.com/tools/peload/peloader.c

#if !defined(NAKED)
#include <stdint.h>
#include <windows.h>

#define KERNEL32_DLL_HASH 0x6ddb9555

static uint32_t hash(char *str)
{
   uint32_t hash = 5381;
   int c;

   while((c = *str++))
      hash = ((hash << 5) + hash) + c; // hash * 33 + c

   return hash;
}

static uint32_t hash_skip(char *str)
{
   uint32_t hash = 5381;
   int c;

   while((c = *str))
   {
      hash = ((hash << 5) + hash) + c; // hash * 33 + c
      str += 2;
   }

   return hash;
}

static void *get_peb()
{
   void *ptr;

#ifdef WIN64
   __asm__ volatile(
      "movq %%gs:0x60, %0\n"
      : "=r" (ptr)
      : 
      :
   );
#else
   __asm__ volatile(
      "movl %%fs:0x30, %0\n"
      : "=r" (ptr)
      : 
      :
   );
#endif

   return ptr;
}

#else
   #include <system/syscall.h>
#endif

#include "pe.h"


int pe_is_dll(char *data)
{
   IMAGE_DOS_HEADER *dh = (IMAGE_DOS_HEADER *)data;
   IMAGE_NT_HEADERS *nh = (IMAGE_NT_HEADERS *)(data + dh->e_lfanew);

   // Check if the file is a DLL
   return (nh->FileHeader.Characteristics & IMAGE_FILE_DLL) != 0;
}

void pe_load(boot_func_t *funcs, char *data, size_t *base, size_t *entry)
{
   int x, y;

   IMAGE_DOS_HEADER *dh = (IMAGE_DOS_HEADER *)data;
   IMAGE_NT_HEADERS *nh = (IMAGE_NT_HEADERS *)(data + dh->e_lfanew);
   
   ULONG_PTR uiBaseAddress = (ULONG_PTR)funcs->win_VirtualAlloc((void *)nh->OptionalHeader.ImageBase, nh->OptionalHeader.SizeOfImage, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);

   if(!uiBaseAddress)
   {
      // We failed to allocate the chosen region. Choose a random one
      //TODO
      uiBaseAddress = (ULONG_PTR)funcs->win_VirtualAlloc(0, nh->OptionalHeader.SizeOfImage, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
   }

   ULONG_PTR uiLibraryAddress = uiBaseAddress - nh->OptionalHeader.ImageBase;

   // Copy over the headers
   memcpy((void *)uiBaseAddress, (void *)data, nh->OptionalHeader.SizeOfHeaders);

   IMAGE_NT_HEADERS *nh_new = (IMAGE_NT_HEADERS *)(uiBaseAddress + dh->e_lfanew);
   nh_new->OptionalHeader.ImageBase = uiBaseAddress;

   IMAGE_SECTION_HEADER *sec = (IMAGE_SECTION_HEADER *)((char *)&nh->OptionalHeader + nh->FileHeader.SizeOfOptionalHeader);

   //
   // Load all the sections
   // We disregard section permissions (all are RWX)
   //
   for(x = 0; x < nh->FileHeader.NumberOfSections; x++)
      memcpy((char *)uiBaseAddress + sec[x].VirtualAddress, (char *)data + sec[x].PointerToRawData, sec[x].SizeOfRawData);

   IMAGE_IMPORT_DESCRIPTOR *imp_desc = (IMAGE_IMPORT_DESCRIPTOR *)(uiBaseAddress + nh->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);

   //
   // Build import table
   //
   for(x = 0; imp_desc[x].Name; x++)
   {
      FARPROC *addr;
      HANDLE handle = funcs->win_LoadLibrary((char *)(uiBaseAddress + imp_desc[x].Name));

      IMAGE_THUNK_DATA *thunk_data_out;
      IMAGE_THUNK_DATA *thunk_data_in;

      if(imp_desc[x].OriginalFirstThunk)
         thunk_data_in = (IMAGE_THUNK_DATA *)(uiBaseAddress + imp_desc[x].OriginalFirstThunk);
      else
         thunk_data_in = (IMAGE_THUNK_DATA *)(uiBaseAddress + imp_desc[x].FirstThunk);
      
      thunk_data_out = (IMAGE_THUNK_DATA *)(uiBaseAddress + imp_desc[x].FirstThunk);

      for(y = 0; thunk_data_in[y].u1.AddressOfData != 0; y++)
      {
         if(thunk_data_in[y].u1.Ordinal & IMAGE_ORDINAL_FLAG) 
         {
            // No name, just ordinal
            // http://www.cultdeadcow.com/tools/peload/peloader.c
            addr = (FARPROC *)funcs->win_GetProcAddress(handle, MAKEINTRESOURCE(LOWORD(thunk_data_in[y].u1.Ordinal)));
            // FIXME: Does this ever happen?
            while(1);
         }
         else
         {
            IMAGE_IMPORT_BY_NAME *img_imp = (IMAGE_IMPORT_BY_NAME *)(uiBaseAddress + thunk_data_in[y].u1.AddressOfData);
            addr = (FARPROC *)funcs->win_GetProcAddress(handle, (LPCSTR)img_imp->Name);
         }

         // Patch the resolved address in
         thunk_data_out[y].u1.Function = (size_t) addr; 
      }
   }

   //
   // Parse relocations
   //
   if(nh->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size)
   {
      IMAGE_BASE_RELOCATION *reloc = (IMAGE_BASE_RELOCATION *)(uiBaseAddress + nh->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);

      while(reloc->VirtualAddress > 0)
      {
         size_t ptr = uiBaseAddress + reloc->VirtualAddress;
         IMAGE_RELOC *relInfo = (IMAGE_RELOC *)(((size_t) reloc) + sizeof(IMAGE_BASE_RELOCATION));

         for(x = 0; x < (reloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(IMAGE_RELOC); x++, relInfo++)
         {
            switch(relInfo->type)
            {
               case IMAGE_REL_BASED_DIR64:
                  *((ULONG_PTR*)(ptr + relInfo->offset)) += uiLibraryAddress;
                  break;   

               case IMAGE_REL_BASED_HIGHLOW:
                  *((DWORD*)(ptr + relInfo->offset)) += (DWORD) uiLibraryAddress;
                  break;

               case IMAGE_REL_BASED_HIGH:
                  *((WORD*)(ptr + relInfo->offset)) += HIWORD(uiLibraryAddress);
                  break;

               case IMAGE_REL_BASED_LOW:
                  *((WORD*)(ptr + relInfo->offset)) += LOWORD(uiLibraryAddress);
                  break;

               case IMAGE_REL_BASED_ABSOLUTE:
                  break;

               default:
                  //printf("Unknown relocation type: 0x%08x\n", relInfo->type);
                  break;
            }
         }
         reloc = (IMAGE_BASE_RELOCATION *)((char *)reloc + reloc->SizeOfBlock);
      }
   }

   // TODO: Don't think this is needed
   // Fixup the PEB
//   PEB *peb = (PEB *)get_peb();
//   peb->lpImageBaseAddress = (LPVOID) uiBaseAddress;

   //
   // Call TLS callback functions, if any
   //
   if(nh->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].Size)
   {
      PIMAGE_TLS_DIRECTORY tls = (PIMAGE_TLS_DIRECTORY)(uiBaseAddress + nh->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress);
      PIMAGE_TLS_CALLBACK *callback = (PIMAGE_TLS_CALLBACK *) tls->AddressOfCallBacks;

      while(*callback)
      {
         (*callback)((LPVOID) uiBaseAddress, DLL_PROCESS_ATTACH, NULL);
         callback++;
      }
   }

   // At the very end, set all section permissions
   for(x = 0; x < nh->FileHeader.NumberOfSections; x++)
   {
      DWORD oldFlags;
      DWORD flags = 0;

      if(sec[x].Characteristics & IMAGE_SCN_MEM_READ)
         flags |= PAGE_READONLY;

      if(sec[x].Characteristics & IMAGE_SCN_MEM_WRITE)
         flags |= PAGE_READWRITE;

      else if(sec[x].Characteristics & IMAGE_SCN_MEM_EXECUTE)
         flags |= PAGE_EXECUTE;

      funcs->win_VirtualProtect((char *)uiBaseAddress + sec[x].VirtualAddress, sec[x].Misc.VirtualSize, flags, &oldFlags);
   }

   *base = uiBaseAddress;
   *entry = uiBaseAddress + nh->OptionalHeader.AddressOfEntryPoint;
}

void pe_bootstrap(boot_func_t *funcs)
{
   int x;
   PEB *peb = get_peb();

   PEB_LDR_DATA *ldr = peb->pLdr;
   LDR_DATA_TABLE_ENTRY *e = (LDR_DATA_TABLE_ENTRY *) ldr->InMemoryOrderModuleList.Flink->Flink;

   for(; e->BaseDllName.pBuffer; e = (LDR_DATA_TABLE_ENTRY *) e->InMemoryOrderModuleList.Flink)
   {
      // We want to minimize the chance of symbol collisions
      if(hash_skip((char *)e->BaseDllName.pBuffer) != KERNEL32_DLL_HASH)
         continue;

      IMAGE_DOS_HEADER *dh = e->DllBase;
      ULONG_PTR base = (ULONG_PTR) e->DllBase;
      IMAGE_NT_HEADERS *nh = (IMAGE_NT_HEADERS *)(base + dh->e_lfanew);
      IMAGE_EXPORT_DIRECTORY *ed = (IMAGE_EXPORT_DIRECTORY *)(base + nh->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
      
      DWORD *names = (DWORD *)(base + ed->AddressOfNames);
      DWORD *ptrs = (DWORD *)(base + ed->AddressOfFunctions);
      WORD *ord = (WORD * )(base + ed->AddressOfNameOrdinals);

      for(x = 0; x < ed->NumberOfNames; x++)
      {
         char *sym_name = (char *)(base + names[x]);
         size_t sym_val = base + ptrs[ord[x]];

         switch(hash(sym_name))
         {
            case 0x5fbff0fb:
               funcs->win_LoadLibrary = (ptr_LoadLibrary) sym_val;
               break;

            case 0xcf31bb1f:
               funcs->win_GetProcAddress = (ptr_GetProcAddress) sym_val;
               break;

            case 0x382c0f97:
               funcs->win_VirtualAlloc = (ptr_VirtualAlloc) sym_val;
               break;

            case 0x844ff18d:
               funcs->win_VirtualProtect = (ptr_VirtualProtect) sym_val;
               break;
         }
      }

      return;
   }
}

