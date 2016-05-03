#if defined(NAKED)
   #include <system/syscall.h>
#else
   #include <stdio.h>
   #include <unistd.h>
#endif

#include "macho.h"

// DJB's string hash
static uint32_t hash_djb(char *str)
{
   int c;
   uint32_t hash = 5381;

   while((c = *str++))
      hash = ((hash << 5) + hash) + c; // hash * 33 + c

   return hash;
}

static int macho_parse(mach_header_t *mh, func_t *funcs)
{
   int x,y;

   segment_command_t *seg;
   segment_command_t *seg_linkedit;
   segment_command_t *seg_text;
   symtab_command_t *sym;
   dylib_command_t *dlb;

   nlist_t *nls;
   char *strtab;

   // Sometimes, we can find our own image in memory, so unless we see a LC_ID_DYLIB
   // that matches our needed string, treat this as a failure
   int ret = 0;

   load_command_t *cmd = (load_command_t *)&mh[1];

   for(x = 0; x < mh->ncmds; x++)
   {
      switch(cmd->cmd)
      {
         case LC_SEGMENT_64:
         case LC_SEGMENT:
            seg = (segment_command_t *)cmd;
            
            // __LINKEDIT
            if(hash_djb(seg->segname) == 0xc214bfb7)
               seg_linkedit = seg;

            // __TEXT
            if(hash_djb(seg->segname) == 0xec5f7168)
               seg_text = seg;

            break;

         case LC_ID_DYLIB:
            dlb = (dylib_command_t *)cmd;
            char *name = (char *)cmd + dlb->dylib.name.offset;
            
            // Is this the lib: /usr/lib/system/libdyld.dylib?
            if(hash_djb(name) == 0x8d3fccfd)
               ret = 1;

            break;

         case LC_SYMTAB:
            sym = (symtab_command_t *)cmd;

            // Determine symbol and string table offsets
            // http://lists.llvm.org/pipermail/lldb-commits/Week-of-Mon-20150608/019449.html
            strtab = (char *)mh + seg_linkedit->vmaddr + sym->stroff - seg_linkedit->fileoff - seg_text->vmaddr;
            nls = (nlist_t *)((char *)mh + seg_linkedit->vmaddr + sym->symoff - seg_linkedit->fileoff - seg_text->vmaddr);

            for(y = 0; y < sym->nsyms; y++)
            {
               char *sym_name = &strtab[nls[y].n_un.n_strx];
               size_t sym_val = (size_t)((char *)mh + nls[y].n_value - seg_text->vmaddr);
               uint32_t hash = hash_djb(sym_name);
               
               switch(hash)
               {
                  case 0x64c5cea0:
                     funcs->NSCreateObjectFileImageFromMemory = (ptr_NSCreateObjectFileImageFromMemory) sym_val;
                     break;
                  
                  case 0x6f320e79:
                     funcs->NSLinkModule = (ptr_NSLinkModule) sym_val;
                     break;
                  
                  case 0x515bc152:
                     funcs->NSLookupSymbolInModule = (ptr_NSLookupSymbolInModule) sym_val;
                     break;

                  case 0xf4da6396:
                     funcs->NSAddressOfSymbol = (ptr_NSAddressOfSymbol) sym_val;
                     break;
               }
            }
            break;
      }
      
      cmd = (load_command_t *)((char *)cmd + cmd->cmdsize);
   }

   // We found libdyld.lib, and we are done
   return ret;
}

static int is_ptr_valid(size_t ptr)
{
   static int fd = 0;

   // A dummy file descriptor for testing if a pointer is valid
   if(!fd)
   {
      #if defined(NAKED)
         fd = open("/dev/random", O_WRONLY, 0);
      #else
         fd = open("/dev/random", O_WRONLY);
      #endif
   }

   if(write(fd, (void *)ptr, sizeof(size_t)) == sizeof(size_t))
      return 1;

   return 0;
}

static int is_macho(size_t ptr)
{
   mach_header_t *mh = (mach_header_t *) ptr;

   // Is this a valid mach-o dylib file?
   if(mh->magic == MACHO_MAGIC && mh->filetype == MH_DYLIB && mh->cputype == CPU_TYPE)
      return 1;

   return 0;
}

int macho_bootstrap(func_t *funcs)
{
   int x, y;

   // We need a pointer anywhere onto the stack
   char *s = __builtin_alloca(0);

   // Let's find the very top of the stack
   while(is_ptr_valid((size_t)s + 1))
      s++;

   for(x = 0; x < 10000; x++)
   {
      // Walk down the stack, one byte at a time
      size_t *ptr = (size_t *)(s - x);

      // Do we have a valid pointer?
      if(!is_ptr_valid((size_t)ptr) || !is_ptr_valid(*ptr))
         continue;
      
      // Page-align the pointer
      size_t addr = *ptr & ~(PAGE_SIZE - 1);

      // Walk backwards one page at a time and try to find the beginning
      // of a mach-o file
      for(y = 0; y < 100; y++)
      {
         if(is_ptr_valid(addr) && is_macho(addr) && macho_parse((void *)addr, funcs))
            return 1;
         
         addr -= PAGE_SIZE;
      }
   }

   return 0;
}

void *macho_load(func_t *funcs, void *data, int size)
{
   void *image;

   if(funcs->NSCreateObjectFileImageFromMemory(data, size, &image) != NSObjectFileImageSuccess)
      return NULL;
      
   return funcs->NSLinkModule(image, "", NSLINKMODULE_OPTION_PRIVATE);
}

void *macho_sym(func_t *funcs, void *module, char *name)
{
   void *symbol;
   
   if(!module)
      return NULL;

   symbol = funcs->NSLookupSymbolInModule(module, name);

   if(!symbol)
      return NULL;
      
   return funcs->NSAddressOfSymbol(symbol);
}

