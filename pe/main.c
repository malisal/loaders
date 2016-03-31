#include <stdio.h>
#include <windows.h>

#include "pe.h"

int main(int argc, char *argv[])
{
   func_t funcs;

   // Walk the PEB, then find kernel32.dll and resolve the functions
   pe_bootstrap(&funcs);

   // Load the PE file in memory
   FILE *f = fopen(argv[1], "rb");
   fseek(f, 0, SEEK_END);
   int len = ftell(f);
   fseek(f, 0, SEEK_SET);

   char *data = malloc(len);
   fread(data, len, 1, f);
   
   size_t entry;
   size_t base;

   pe_load(&funcs, data, &base, &entry);

   if(pe_is_dll(data))
   {
      int (*ptr_DllMain)(HANDLE, DWORD, LPVOID) = (int (*)(HANDLE, DWORD, LPVOID))(entry);
      printf("DllMain: %p\n", ptr_DllMain);
      ptr_DllMain((HANDLE)base, DLL_PROCESS_ATTACH, 0);
   }
   else
   {
      char *_argv[] = {
         "test.exe",
         NULL
      };

      int (*ptr_main)(int, char **) = (int (*)(int, char **))(entry);
      printf("main: %p\n", ptr_main);
      ptr_main(1, _argv);
   }

   // Sanity check
   // printf("%p\n", funcs.GetProcAddress);
   // printf("%p\n", funcs.VirtualAlloc);
   // printf("%p\n", funcs.LoadLibrary);
}

