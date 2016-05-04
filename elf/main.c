#include <stdio.h>
#include <stdlib.h>

#include "elf.h"

int main(int argc, char *argv[], char *envp[])
{
   FILE *f = fopen(argv[1], "rb");

   fseek(f, 0, SEEK_END);
   int size = ftell(f);

   fseek(f, 0L, SEEK_SET);
   
   char *buf = malloc(size);
   fread(buf, size, 1, f);

   char *_argv[] = {
      argv[0],
      "arg1",
      "arg2",
      NULL,
   };

   char *_env[] = {
      "HOME=/tmp",
      NULL,
   };

   printf("main: %p\n", elf_sym(buf, "main"));

   // Run the ELF
   elf_run(buf, argv, envp);

   return 0;
}

