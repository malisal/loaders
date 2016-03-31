#include <stdio.h>
#include <windows.h>

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpReserved)
{
   if(fdwReason == DLL_PROCESS_ATTACH)
   	printf("Hello World\n");
}

