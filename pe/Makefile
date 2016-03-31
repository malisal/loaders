all:
	x86_64-w64-mingw32-gcc main.c pe.c -o main_64.exe
	x86_64-w64-mingw32-gcc test.c -o test_64.dll -shared

	i686-w64-mingw32-gcc main.c pe.c -o main_32.exe
	i686-w64-mingw32-gcc test.c -o test_32.dll -shared

clean:
	rm main_{32,64}.exe test_{32,64}.dll

# Test with:
# ./main_64.exe ./test_64.dll
# ./main_32.exe ./test_32.dll
