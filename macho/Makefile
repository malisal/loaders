all:
	gcc main.c macho.c -o main_64
	gcc bundle.c -o bundle -bundle -o bundle_64

	gcc main.c macho.c -o main_32 -m32
	gcc bundle.c -o bundle -bundle -o bundle_32 -m32

clean:
	rm main_{32,64} bundle_{32,64}

# Test with:
# ./main_32 ./bundle_32
# ./main_64 ./bundle_64
