# The loader (main) needs to be position-independant, otherwise the loader and the file to
# load (dummy) would be loaded onto the same offset => crash!
all:
	rexec gcc -DOS_LINUX -DARCH_X86_64 elf.c main.c -o main_64 -pie -fPIC
	rexec gcc dummy.c -o dummy_64 -fPIC -pie

	rexec gcc -DOS_LINUX -DARCH_I686 elf.c main.c -o main_32 -pie -fPIC -m32
	rexec gcc dummy.c -o dummy_32 -m32

clean:
	rm main_{32,64} dummy_{32,64}

# Test with:
# ./main_32 ./dummy_32
# ./main_64 ./dummy_64

