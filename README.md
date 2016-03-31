## Binary Loaders

[![MIT License](https://img.shields.io/badge/license-MIT-blue.svg?style=flat)](http://choosealicense.com/licenses/mit/)

This repo is about small, self-contained implementations of various binary formats loaders (Macho on OSX, ELF on Linux/*BSD and PE on Windows). The rationale for these libraries is the following: You wrote an exploit and achieved arbitrary code execution. Now what?

These loaders enable you to load and execute an arbitrary binary in your exploited process. The loaders are coded in a way that it's all done in memory, and they do not require access to system libraries/methods - it's all resolved on the fly.

### PE Loader

The PE loader uses the standard trick. We first walk the PEB and resolve `LoadLibrary`, `GetProcAddress` as well as a few other functions. We then load the PE file and resolve it's dependancies.

### Macho Loader

The macho loader requires access to some system functions (e.g., `NSCreateObjectFileImageFromMemory`, `NSLinkModule`) that are provided by `libdyld.dylib`. As we don't know the address of `libdyld.dylib` in memory, we first walk to the very top of the stack. We then start walking downwards on the stack and we inspect every pointer we find. The trick is that the offset inside of `libdyld.dylib` must be present as it's placed there by the dynamic linker as the return function when `main` returns. We find the offset, we resolve the functions and from then on, it's standard loading of macho bundles.

### ELF Loader

TODO
