## Binary Loaders

[![MIT License](https://img.shields.io/badge/license-MIT-blue.svg?style=flat)](http://choosealicense.com/licenses/mit/)

This repo is about small, self-contained implementations of various binary formats (MACH-O on OSX, ELF on Linux/*BSD and PE on Windows). The rationale for these libraries is the following: You wrote an exploit and achieved arbitrary code execution. Now what?

These loaders enable you to load and execute an arbitrary binary in your exploited process. The loaders are coded in a way that it's all done in memory.

