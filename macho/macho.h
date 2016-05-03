#ifndef _MACHO_H_
#define _MACHO_H_

#if !defined(NAKED)
   #include <fcntl.h>
   #include <stdint.h>
   #include <sys/mman.h>

   #define PAGE_SIZE 0x1000
   #define ROUND_UP(v, s) ((v + s - 1) & -s)

   #if INTPTR_MAX == INT64_MAX
      #define BITS_64
   #else
      #define BITS_32
   #endif
#else
   #if defined(ARCH_X86_64)
      #define BITS_64
   #elif defined(ARCH_I686)
      #define BITS_32
   #else
      #error("Are you a wizard?")
   #endif
#endif

#define CPU_ARCH_ABI64     0x01000000              /* 64 bit ABI */
#define CPU_TYPE_X86       7
#define CPU_TYPE_X86_64    (CPU_TYPE_X86 | CPU_ARCH_ABI64)
#define CPU_TYPE_ARM       12
#define CPU_TYPE_ARM64     (CPU_TYPE_ARM | CPU_ARCH_ABI64)

#define NSLINKMODULE_OPTION_PRIVATE 0x2
#define LC_SEGMENT      0x1
#define LC_SEGMENT_64   0x19
#define LC_ID_DYLIB     0xd
#define LC_SYMTAB       0x2     /* link-edit stab symbol table info */

#define MH_MAGIC        0xfeedface     /* the mach magic number */
#define MH_CIGAM        0xcefaedfe     /* NXSwapInt(MH_MAGIC) */
#define MH_MAGIC_64     0xfeedfacf     /* the 64-bit mach magic number */
#define MH_CIGAM_64     0xcffaedfe     /* NXSwapInt(MH_MAGIC_64) */

#define	MH_DYLIB	0x6

typedef enum {
   NSObjectFileImageFailure,
   NSObjectFileImageSuccess,
   NSObjectFileImageInappropriateFile,
   NSObjectFileImageArch,
   NSObjectFileImageFormat,
   NSObjectFileImageAccess 
} NSObjectFileImageReturnCode;

union lc_str {
   uint32_t        offset; /* offset to the string */
#ifndef __LP64__
   char            *ptr;   /* pointer to the string */
#endif
};

struct dylib {
   union lc_str  name;                 /* library's path name */
   uint32_t timestamp;                 /* library's build time stamp */
   uint32_t current_version;           /* library's current version number */
   uint32_t compatibility_version;     /* library's compatibility vers number*/
};

typedef struct {
   uint32_t cmd;           /* type of load command */
   uint32_t cmdsize;       /* total size of command in bytes */
} load_command_t;

typedef struct {
   uint32_t        cmd;            /* LC_SYMTAB */
   uint32_t        cmdsize;        /* sizeof(struct symtab_command) */
   uint32_t        symoff;         /* symbol table offset */
   uint32_t        nsyms;          /* number of symbol table entries */
   uint32_t        stroff;         /* string table offset */
   uint32_t        strsize;        /* string table size in bytes */
} symtab_command_t;

typedef struct {
   uint32_t        cmd;            /* LC_ID_DYLIB, LC_LOAD_{,WEAK_}DYLIB, LC_REEXPORT_DYLIB */
   uint32_t        cmdsize;        /* includes pathname string */
   struct dylib    dylib;          /* the library identification */
} dylib_command_t;

typedef struct  {
   uint32_t        magic;          /* mach magic number identifier */
   uint32_t        cputype;        /* cpu specifier */
   uint32_t        cpusubtype;     /* machine specifier */
   uint32_t        filetype;       /* type of file */
   uint32_t        ncmds;          /* number of load commands */
   uint32_t        sizeofcmds;     /* the size of all the load commands */
   uint32_t        flags;          /* flags */
} mach_header_32_t;

typedef struct {
   uint32_t        magic;          /* mach magic number identifier */
   uint32_t        cputype;        /* cpu specifier */
   uint32_t        cpusubtype;     /* machine specifier */
   uint32_t        filetype;       /* type of file */
   uint32_t        ncmds;          /* number of load commands */
   uint32_t        sizeofcmds;     /* the size of all the load commands */
   uint32_t        flags;          /* flags */
   uint32_t        reserved;       /* reserved */
} mach_header_64_t;

typedef struct  { /* for 32-bit architectures */
   uint32_t        cmd;            /* LC_SEGMENT */
   uint32_t        cmdsize;        /* includes sizeof section structs */
   char            segname[16];    /* segment name */
   uint32_t        vmaddr;         /* memory address of this segment */
   uint32_t        vmsize;         /* memory size of this segment */
   uint32_t        fileoff;        /* file offset of this segment */
   uint32_t        filesize;       /* amount to map from the file */
   uint32_t        maxprot;        /* maximum VM protection */
   uint32_t        initprot;       /* initial VM protection */
   uint32_t        nsects;         /* number of sections in segment */
   uint32_t        flags;          /* flags */
} segment_command_32_t;

typedef struct { /* for 64-bit architectures */
   uint32_t        cmd;            /* LC_SEGMENT_64 */
   uint32_t        cmdsize;        /* includes sizeof section_64 structs */
   char            segname[16];    /* segment name */
   uint64_t        vmaddr;         /* memory address of this segment */
   uint64_t        vmsize;         /* memory size of this segment */
   uint64_t        fileoff;        /* file offset of this segment */
   uint64_t        filesize;       /* amount to map from the file */
   uint32_t        maxprot;        /* maximum VM protection */
   uint32_t        initprot;       /* initial VM protection */
   uint32_t        nsects;         /* number of sections in segment */
   uint32_t        flags;          /* flags */
} segment_command_64_t;

typedef struct { /* for 32-bit architectures */
   char            sectname[16];   /* name of this section */
   char            segname[16];    /* segment this section goes in */
   uint32_t        addr;           /* memory address of this section */
   uint32_t        size;           /* size in bytes of this section */
   uint32_t        offset;         /* file offset of this section */
   uint32_t        align;          /* section alignment (power of 2) */
   uint32_t        reloff;         /* file offset of relocation entries */
   uint32_t        nreloc;         /* number of relocation entries */
   uint32_t        flags;          /* flags (section type and attributes)*/
   uint32_t        reserved1;      /* reserved (for offset or index) */
   uint32_t        reserved2;      /* reserved (for count or sizeof) */
} section_32_t;

typedef struct { /* for 64-bit architectures */
   char            sectname[16];   /* name of this section */
   char            segname[16];    /* segment this section goes in */
   uint64_t        addr;           /* memory address of this section */
   uint64_t        size;           /* size in bytes of this section */
   uint32_t        offset;         /* file offset of this section */
   uint32_t        align;          /* section alignment (power of 2) */
   uint32_t        reloff;         /* file offset of relocation entries */
   uint32_t        nreloc;         /* number of relocation entries */
   uint32_t        flags;          /* flags (section type and attributes)*/
   uint32_t        reserved1;      /* reserved (for offset or index) */
   uint32_t        reserved2;      /* reserved (for count or sizeof) */
   uint32_t        reserved3;      /* reserved */
} section_64_t;

typedef struct {
   union {
#ifndef __LP64__
      char *n_name;        /* for use when in-core */
#endif
      uint32_t n_strx;     /* index into the string table */
   } n_un;
   uint8_t n_type;         /* type flag, see below */
   uint8_t n_sect;         /* section number or NO_SECT */
   int16_t n_desc;         /* see <mach-o/stab.h> */
   uint32_t n_value;       /* value of this symbol (or stab offset) */
} nlist_32_t;

typedef struct {
    union {
        uint32_t  n_strx; /* index into the string table */
    } n_un;
    uint8_t n_type;        /* type flag, see below */
    uint8_t n_sect;        /* section number or NO_SECT */
    uint16_t n_desc;       /* see <mach-o/stab.h> */
    uint64_t n_value;      /* value of this symbol (or stab offset) */
} nlist_64_t;

#if defined(BITS_32)
   #define CPU_TYPE CPU_TYPE_X86
   typedef mach_header_32_t mach_header_t;
   typedef segment_command_32_t segment_command_t;
   typedef section_32_t section_t;
   typedef nlist_32_t nlist_t;
   #define MACHO_MAGIC MH_MAGIC
#elif defined(BITS_64)
   #define CPU_TYPE CPU_TYPE_X86_64
   typedef mach_header_64_t mach_header_t;
   typedef segment_command_64_t segment_command_t;
   typedef section_64_t section_t;
   typedef nlist_64_t nlist_t;
   #define MACHO_MAGIC MH_MAGIC_64
#else
   #error("Are you a wizard?")
#endif

typedef int (*ptr_NSCreateObjectFileImageFromMemory)(void *address, int size, void *objectFileImage);
typedef void *(*ptr_NSLinkModule)(void *objectFileImage, char *moduleName, uint32_t options);
typedef void *(*ptr_NSLookupSymbolInModule)(void *module, char *symbolName);
typedef void *(*ptr_NSAddressOfSymbol)(void *symbol);

typedef struct
{
   ptr_NSCreateObjectFileImageFromMemory NSCreateObjectFileImageFromMemory;
   ptr_NSLinkModule NSLinkModule;
   ptr_NSLookupSymbolInModule NSLookupSymbolInModule;
   ptr_NSAddressOfSymbol NSAddressOfSymbol;
} func_t;

int macho_bootstrap(func_t *funcs);;
void *macho_load(func_t *funcs, void *data, int size);
void *macho_sym(func_t *funcs, void *module, char *name);

#endif // _MACHO_H_

