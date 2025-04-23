---
title: Portable Executable Structure
published: 2025-04-20
description: A simple Portable Executable Structure blog post.
tags: [PE, Blogging]
category: Blog
draft: false
---


# Portable Executable Structure

## Introduction and Overview

### PE format

PE stands for Portable Executable, it's a file format based on COFF (Common Object File Format), used by Windows operating systems to store executable files.

But PE isn't just ```.exe``` file, it's also used for ```.dll``` (Dynamic Link Libraries) , ```.srv``` (Kernel modules), and other types of files of PE.


### PE Structure Overview

![alt text](https://raw.githubusercontent.com/raviyelna/Journey-into-the-Fundamental-of-Malware-Analysing/refs/heads/main/Asset/PE_structure/images/PE_Structure.png)

If we open any PE file in PE-bear we will see it's the same as the picture above

![alt text](https://raw.githubusercontent.com/raviyelna/Journey-into-the-Fundamental-of-Malware-Analysing/refs/heads/main/Asset/PE_structure/images/image.png)

Let's talk about some of the header first. The ```DOS Header``` is 64 bytes long and it will determine if the file is a PE MS-DOS executable or not.

![alt text](https://raw.githubusercontent.com/raviyelna/Journey-into-the-Fundamental-of-Malware-Analysing/refs/heads/main/Asset/PE_structure/images/image-1.png)
The ```DOS Stub``` is a error message, it will print out the string "This program cannot be run in DOS mode" if the file is run in DOS mode. 

![alt text](https://raw.githubusercontent.com/raviyelna/Journey-into-the-Fundamental-of-Malware-Analysing/refs/heads/main/Asset/PE_structure/images/image-2.png)

```NT Headers```, this is where the PE signature located ```PE```, this header has 3 parts, the ***PE Signature, File Header and Optional Header***

1. ***PE Signature***: This is the first 4 bytes of the NT Headers, it's the word ```PE```, this used to identified this is an PE file.

2. ***File Header***: This is 20 bytes long, it contains information about the fil , such as the machine type, number of sections, and the time and date the file was created

3. ***Optional Header***: This is 224 bytes long, it contains information about the file , such as the entry point, the base address of the file, and the size of the file, this is the most important header in the ```NT Header``` since it provides important information to the OS loader and only image file such as ```.exe``` has it.

![alt text](https://raw.githubusercontent.com/raviyelna/Journey-into-the-Fundamental-of-Malware-Analysing/refs/heads/main/Asset/PE_structure/images/image-3.png)

Finally ```Section table```, this is an array of structures that describe each section in the file, each section is a contiguous block of memory that contains the code, data, or resources of the file.

![alt text](https://raw.githubusercontent.com/raviyelna/Journey-into-the-Fundamental-of-Malware-Analysing/refs/heads/main/Asset/PE_structure/images/image-4.png)

---

## DOS, DOS Stub and Rich Header

### Dos Header

Like we already know, the DOS header is 64 bytes and it's used to determine if a file is a PE file or not, it may not look important but it's actually is, because it's the first thing the OS loader will check when it loads a file. If you try to load this file in DOS-mode it will print out the string "This program cannot be run in DOS mode" in the DOS stub instead of running the actual program. We can look more into this by looking at the ```_IMAGE_DOS_HEADER``` struct in ```winnt.h```.

```
typedef struct _IMAGE_DOS_HEADER {      // DOS .EXE header
    WORD   e_magic;                     // Magic number
    WORD   e_cblp;                      // Bytes on last page of file
    WORD   e_cp;                        // Pages in file
    WORD   e_crlc;                      // Relocations
    WORD   e_cparhdr;                   // Size of header in paragraphs
    WORD   e_minalloc;                  // Minimum extra paragraphs needed
    WORD   e_maxalloc;                  // Maximum extra paragraphs needed
    WORD   e_ss;                        // Initial (relative) SS value
    WORD   e_sp;                        // Initial SP value
    WORD   e_csum;                      // Checksum
    WORD   e_ip;                        // Initial IP value
    WORD   e_cs;                        // Initial (relative) CS value
    WORD   e_lfarlc;                    // File address of relocation table
    WORD   e_ovno;                      // Overlay number
    WORD   e_res[4];                    // Reserved words
    WORD   e_oemid;                     // OEM identifier (for e_oeminfo)
    WORD   e_oeminfo;                   // OEM information; e_oemid specific
    WORD   e_res2[10];                  // Reserved words
    LONG   e_lfanew;                    // File address of new exe header
  } IMAGE_DOS_HEADER, *PIMAGE_DOS_HEADER;
```

Some of these variable is important to the PE loader on Windows and some are not, so we will only dig in the important ones.

1. e_magic: this is the magic number that identifies the file as a DOS file, it's the first 2 bytes (```4D 5A```) of the DOS header, some called it hex header, basically its the word **MZ**, you may see something like "MZx", "MZRAUH",.... it's actually the same thing, the first 2 bytes is still **MZ**.

![alt text](https://raw.githubusercontent.com/raviyelna/Journey-into-the-Fundamental-of-Malware-Analysing/refs/heads/main/Asset/PE_structure/images/image-5.png)

2. e_lfanew: this is the last variable inside the DOS header, It's located at offset ```0x3C```, this variable is VERY important because It will tell the loader where to look for the file header.

![alt text](https://raw.githubusercontent.com/raviyelna/Journey-into-the-Fundamental-of-Malware-Analysing/refs/heads/main/Asset/PE_structure/images/image-7.png)

### DOS Stub

The DOS stub is the code that will be executed when the file is loaded in DOS mode, when got executed it will print out the string "This program cannot be run in DOS mode", let's dig a bit deeper into this by dumping out the DOS stub.

```
0e 1f ba 0e 00 b4 09 cd 21 b8 01 4c cd 21 54 68 69 73 20 70 72 6f 67 72 61 6d 20 63 61 6e 6e 6f 74 20 62 65 20 72 75 6e 20 69 6e 20 44 4f 53 20 6d 6f 64 65 2e 0d 0d 0a 24 00 00 00 00 00 00 00 65 5a 2d c6 21 3b 43 95 21 3b 43 95 21 3b 43 95 28 43 d0 95 33 3b 43 95 73 4e 47 94 2b 3b 43 95 73 4e 40 94 25 3b 43 95 73 4e 46 94 02 3b 43 95 73 4e 42 94 27 3b 43 95 e5 4e 42 94 23 3b 43 95 fc c4 88 95 2f 3b 43 95 98 4e 42 94 28 3b 43 95 21 3b 42 95 aa 35 43 95 e5 4e 46 94 32 3a 43 95 e5 4e bc 95 20 3b 43 95 21 3b d4 95 20 3b 43 95 e5 4e 41 94 20 3b 43 95 52 69 63 68 21 3b 43 95 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
```

Loading this binary into IDA (Make sure to choose 16 bit since DOS is 16 bit) we can see that it's a simple program that will print out the string "This program cannot be run in DOS mode" and then exit the program.

![alt text](https://raw.githubusercontent.com/raviyelna/Journey-into-the-Fundamental-of-Malware-Analysing/refs/heads/main/Asset/PE_structure/images/image-8.png)

```
seg000:0002                 mov     dx, 0Eh
seg000:0005                 mov     ah, 9
seg000:0007                 int     21h             ; DOS - PRINT STRING
seg000:0007                                         ; DS:DX -> string terminated by "$"
```

These 3 lines here is the code that will print out the string "This program cannot be run in DOS mode". The first line will sets **DX** to the address of the "This program..." string then it will set **AD** to **9h** which is the DOS function code for printing a string, then it will call the DOS interrupt **21h** to execute the function.

```Basically, the interupt 21h takes a parameter that determines what function to execute and that parameter is passed in the ah register. We see here that the value 9 is given to the interrupt, 9 is the code of the function that prints a string to the screen, that function takes a parameter which is the address of the string to print, that parameter is passed in the dx register```

**More about the DOS interupt can be read from [here](https://en.wikipedia.org/wiki/DOS_API)**

![alt text](https://raw.githubusercontent.com/raviyelna/Journey-into-the-Fundamental-of-Malware-Analysing/refs/heads/main/Asset/PE_structure/images/image-9.png)

### Rich Header

If you havent notice in the previous part of the DOS stub, there a chunk of Bytes just under the "This program cannot be run in DOS mode" string. This is called Rich Header. It's an undocumented structure that’s only present in executables built using the Microsoft Visual Studio toolset.


![alt text](https://raw.githubusercontent.com/raviyelna/Journey-into-the-Fundamental-of-Malware-Analysing/refs/heads/main/Asset/PE_structure/images/image-11.png)

This structure holds some metadata about the tools used to build the executable like their names or types and their specific versions and build numbers.

![alt text](https://raw.githubusercontent.com/raviyelna/Journey-into-the-Fundamental-of-Malware-Analysing/refs/heads/main/Asset/PE_structure/images/image-10.png)

While learning about the PE structure on [0xRick](https://0xrick.github.io/) blog, he has mentioned a case where there is a malware used the rich header of a famous APT (Lazarus) to make it look like it was Lazarus behind the attack of the Winter Olympic 2018, you can check more detail about this [here](https://securelist.com/the-devils-in-the-rich-header/84348/) 

The rich header is a bunch of Xor data followed by a signature (Rich) and next to it is the XOR key.

Rich Header:

```
65 5a 2d c6 21 3b 43 95 21 3b 43 95 21 3b 43 95 28 43 d0 95 33 3b 43 95 73 4e 47 94 2b 3b 43 95 73 4e 40 94 25 3b 43 95 73 4e 46 94 02 3b 43 95 73 4e 42 94 27 3b 43 95 e5 4e 42 94 23 3b 43 95 fc c4 88 95 2f 3b 43 95 98 4e 42 94 28 3b 43 95 21 3b 42 95 aa 35 43 95 e5 4e 46 94 32 3a 43 95 e5 4e bc 95 20 3b 43 95 21 3b d4 95 20 3b 43 95 e5 4e 41 94 20 3b 43 95 52 69 63 68 21 3b 43 95 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
```

From this we can split them into 2 parts:

Data: 

```
655a2dc6213b4395213b4395213b43952843d095333b4395734e47942b3b4395734e4094253b4395734e4694023b4395734e4294273b4395e54e4294233b4395fcc488952f3b4395984e4294283b4395213b4295aa354395e54e4694323a4395e54ebc95203b4395213bd495203b4395e54e4194203b4395
```

Key:

```
213b4395
```

The original script belong to 0xRick, I stole it and modified it to add the VS version part to showcase the data after xored it will look exactly like the data in the PE-bear.

```py
import textwrap

def xor(data, key):
	return bytearray(((data[i] ^ key[i % len(key)]) for i in range(len(data))))

def rev_endiannes(data):
	tmp = [data[i:i+8] for i in range(0, len(data), 8)]
	for i in range(len(tmp)):
		tmp[i] = "".join(reversed([tmp[i][x:x+2] for x in range(0, len(tmp[i]), 2)]))
	return "".join(tmp)

def richhdr_prod_id_to_vsversion(i):
    if 0x0106 <= i <= 0x010a:
        return "Visual Studio 2017 14.01+"
    if 0x00fd <= i < 0x0106:
        return "Visual Studio 2015 14.00"
    if 0x00eb <= i < 0x00fd:
        return "Visual Studio 2013 12.10"
    if 0x00d9 <= i < 0x00eb:
        return "Visual Studio 2013 12.00"
    if 0x00c7 <= i < 0x00d9:
        return "Visual Studio 2012 11.00"
    if 0x00b5 <= i < 0x00c7:
        return "Visual Studio 2010 10.10"
    if 0x0098 <= i < 0x00b5:
        return "Visual Studio 2010 10.00"
    if 0x0083 <= i < 0x0098:
        return "Visual Studio 2008 09.00"
    if 0x006d <= i < 0x0083:
        return "Visual Studio 2005 08.00"
    if 0x005a <= i < 0x006d:
        return "Visual Studio 2003 07.10"
    if 0x0019 <= i <= 0x0045:
        return "Visual Studio 2002 07.00"
    if i in [0xA, 0xB, 0xD, 0x15, 0x16]:
        return "Visual Studio 6.0 06.00"
    if i in [0x2, 0x6, 0xC, 0xE]:
        return "Visual Studio 97 05.00"
    if i == 1:
        return "Visual Studio"
    return ""

data = bytearray.fromhex("655a2dc6213b4395213b4395213b43952843d095333b4395734e47942b3b4395734e4094253b4395734e4694023b4395734e4294273b4395e54e4294233b4395fcc488952f3b4395984e4294283b4395213b4295aa354395e54e4694323a4395e54ebc95203b4395213bd495203b4395e54e4194203b4395")
key  = bytearray.fromhex("213b4395")

rch_hdr = (xor(data,key)).hex()
rch_hdr = textwrap.wrap(rch_hdr, 16)

for i in range(2, len(rch_hdr)):
	tmp = textwrap.wrap(rch_hdr[i], 8)
	f1 = rev_endiannes(tmp[0])
	f2 = rev_endiannes(tmp[1])
	build = int(f1[4:], 16)
	prod_id = int(f1[0:4], 16)
	count = int(f2, 16)
	vs_version = richhdr_prod_id_to_vsversion(prod_id)

	print(f"{f1} {f2} : {build}.{prod_id}.{count} -> {vs_version}")
```

![alt text](https://raw.githubusercontent.com/raviyelna/Journey-into-the-Fundamental-of-Malware-Analysing/refs/heads/main/Asset/PE_structure/images/image-12.png)

This is pretty much about DOS, DOS Stub and Rich Header, it can be summarized in the picture under.

![alt text](https://raw.githubusercontent.com/raviyelna/Journey-into-the-Fundamental-of-Malware-Analysing/refs/heads/main/Asset/PE_structure/images/image-13.png)

## NT Headers 

NT headers is a structure defined in ```winnt.h``` as ```IMAGE_NT_HEADERS```, by looking at its definition we can see that it has three members, a DWORD signature, an ```IMAGE_FILE_HEADER``` structure called ```FileHeader``` and an ```IMAGE_OPTIONAL_HEADER``` structure called ```OptionalHeader```.

There are two types of NT headers, one is the 32-bit (PE32 Executable) NT header and the other is the 64-bit(PE32+ Executable) version.

```C
typedef struct _IMAGE_NT_HEADERS64 {
    DWORD Signature;
    IMAGE_FILE_HEADER FileHeader;
    IMAGE_OPTIONAL_HEADER64 OptionalHeader;
} IMAGE_NT_HEADERS64, *PIMAGE_NT_HEADERS64;

typedef struct _IMAGE_NT_HEADERS {
    DWORD Signature;
    IMAGE_FILE_HEADER FileHeader;
    IMAGE_OPTIONAL_HEADER32 OptionalHeader;
} IMAGE_NT_HEADERS32, *PIMAGE_NT_HEADERS32;
```

### Signature

If we look at the first member of the NT Header, it's the Signature also known as the NT Signature, it's a 4-byte value (DWORD) it's actually the **PE** you saw when reading the hexadecimal bytes, The value of this field is fixed as **0x50450000** (PE)

![alt text](https://raw.githubusercontent.com/raviyelna/Journey-into-the-Fundamental-of-Malware-Analysing/refs/heads/main/Asset/PE_structure/images/image-14.png)

### File Header (IMAGE_FILE_HEADER)

This also called the "COFF File Header (Common Object File Format)" it's a structure that contains information about the PE file. This section is defined as ```IMAGE_FILE_HEADER ``` in ```winnt.h```

```C
typedef struct _IMAGE_FILE_HEADER {
    WORD    Machine;
    WORD    NumberOfSections;
    DWORD   TimeDateStamp;
    DWORD   PointerToSymbolTable;
    DWORD   NumberOfSymbols;
    WORD    SizeOfOptionalHeader;
    WORD    Characteristics;
} IMAGE_FILE_HEADER, *PIMAGE_FILE_HEADER;
```

This struct has 7 member inside it:

1. **Machine**: This is a 16-bit value that indicates the type of machine (a.k.a CPU Architecture) that the PE file is designed to run on, this field can held lots of value but the only 2 important one is **0x8864** for AMD64 and **0x14C** for i386, you can read more about this by checking the official [Microsoft Document](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format)

2. **NumberOfSections**: This is a 16-bit value that indicates the number of sections in the PE.

3. **TimeDateStamp**: This is a 32-bit value that indicates the time and date that the PE file was created.

4. **PointerToSymbolTable**: This is a 32-bit value that indicates the location of the symbol table in the PE file, this will be set to 0 if there no COFF symbol table in the file.

5. **NumberOfSymbols**: This is a 32-bit value that indicates the number of symbols in the PE, this also will be set to 0 if there no COFF symbol table in the file.

6. **SizeOfOptionalHeader**: This is a 16-bit value that indicates the size of the optional Header.

7. **Characteristics**: This is a 16-bit value that indicates the characteristics of the PE file, this field can held lots of value such as **IMAGE_FILE_RELOCS_STRIPPED**, **IMAGE_FILE_EXECUTABLE_IMAGE**, you can read more about this by checking the official [Microsoft Document](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format)

![alt text](https://raw.githubusercontent.com/raviyelna/Journey-into-the-Fundamental-of-Malware-Analysing/refs/heads/main/Asset/PE_structure/images/image-15.png)

### Optional Header (IMAGE_OPTIONAL_HEADER)

The Optional header is one of the most important header in the NT header, the PE loader will use the information provided by the optional header to be able to run and load the executable file.

So why does it called **Optional Header**?

It actually called by that because it's not required to be present in the PE file,It also doesn’t have a fixed size, that’s why the ```IMAGE_FILE_HEADER.SizeOfOptionalHeader``` member exists.

The first 8 members of the optional header are the same for all PE files, the rest of the members are extension specific, that’s why it’s called **Optional**.

Also the Option Heaader has 2 version, 32-bit and 64-bit or (PE32 & PE32+) there actually some differences between them.

1. The size of the structure: ```IMAGE_OPTIONAL_HEADER32``` has 31 members while ```IMAGE_OPTIONAL_HEADER64``` only has 30 members, that additional member in the 32-bit version is a DWORD named BaseOfData which holds an RVA of the beginning of the data section.

2. Data type of member: The following 5 members of the Optional Header structure are defined as **DWORD** in the 32-bit version and as **ULONGLONG** in the 64-bit version:

    ```
    ImageBase
    SizeOfStackReserve
    SizeOfStackCommit
    SizeOfHeapReserve
    SizeOfHeapCommit
    ```

Optional Header 32-bit Structure: 

```C
typedef struct _IMAGE_OPTIONAL_HEADER {
    //
    // Standard fields.
    //

    WORD    Magic;
    BYTE    MajorLinkerVersion;
    BYTE    MinorLinkerVersion;
    DWORD   SizeOfCode;
    DWORD   SizeOfInitializedData;
    DWORD   SizeOfUninitializedData;
    DWORD   AddressOfEntryPoint;
    DWORD   BaseOfCode;
    DWORD   BaseOfData;

    //
    // NT additional fields.
    //

    DWORD   ImageBase;
    DWORD   SectionAlignment;
    DWORD   FileAlignment;
    WORD    MajorOperatingSystemVersion;
    WORD    MinorOperatingSystemVersion;
    WORD    MajorImageVersion;
    WORD    MinorImageVersion;
    WORD    MajorSubsystemVersion;
    WORD    MinorSubsystemVersion;
    DWORD   Win32VersionValue;
    DWORD   SizeOfImage;
    DWORD   SizeOfHeaders;
    DWORD   CheckSum;
    WORD    Subsystem;
    WORD    DllCharacteristics;
    DWORD   SizeOfStackReserve;
    DWORD   SizeOfStackCommit;
    DWORD   SizeOfHeapReserve;
    DWORD   SizeOfHeapCommit;
    DWORD   LoaderFlags;
    DWORD   NumberOfRvaAndSizes;
    IMAGE_DATA_DIRECTORY DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
} IMAGE_OPTIONAL_HEADER32, *PIMAGE_OPTIONAL_HEADER32;
```

Option Header 64-bit version:

```C
typedef struct _IMAGE_OPTIONAL_HEADER64 {
    WORD        Magic;
    BYTE        MajorLinkerVersion;
    BYTE        MinorLinkerVersion;
    DWORD       SizeOfCode;
    DWORD       SizeOfInitializedData;
    DWORD       SizeOfUninitializedData;
    DWORD       AddressOfEntryPoint;
    DWORD       BaseOfCode;
    ULONGLONG   ImageBase;
    DWORD       SectionAlignment;
    DWORD       FileAlignment;
    WORD        MajorOperatingSystemVersion;
    WORD        MinorOperatingSystemVersion;
    WORD        MajorImageVersion;
    WORD        MinorImageVersion;
    WORD        MajorSubsystemVersion;
    WORD        MinorSubsystemVersion;
    DWORD       Win32VersionValue;
    DWORD       SizeOfImage;
    DWORD       SizeOfHeaders;
    DWORD       CheckSum;
    WORD        Subsystem;
    WORD        DllCharacteristics;
    ULONGLONG   SizeOfStackReserve;
    ULONGLONG   SizeOfStackCommit;
    ULONGLONG   SizeOfHeapReserve;
    ULONGLONG   SizeOfHeapCommit;
    DWORD       LoaderFlags;
    DWORD       NumberOfRvaAndSizes;
    IMAGE_DATA_DIRECTORY DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
} IMAGE_OPTIONAL_HEADER64, *PIMAGE_OPTIONAL_HEADER64;
```

1. **Magic**: This field contains the value `0x10B` for 32-bit, `0x20B` for 64-bit and `0x107` for ROM image. The value of this field is what determines whether the executable is 32-bit or 64-bit, ```IMAGE_FILE_HEADER.Machine``` is ignored by the Windows PE loader.

2. **MajorLinkerVersion**: This field is used to determine the version of the linker that was used to create the executable.

3. **MinorLinkerVersion**: The same as above but for Minor Linker.

4. **SizeOfCode**: This field contains the size of the code section (.text) in the Executable. ```(NOTE: this is also can be used to stored sum of all the code section if there are multiple section)```

5. **SizeOfInitializedData**: This field contains the size of the initialized data section (.data) in the Executable. ```(NOTE: this is also can be used  to store the sum of all initialized data section if there is multiple data section)```

6. **SizeOfUninitializedData**: This field contains the size of the uninitialized data section (.bss) in the Executable. ```(NOTE: this is also can be used to store the sum of all uninitialized data section if there are multiple sections)```

7. **AddressOfEntryPoint**: This field contains the virtual address of the entry point of the executable. ```(NOTE: This is the address where the program starts execution, sometime this is called RVA - Relative Virtual Address, for DLLs this field is set to 0)```

8. **BaseOfCode**: This field contains the RVA of the code when loaded into memory.

9. **BaseOfData (PE32 Exclusively)**: This field contains the RVA of the initialized data (.data) when loaded into memory.

10. **ImageBase**: This field holds the preferred address of the first byte of image when loaded into memory (the preferred base address), this value must be a multiple of 64K. Due to memory protections like ASLR, and a lot of other reasons, the address specified by this field is almost never used, in this case the PE loader chooses an unused memory range to load the image into, after loading the image into that address the loader goes into a process called the relocating where it fixes the constant addresses within the image to work with the new image base, there’s a special section that holds information about places that will need fixing if relocation is needed, that section is called the relocation section (.reloc).

11. **SectionAlignment**: This field holds a value that gets used for section alignment in memory (in bytes), sections are aligned in memory boundaries that are multiples of this value. The documentation states that this value defaults to the page size for the architecture and it can’t be less than the value of FileAlignment.

12. **FileAlignment**: Similar to SectionAligment this field holds a value that gets used for section raw data alignment on disk (in bytes), if the size of the actual data in a section is less than the FileAlignment value, the rest of the chunk gets padded with zeroes to keep the alignment boundaries. The documentation states that this value should be a power of 2 between 512 and 64K, and if the value of SectionAlignment is less than the architecture’s page size then the sizes of FileAlignment and SectionAlignment must match.

13. **MajorOperatingSystemVersion**: This field holds the major version of the operating system that the executable was built for.

14. **MinorOperatingSystemVersion**: This field holds the minor version of the operating system that the executable was built for.

15. **MajorImageVersion**: This field holds the major version of the image that the executable was built for.

16. **MinorImageVersion**: This field holds the minor version of the image that the executable was built for.

17. **Win32VersionValue**: A reserved field that the documentation says should be set to 0.

18. **SizeOfImage**: This field holds the total size of the image in memory (in bytes) ```(NOTE: this will include all the headers , sections and will be rounded up to a multiple of SectionAlignment because it will be used when load the image into the memory)```.

19. **SizeOfHeaders**: This field holds the size of the DOS stub, NT Headers and Section header in the executable ```(NOTE: This will also be rounded up to a multiple of SectionAlignment)```.

20. **CheckSum**: This field holds a checksum of the executable at loading time.

21. **Subsystem**: This field holds the subsystem that the executable was built for, you can check the official [Microsoft Document](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format) to get the full list of Subsystem.

22. **DllCharacteristics**: This field holds a set of flags that describe the characteristics of the executable such as whether it’s NX compatible or if DLL is movable or not, you can check out the full list by reading the official [Microsoft DLL Characteristics Table](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#dll-characteristics)

23. **SizeOfStackReserve**: This field holds the size of the stack reserve in the executable, this is the amount of memory that the OS will reserve for the stack when the executable is loaded into memory.

24. **SizeOfStackCommit**: This field holds the size of the stack commit in the executable.

25. **SizeOfHeapReserve**: This field holds the size of the heap reserve in the executable.

26. **SizeOfHeapCommit**: This field holds the size of the heap commit in the executable.

27. **LoaderFlags**: This field holds a set of flags that describe the loader behavior when loading the executable into memory.

28. **NumberOfRvaAndSizes**: This field holds the number of entries in the DataDirectory array.

29. **DataDirectory**: This field holds an array of ```DataDirectory``` structures that describe the resources that the executable uses, each structure contains a VirtualAddress and a Size field that describe the resource, the VirtualAddress field holds the RVA of the resource and the Size field holds the size of the resource in memory.

Optional Header in PE-bear:

![alt text](https://raw.githubusercontent.com/raviyelna/Journey-into-the-Fundamental-of-Malware-Analysing/refs/heads/main/Asset/PE_structure/images/image-16.png)

Let's take an example here, the image below is show the **.data** section, if you noticed the part inside the red box is the actual data of the **.data** section but the end address is ```0x3A93F0``` It isn't fit to the **FileAlignment** so it has to pad with zeroes to keep the alignment boundaries. You can also check the value of **SizeOfImage** and **SizeOfHeaders** they both are multiples of **SectionAlignment** and **FileAlignment**

![alt text](https://raw.githubusercontent.com/raviyelna/Journey-into-the-Fundamental-of-Malware-Analysing/refs/heads/main/Asset/PE_structure/images/image-17.png)

![alt text](https://raw.githubusercontent.com/raviyelna/Journey-into-the-Fundamental-of-Malware-Analysing/refs/heads/main/Asset/PE_structure/images/image-18.png)

## Data Directories, Section Headers and Sections

The Data Directories, Section Headers and Sections are the most important part of the PE file format.

### Data Directories

If you remember what I show above that's The last member of the ```IMAGE_OPTIONAL_HEADER``` structure was an array of ```IMAGE_DATA_DIRECTORY```, it's structures defined as follows:

```C
IMAGE_DATA_DIRECTORY DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
```

```IMAGE_NUMBEROF_DIRECTORY_ENTRIES``` is a constant defined with the value **16**, meaning that this array can have up to **16** ```IMAGE_DATA_DIRECTORY``` entries:

```C
#define IMAGE_NUMBEROF_DIRECTORY_ENTRIES    16
```

An ```IMAGE_DATA_DIRETORY``` structure is defines as follows:

```C
typedef struct _IMAGE_DATA_DIRECTORY {
    DWORD   VirtualAddress;
    DWORD   Size;
} IMAGE_DATA_DIRECTORY, *PIMAGE_DATA_DIRECTORY;
```

the structure of the Data Directory is very simple, it only has 2 fields, the RVA pointing to the start of the DD and the second being the size of the DD.

Again you may confused, what actually a Data Directory (DD) @@? Precisely it just a bunch of data located within one of the sections of the PE file.

Data Directory contain useful information needed by the loader, an example of a very important directory is the Import Directory which contains a list of external functions imported from other libraries, 

####  ```NOTE: NOT all Data Directories have the same structure, the IMAGE_DATA_DIRECTORY.VirtualAddress points to the Data Directory, however the type of that directory is what determines how that chunk of data is going to be parsed.```

Here a list of DD defined in ```winnt.h```(Each one of these values represents an index in the DataDirectory array, if both of the value is set to 0 that mean that specific DD isn't used or even doesn't exist in the PE):

```C
// Directory Entries

#define IMAGE_DIRECTORY_ENTRY_EXPORT          0   // Export Directory
#define IMAGE_DIRECTORY_ENTRY_IMPORT          1   // Import Directory
#define IMAGE_DIRECTORY_ENTRY_RESOURCE        2   // Resource Directory
#define IMAGE_DIRECTORY_ENTRY_EXCEPTION       3   // Exception Directory
#define IMAGE_DIRECTORY_ENTRY_SECURITY        4   // Security Directory
#define IMAGE_DIRECTORY_ENTRY_BASERELOC       5   // Base Relocation Table
#define IMAGE_DIRECTORY_ENTRY_DEBUG           6   // Debug Directory
//      IMAGE_DIRECTORY_ENTRY_COPYRIGHT       7   // (X86 usage)
#define IMAGE_DIRECTORY_ENTRY_ARCHITECTURE    7   // Architecture Specific Data
#define IMAGE_DIRECTORY_ENTRY_GLOBALPTR       8   // RVA of GP
#define IMAGE_DIRECTORY_ENTRY_TLS             9   // TLS Directory
#define IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG    10   // Load Configuration Directory
#define IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT   11   // Bound Import Directory in headers
#define IMAGE_DIRECTORY_ENTRY_IAT            12   // Import Address Table
#define IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT   13   // Delay Load Import Descriptors
#define IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR 14   // COM Runtime descriptor
```

![alt text](https://raw.githubusercontent.com/raviyelna/Journey-into-the-Fundamental-of-Malware-Analysing/refs/heads/main/Asset/PE_structure/images/image-19.png)

### Sections

Sections are the containers of the actual data of the executable file, they occupy the rest of the PE file after the headers, precisely after the section headers.

Some sections have special names that indicate their purpose, we’ll go over some of them, and a full list of these names can be found on the official [Microsoft Special Section Document](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#special-sections) 

```
.text: Contains the executable code of the program.
.data: Contains the initialized data.
.bss: Contains uninitialized data.
.rdata: Contains read-only initialized data.
.edata: Contains the export tables.
.idata: Contains the import tables.
.reloc: Contains image relocation information.
.rsrc: Contains resources used by the program, these include images, icons or even embedded binaries.
.tls: (Thread Local Storage), provides storage for every executing thread of the program.
```

![alt text](https://raw.githubusercontent.com/raviyelna/Journey-into-the-Fundamental-of-Malware-Analysing/refs/heads/main/Asset/PE_structure/images/image-20.png)

### Section Headers

After the Optional Header and before the sections comes the Section Headers. These headers contain information about the sections of the PE file.

A Section Header is a structure named ```IMAGE_SECTION_HEADER``` defined in ```winnt.h``` as below: 

```C
typedef struct _IMAGE_SECTION_HEADER {
    BYTE    Name[IMAGE_SIZEOF_SHORT_NAME];
    union {
            DWORD   PhysicalAddress;
            DWORD   VirtualSize;
    } Misc;
    DWORD   VirtualAddress;
    DWORD   SizeOfRawData;
    DWORD   PointerToRawData;
    DWORD   PointerToRelocations;
    DWORD   PointerToLinenumbers;
    WORD    NumberOfRelocations;
    WORD    NumberOfLinenumbers;
    DWORD   Characteristics;
} IMAGE_SECTION_HEADER, *PIMAGE_SECTION_HEADER;
```

1. **Name**: This is the name of the section, it’s a string of 8 characters, followed by a null character and then 4 padding bytes. ```(NOTE: For longer names the official documentation mentions a work-around by filling this field with an offset in the string table, however executable images do not use a string table so this limitation of 8 characters holds for executable images.)```

2. **PhysicalAddress or VirtualSize**: A union defines multiple names for the same thing, this field contains the total size of the section when it’s loaded in memory.

3. **VỉtualAddress**: The documentation states that for executable images this field holds the address of the first byte of the section relative to the image base when loaded in memory, and for object files it holds the address of the first byte of the section before relocation is applied.

4. **SizeOfRawData**: This field contains the size of the section on disk, it must be a multiple of ```IMAGE_OPTIONAL_HEADER.FileAlignment```.

5. **PointerToRawData**: A pointer to the first page of the section within the file, for executable images it must be a multiple of ```IMAGE_OPTIONAL_HEADER.FileAlignment```.

6. **PointerToRelocations**: A pointer to the beginning of the relocation entries for the section, it will be set to 0 if the file is an executable.

7. **PointerToLinenumbers**: A pointer to the beginning of the COFF line number entries for the section, it will be set to 0 if the COFF debugging information is deprecated.

8. **NumberOfRelocations**: The number of relocation entries for the section, it’s set to 0 for executable images.

9. **NumberOfLinenumbers**: The number of COFF line-number entries for the section, it will be set to 0 if the COFF debugging information is deprecated.

10. **Characteristics**: Flags that describe the characteristics of the section.
These characteristics are things like if the section contains executable code, contains initialized/uninitialized data, can be shared in memory.

#### NOTE: ```SizeOfRawData``` and ```VirtualSize``` can be different and this is normal for lots of reason.

```SizeOfRawData``` must be a multiple of ```IMAGE_OPTIONAL_HEADER.FileAlignment```, so if the section size is less than that value the rest gets padded and ```SizeOfRawData``` gets rounded to the nearest multiple of ```IMAGE_OPTIONAL_HEADER.FileAlignment```.
However when the section is loaded into memory it doesn’t follow that alignment and only the actual size of the section is occupied.
In this case ```SizeOfRawData``` will be greater than ```VirtualSize```

The opposite can happen as well.
If the section contains uninitialized data, these data won’t be accounted for on disk, but when the section gets mapped into memory, the section will expand to reserve memory space for when the uninitialized data gets later initialized and used.
This means that the section on disk will occupy less than it will do in memory, in this case ```VirtualSize``` will be greater than ```SizeOfRawData```.

![alt text](https://raw.githubusercontent.com/raviyelna/Journey-into-the-Fundamental-of-Malware-Analysing/refs/heads/main/Asset/PE_structure/images/image-21.png)

We can see ```Raw Addr.``` and ```Virtual Addr.``` fields which correspond to ```IMAGE_SECTION_HEADER.PointerToRawData``` and ```IMAGE_SECTION_HEADER.VirtualAddress```.

```Raw Size``` and ```Virtual Size``` correspond to ```IMAGE_SECTION_HEADER.SizeOfRawData``` and ```IMAGE_SECTION_HEADER.VirtualSize.```
We can see how these two fields are used to calculate where the section ends, both on disk and in memory. Let's take an example here:

for the ```.text``` section, the ```Raw Addr.``` is **0x400** and the ```Raw size``` is **0x24EE00** if we add sum both of these we will get the **0x24F200** that's the end of the ```.text``` section this also work for the ```Virtual Addr.``` and ```Virtual Size``` 
 
![alt text](https://raw.githubusercontent.com/raviyelna/Journey-into-the-Fundamental-of-Malware-Analysing/refs/heads/main/Asset/PE_structure/images/image-22.png)

## PE Imports (Import Directory Table - IDT, Import Lookup Table - ILT,  Import Address Table - IAT)

In the Section above, we have discussed about the Data section or (.text) section now we will dig into the (.data) section.

### Import Directory Table (IDT)

The Import Directory Table is a Data Directory located at the beginning of the .idata section.

It consists of an array of ```IMAGE_IMPORT_DESCRIPTOR``` structures, each one of them is for a DLL.
It doesn’t have a fixed size, so the last ```IMAGE_IMPORT_DESCRIPTOR``` of the array is zeroed-out (NULL-Padded) to indicate the end of the Import Directory Table.

```IMAGE_IMPORT_DESCRIPTOR``` is defined as below:

```C
typedef struct _IMAGE_IMPORT_DESCRIPTOR {
    union {
        DWORD   Characteristics;
        DWORD   OriginalFirstThunk;
    } DUMMYUNIONNAME;
    DWORD   TimeDateStamp;
    DWORD   ForwarderChain;
    DWORD   Name;
    DWORD   FirstThunk;
} IMAGE_IMPORT_DESCRIPTOR;
typedef IMAGE_IMPORT_DESCRIPTOR UNALIGNED *PIMAGE_IMPORT_DESCRIPTOR;
```

1. **OriginalFirstThunk**: RVA of the IAT

2. **TimeDateStamp**: A time date stamp, that’s initially set to 0 if not bound and set to -1 if bound.
In case of an unbound import the time date stamp gets updated to the time date stamp of the DLL after the image is bound.
In case of a bound import it stays set to -1 and the real time date stamp of the DLL can be found in the Bound Import Directory Table in the corresponding ```IMAGE_BOUND_IMPORT_DESCRIPTOR```.

3. **ForwarderChain**: The index of the first forwarder chain reference.
This is something responsible for DLL forwarding. ```(DLL forwarding is when a DLL forwards some of its exported functions to another DLL.)```

4. **Name**: An RVA of an ASCII string that contains the name of the imported DLL.

5. **FirstThunk**: RVA of the IAT.

### Bound Imports

A bound import essentially means that the import table contains **FIXED** addresses for the imported functions, These addresses are calculated and written during compile time by the linker.

Using bound imports is a speed optimization, it reduces the time needed by the loader to resolve function addresses and fill the IAT, however if at run-time the bound addresses **DO NOT** match the real ones then the loader will have to resolve these addresses again and fix the IAT.

### Bound Import Data Directory

The Bound Import Data Directory is similar to the Import Directory Table, however as the name suggests, it holds information about the bound imports.

It consists of an array of ```IMAGE_BOUND_IMPORT_DESCRIPTOR``` structures, and ends with a zeroed-out ```IMAGE_BOUND_IMPORT_DESCRIPTOR```.

```IMAGE_BOUND_IMPORT_DESCRIPTOR``` is defined as below:

```C
typedef struct _IMAGE_BOUND_IMPORT_DESCRIPTOR {
    DWORD   TimeDateStamp;
    WORD    OffsetModuleName;
    WORD    NumberOfModuleForwarderRefs;
// Array of zero or more IMAGE_BOUND_FORWARDER_REF follows
} IMAGE_BOUND_IMPORT_DESCRIPTOR,  *PIMAGE_BOUND_IMPORT_DESCRIPTOR;
```

1.  **TimeDateStamp**: The time date stamp of the DLL.

2. **OffsetModuleName**: The offset from the base of the image to the name of the DLL. (It's actually the offset from the ```IMAGE_BOUND_IMPORT_DESCRIPTOR```)

3. **NumberOfModuleForwarderRefs**: The number of the ```IMAGE_BOUND_FORWARDER_REF``` structures that immediately follow this structure.
```IMAGE_BOUND_FORWARDER_REF``` is a structure that’s identical to ```IMAGE_BOUND_IMPORT_DESCRIPTOR```, the only difference is that the last member is reserved.

### Import Lookup Table (ILT)

Or you may call it Import Name Table (INT), pretty much the same.

Every imported DLL has an Import Lookup Table.
```IMAGE_IMPORT_DESCRIPTOR```.```OriginalFirstThunk``` holds the RVA of the ILT of the corresponding DLL. The ILT is essentially a table of names or references, it tells the loader which functions are needed from the imported DLL.

The ILT consists of an array of 32-bit numbers (for PE32) or 64-bit numbers for (PE32+), the last one is zeroed-out to indicate the end of the ILT.

Each entry of these entries encodes information as follows:

1. **Bit 31/63 (most significant bit)**: This is called the Ordinal/Name flag, it specifies whether to import the function by name or by ordinal.

2. **Bits 15-0**: If the Ordinal/Name flag is set to 1 these bits are used to hold the 16-bit ordinal number that will be used to import the function, bits 30-15/62-15 for PE32/PE32+ must be set to 0.

3. **Bits 30-0**: If the Ordinal/Name flag is set to 0 these bits are used to hold an RVA of a Hint/Name table.

### Hint/Name Table

A Hint/Name table is a structure defined in winnt.h as IMAGE_IMPORT_BY_NAME:

``` CC
typedef struct _IMAGE_IMPORT_BY_NAME {
    WORD    Hint;
    CHAR   Name[1];
} IMAGE_IMPORT_BY_NAME, *PIMAGE_IMPORT_BY_NAME;
```

1. **Hint**: A word that contains a number, this number is used to look-up the function, that number is first used as an index into the export name pointer table, if that initial check fails a binary search is performed on the DLL’s export name pointer table.

2. **Name**: A character array that contains the name of the function to be imported.

### Import Address Table (IAT)

The IAT is identical to the ILT, however during bounding when the binary is being loaded into memory, the entries of the IAT get overwritten with the addresses of the functions that are being imported.

Example: Let's look at the SHELL32.dll in the picture below, after following the RVA in the OriginalFirstThunk, Let's say I want to know where and what the 2nd function (yellow box) imported from that DLL is, I will take 2nd 8 bytes (64-bits, and goto that virtual address location)

![alt text](https://raw.githubusercontent.com/raviyelna/Journey-into-the-Fundamental-of-Malware-Analysing/refs/heads/main/Asset/PE_structure/images/image-23.png)

![alt text](https://raw.githubusercontent.com/raviyelna/Journey-into-the-Fundamental-of-Malware-Analysing/refs/heads/main/Asset/PE_structure/images/image-24.png)

Remember, the first 2 bytes is for hint the rest is for the name, you see all the correct value right? ShellExecuteExA, CommandLine... then finally the SHELL32.dll

![alt text](https://raw.githubusercontent.com/raviyelna/Journey-into-the-Fundamental-of-Malware-Analysing/refs/heads/main/Asset/PE_structure/images/image-25.png)

## PE Base Relocation

### Relocations 

So let's just say when a program is compiled, the compiler assumes that the executable will be loaded at a certain base address, that address is saved in ```IMAGE_OPTIONAL_HEADER.ImageBase```, some addresses will get calculated then hardcoded into the binary based on the base address. However, the base address is not always the same, it can be different for variety of reasons, such as the program is loaded into a different memory location, or the program is loaded into a different process. In such cases, the hardcoded addresses will be incorrect and invalid.

A list of all hardcoded values that will need fixing if the image is loaded at a different base address is saved in a special table called the Relocation Table (a Data Directory within the ```.reloc``` section). The process of relocating (done by the loader) is what fixes these values.

Let’s take an example, the following code defines an int variable and a pointer to that variable:

```C
int test = 2;
int* testPtr = &test;
```

During compile-time, the compiler will assume a base address, let’s say it assumes a base address of ```0x1000```, it decides that test will be located at an offset of ```0x100``` and based on that it gives testPtr a value of ```0x1100```.
Later on, a user runs the program and the image gets loaded into memory.
It gets a base address of ```0x2000```, this means that the hardcoded value of testPtr will be invalid, the loader fixes that value by adding the difference between the assumed base address and the actual base address, in this case it’s a difference of ```0x1000``` (```0x2000``` - ```0x1000```), so the new value of testPtr will be ```0x2100``` (```0x1100``` + ```0x1000```) which is the correct new address of test.

### Relocation Table

As described by Microsoft documentation, the base relocation table contains entries for all base relocations in the image.

It’s a Data Directory located within the ```.reloc``` section, it’s divided into blocks, each block represents the base relocations for a 4K page and each block must start on a 32-bit boundary.

Each block starts with an ```IMAGE_BASE_RELOCATION``` structure followed by any number of offset field entries.

The ```IMAGE_BASE_RELOCATION``` structure specifies the page RVA, and the size of the relocation block.

```C
typedef struct _IMAGE_BASE_RELOCATION {
    DWORD   VirtualAddress;
    DWORD   SizeOfBlock;
} IMAGE_BASE_RELOCATION;
typedef IMAGE_BASE_RELOCATION UNALIGNED * PIMAGE_BASE_RELOCATION;
```

Each offset field entry is a WORD, first 4 bits of it define the relocation type, you can check [Microsoft documentation for a list of relocation types](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#base-relocation-types).

The last 12 bits store an offset from the RVA specified in the IMAGE_BASE_RELOCATION structure at the start of the relocation block. 

Each relocation entry gets processed by adding the RVA of the page to the image base address, then by adding the offset specified in the relocation entry, an absolute address of the location that needs fixing can be obtained.

Let's take an example the first relocation block, it's size is **0x2FC**, we know that each block start with 8 bytes-long structure so the actual size is **0x2F4** is 756 in decimal, each entry is 2 bytes so the total entry should be 378, and that is correct.

![alt text](https://raw.githubusercontent.com/raviyelna/Journey-into-the-Fundamental-of-Malware-Analysing/refs/heads/main/Asset/PE_structure/images/image-27.png)

---

Thats pretty much it, thanks for reading <3

Reference: 

[0xRick](https://github.com/0xRick)

[Microsoft Official Document](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#base-relocation-types)

![text](https://raw.githubusercontent.com/raviyelna/Journey-into-the-Fundamental-of-Malware-Analysing/refs/heads/main/Asset/Zani_gif/working.gif)
