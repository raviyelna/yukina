---
title: API Hashing & HashDB
published: 2025-04-24
description: A simple blog about API Hashing & HashDB blog post, may you found what you need here <3
tags: [API Hashing, Blogging, HashDB]
category: Blog
draft: false
---

# API Hashing & HashDB

## API Hashing

### Overview

- API Hashing - a technique employed by malware developers, that makes malware analysis a bit more difficult by hiding suspicious imported Windows APIs from the Import Address Table of the Portable Executable.

- This technique can obfuscate the true behavior of the malware, making it challenging for analysts to identify the specific functions being called and the overall intent of the malware.

### Analyze


If we have this code like the one below then compile it, checking the imported address table (IAT) you will see there a suspicious API in the Kernel32 DLL table.

![alt text](https://raw.githubusercontent.com/raviyelna/Journey-into-the-Fundamental-of-Malware-Analysing/refs/heads/main/Asset/API_Asset/images/image-0.png)

![alt text](https://raw.githubusercontent.com/raviyelna/Journey-into-the-Fundamental-of-Malware-Analysing/refs/heads/main/Asset/API_Asset/images/image-1.png)

So the goal here is how can we hide it? That's where API hashing technique jump in.

![alt text](https://raw.githubusercontent.com/raviyelna/Journey-into-the-Fundamental-of-Malware-Analysing/refs/heads/main/Asset/API_Asset/images/image-2.png)

By using a hashing algorithm to compute a hash value of the API name, we can replace the actual API name in the code with its hash, thereby obscuring the true function being called. When the malware is executed, it can dynamically resolve the hash back to the original API name at runtime, allowing it to function normally while remaining hidden from static analysis tools. 

As you can see in the image below, there is no "CreateThread" in the Kernel32.dll Import Address Table (IAT). even though the program can still create new thread.

![alt text](https://raw.githubusercontent.com/raviyelna/Journey-into-the-Fundamental-of-Malware-Analysing/refs/heads/main/Asset/API_Asset/images/image-3.png)

![alt text](https://raw.githubusercontent.com/raviyelna/Journey-into-the-Fundamental-of-Malware-Analysing/refs/heads/main/Asset/API_Asset/images/image-4.png)

So how does it work? Let's start by implementing a hashing function that can convert the API names into their corresponding hash values.

you can check out the full python script [here](https://github.com/raviyelna/Journey-into-the-Fundamental-of-Malware-Analysing/tree/main/Asset/API_Asset/Script/), the script is using `djb2` hashing, one of the most common hashing algorithm used by malware developer.

![alt text](https://raw.githubusercontent.com/raviyelna/Journey-into-the-Fundamental-of-Malware-Analysing/refs/heads/main/Asset/API_Asset/images/image-5.png)

![alt text](https://raw.githubusercontent.com/raviyelna/Journey-into-the-Fundamental-of-Malware-Analysing/refs/heads/main/Asset/API_Asset/images/image-6.png)

By default if we want to know what does the value `"0x4185CD83"` is, we have to reverse engineer the whole function that it used to hash the API name, like the one above is `djb2`, then write a script with the wordlist to bruteforce the original API name back from the hash.

like this example script, you can check out the full python script [here](https://github.com/raviyelna/Journey-into-the-Fundamental-of-Malware-Analysing/tree/main/Asset/API_Asset/Script/)

![alt text](https://raw.githubusercontent.com/raviyelna/Journey-into-the-Fundamental-of-Malware-Analysing/refs/heads/main/Asset/API_Asset/images/image-7.png)

So how does a C++ program resolve the API? Here a simple C++ code that resolve the `"CreateThread"` API in ```Kernel32.dll```

```c++
#include <windows.h>
#include <iostream>
#include <string>

using namespace std;

typedef HANDLE(WINAPI* CreateThread_t)(
    LPSECURITY_ATTRIBUTES, SIZE_T, LPTHREAD_START_ROUTINE, LPVOID, DWORD, LPDWORD);

DWORD djb2_hash(const char* str, DWORD seed = 0x1337) {
    DWORD hash = seed;
    while (*str) {
        hash = ((hash << 5) + hash) + *str;
        str++;
    }
    return hash;
}

DWORD WINAPI SussyThreadCreating(LPVOID lpParam) {
    cout << "[*] Hello, I'm Ravi\n";
    Sleep(12000);
    cout << "[*] Byeeee.\n";
    return 0;
}

int main() {
    HMODULE hModule = LoadLibraryA("kernel32.dll");
    if (!hModule) {
        cerr << "Failed to load kernel32.dll\n";
        return 1;
    }

    DWORD targetHash = 0x4185CD83;

    BYTE* baseAddr = (BYTE*)hModule;
    IMAGE_DOS_HEADER* dosHeader = (IMAGE_DOS_HEADER*)baseAddr;
    IMAGE_NT_HEADERS* ntHeaders = (IMAGE_NT_HEADERS*)(baseAddr + dosHeader->e_lfanew);

    IMAGE_EXPORT_DIRECTORY* exportDir = (IMAGE_EXPORT_DIRECTORY*)(
        baseAddr + ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

    DWORD* nameRvas = (DWORD*)(baseAddr + exportDir->AddressOfNames);
    WORD* ordinals = (WORD*)(baseAddr + exportDir->AddressOfNameOrdinals);
    DWORD* funcRvas = (DWORD*)(baseAddr + exportDir->AddressOfFunctions);

    void* resolvedFunc = nullptr;

    for (DWORD i = 0; i < exportDir->NumberOfNames; i++) {
        char* funcName = (char*)(baseAddr + nameRvas[i]);
        DWORD hash = djb2_hash(funcName);

        if (hash == targetHash) {
            WORD ordinal = ordinals[i];
            DWORD funcRva = funcRvas[ordinal];
            resolvedFunc = (void*)(baseAddr + funcRva);

            cout << "[+] Resolved CreateThread:\n";
            cout << "    Address: " << resolvedFunc << "\n";
            break;
        }
    }

    if (!resolvedFunc) {
        cerr << "[-] Failed to resolve CreateThread\n";
        return 1;
    }

    CreateThread_t VerySusThread = (CreateThread_t)resolvedFunc;

    DWORD threadId;
    HANDLE hThread = VerySusThread(nullptr, 0, SussyThreadCreating, nullptr, 0, &threadId);

    if (hThread) {
        cout << "[+] Thread started! Waiting...\n";
        WaitForSingleObject(hThread, INFINITE);
        CloseHandle(hThread);
    }
    else {
        cerr << "[-] Failed to start thread\n";
    }

    return 0;
}
```

If we look at the code when it compiled and loaded in the IDA pseudo-code we can see the API that it's trying to resolve, you can try out this yourself by downloading the PE [here](https://github.com/raviyelna/Journey-into-the-Fundamental-of-Malware-Analysing/tree/main/Asset/API_Asset/Script/).

![alt text](https://raw.githubusercontent.com/raviyelna/Journey-into-the-Fundamental-of-Malware-Analysing/refs/heads/main/Asset/API_Asset/images/image-8.png)

## HashDB

### Overview

- HashDB is a community-sourced library of hashing algorithms used in malware. 

- HashDB's database designed to store and retrieve hashes of various APIs, allowing for efficient resolution and identification of functions within portable executable (PE) files. This tool aids in reverse engineering and malware analysis by providing quick access to known hashes and their corresponding API names.

### Analyze 

HashDB allows analysts to quickly identify functions within binaries, streamlining the reverse engineering process. By referencing known hashes, users can verify the integrity of APIs and detect potential modifications or obfuscations in malware samples.

This is a ```CobaltStrike``` Sample, SHA256: ```132fa71af952927e1961f735e68ae38a3305e7ae8d7197c170d071f74db60d1c```

![alt text](https://raw.githubusercontent.com/raviyelna/Journey-into-the-Fundamental-of-Malware-Analysing/refs/heads/main/Asset/API_Asset/images/image-9.png)

HashDB have a feature where it can help you detect what type of hashing algorithm the value is, it's called "HashDB Hunt Algorithm", we can quickly found out that this is metasploit hash, then just resolve and set the enum for that value.

![alt text](https://raw.githubusercontent.com/raviyelna/Journey-into-the-Fundamental-of-Malware-Analysing/refs/heads/main/Asset/API_Asset/images/image-10.png)

![alt text](https://raw.githubusercontent.com/raviyelna/Journey-into-the-Fundamental-of-Malware-Analysing/refs/heads/main/Asset/API_Asset/images/image-11.png)

Another example in the same PE file.

![alt text](https://raw.githubusercontent.com/raviyelna/Journey-into-the-Fundamental-of-Malware-Analysing/refs/heads/main/Asset/API_Asset/images/image-12.png)

![alt text](https://raw.githubusercontent.com/raviyelna/Journey-into-the-Fundamental-of-Malware-Analysing/refs/heads/main/Asset/API_Asset/images/image-13.png)

Ok let's try another sample, ```Dridex```, SHA256: ```c7990f1e72fdfa84552f02f9d11cabb74251b0508291af5366fefcee646f9c91```

This definately look like a API resolving, but the interesting here is that if you try to hunt for the hash, there nothing match the hash, weird huh? because this one actually has a xor key.

![alt text](https://raw.githubusercontent.com/raviyelna/Journey-into-the-Fundamental-of-Malware-Analysing/refs/heads/main/Asset/API_Asset/images/image-14.png)

Xor key: 0x7AF3DA47 (You have to reverse engineering it yourself to understand why the xor key is that value, hehe)

![alt text](https://raw.githubusercontent.com/raviyelna/Journey-into-the-Fundamental-of-Malware-Analysing/refs/heads/main/Asset/API_Asset/images/image-15.png)

After setting the xor key, try hunting the hash again, you will see it now identified the algorithm and there we go, all resolved.

![alt text](https://raw.githubusercontent.com/raviyelna/Journey-into-the-Fundamental-of-Malware-Analysing/refs/heads/main/Asset/API_Asset/images/image-16.png)

![alt text](https://raw.githubusercontent.com/raviyelna/Journey-into-the-Fundamental-of-Malware-Analysing/refs/heads/main/Asset/API_Asset/images/image-17.png)

Too slow? Too lazy to set the enum? There actually a quicker way to do this. Try setting the prototype of the function instead of int, try setting it to the name of the enum that hashDB created for you. 


![alt text](https://raw.githubusercontent.com/raviyelna/Journey-into-the-Fundamental-of-Malware-Analysing/refs/heads/main/Asset/API_Asset/images/image-18.png)

Everything is automated now, if it still showing the hash value then that hash value hasn't been imported as an enum try looking up that hash value again or try hunt for algorithm if it actually another hashing algorithm.

![alt text](https://raw.githubusercontent.com/raviyelna/Journey-into-the-Fundamental-of-Malware-Analysing/refs/heads/main/Asset/API_Asset/images/image-19.png)

Another Sample, let's go this one is ```Blackmatter Ransomware```  SHA256: ```22d7d67c3af10b1a37f277ebabe2d1eb4fd25afbd6437d4377400e148bcc08d6```

You can see here in the picture below, this time the input value isn't only an int anymore, it now a chunk of DWORD.

![alt text](https://raw.githubusercontent.com/raviyelna/Journey-into-the-Fundamental-of-Malware-Analysing/refs/heads/main/Asset/API_Asset/images/image-20.png)

This is the inside of the function that it hashing and resolving the API, there a particular value that appear at the end of every chunk of data, its the `"0xCCCCCCCC"` this indicate the end of a chunk, also remember to set the xor key (`0x22065FED`)

![alt text](https://raw.githubusercontent.com/raviyelna/Journey-into-the-Fundamental-of-Malware-Analysing/refs/heads/main/Asset/API_Asset/images/image-21.png)

Before: 

![alt text](https://raw.githubusercontent.com/raviyelna/Journey-into-the-Fundamental-of-Malware-Analysing/refs/heads/main/Asset/API_Asset/images/image-22.png)

After: 

![alt text](https://raw.githubusercontent.com/raviyelna/Journey-into-the-Fundamental-of-Malware-Analysing/refs/heads/main/Asset/API_Asset/images/image-23.png)

You can even create a struct for it, then rename the ptr that target that stucture to find the xref quicker.

![alt text](https://raw.githubusercontent.com/raviyelna/Journey-into-the-Fundamental-of-Malware-Analysing/refs/heads/main/Asset/API_Asset/images/image-24.png)

![alt text](https://raw.githubusercontent.com/raviyelna/Journey-into-the-Fundamental-of-Malware-Analysing/refs/heads/main/Asset/API_Asset/images/image-25.png)

Okay final sample, this one actually came from [Cyberdefenders](https://cyberdefenders.org/blueteam-ctf-challenges/tealer/), the malware in the lab used CRC32 with a xor key that can be found in the picture below, setting the key then use HashDB we can get what it's trying to do.

![alt text](https://raw.githubusercontent.com/raviyelna/Journey-into-the-Fundamental-of-Malware-Analysing/refs/heads/main/Asset/API_Asset/images/image-26.png)

![alt text](https://raw.githubusercontent.com/raviyelna/Journey-into-the-Fundamental-of-Malware-Analysing/refs/heads/main/Asset/API_Asset/images/image-27.png)

![alt text](https://raw.githubusercontent.com/raviyelna/Journey-into-the-Fundamental-of-Malware-Analysing/refs/heads/main/Asset/API_Asset/images/image-28.png)

![alt text](https://raw.githubusercontent.com/raviyelna/Journey-into-the-Fundamental-of-Malware-Analysing/refs/heads/main/Asset/API_Asset/images/image-29.png)

![alt text](https://raw.githubusercontent.com/raviyelna/Journey-into-the-Fundamental-of-Malware-Analysing/refs/heads/main/Asset/API_Asset/images/image-30.png)

![alt text](https://raw.githubusercontent.com/raviyelna/Journey-into-the-Fundamental-of-Malware-Analysing/refs/heads/main/Asset/API_Asset/images/image-31.png)

Note: Since HashDB only contains the Hashing Algorithm of those Malware that the community contribute, if the sample is new or no one upload the hashing algorithm to the DB then you have to do the resolving by hand or debugging. 

Reference: 
[@OAlab](https://x.com/herrcore)