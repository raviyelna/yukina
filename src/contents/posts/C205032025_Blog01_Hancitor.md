---
title: Malware Analyzing Series Blog 01
published: 2025-03-05
description: HancitorDLL Analyze Blog.
tags: [PE, Blogging, Malware Analyze]
category: Malware Analyze
draft: false
---

# Malware Analyzing Series Blog 01
## Blog01 Part 1
### Cool.DLL

Note: This is my First time doing this kind of Analyze, If there is any mistake that I made, I'm very sorry, please forgive me, I'm new to this, I will try fixing and trying harder everyday.

![image](https://hackmd.io/_uploads/SkxPMZEIjJx.png)

SHA256: 8ff43b6ddf6243bd5ee073f9987920fa223809f589d151d7e438fd8cc08ce292


![image](https://hackmd.io/_uploads/HySs-N8ske.png)

![image](https://hackmd.io/_uploads/rkivM4Iiyg.png)

Using Capa, it detected there was a process Injection at the address 0x100400AC, lets open IDA and check it

![image](https://hackmd.io/_uploads/Sk7ekSLiyx.png)

So there was a **VirtualProtecEx**

![image](https://hackmd.io/_uploads/rJB41rLsJe.png)

Let's dig more into it by debugging with x32dbg since this is 32 bit dll

![image](https://hackmd.io/_uploads/rkKhgBLjJe.png)

If you don't know why are we searching for that Windows API, then here the explaination:
```!
VirtualProtectEx is typically used with pages allocated by VirtualAllocEx and for your information there is a technique called, DLL Injection, this technique is used to force a process to load a DLL. Main potentially involved APIs: 
OpenProcess( ), VirtualAllocEx( ), WriteProcessMemory and CreateRemoteThreat | NtCreateThread( ) | RtlCreateUserThread( ).
Also this DLL seem like a packed Executable due to íts IAT and High entropy
```

![image](https://hackmd.io/_uploads/ry3gmrLi1l.png)

But first Lets just sync the IDA with the Debugger, it will help us analyze way more easier.

![image](https://hackmd.io/_uploads/HJJ1HSLoJe.png)

Okay, thats definately look better than before! Now its time to step into/over to understand what does this code do. After stepping over hundreds of times of looping I finally found something intersting another WindowsAPI calling, this time its the actual **Virtual Alloc**, Let's put a breakpoint here so we can get it faster if we need to to resart the whole process.

![image](https://hackmd.io/_uploads/rycm8SUiJe.png)

As you can see below, the EAX register will hold the value of the **Virtual Alloc**, let's dump that EAX register.

![image](https://hackmd.io/_uploads/BkodUr8jye.png)

After Debugging around the **Virtual Alloc** and dumping where the register seem weird, I finally found something interesting

![image](https://hackmd.io/_uploads/B1FLFSUjyl.png)

![image](https://hackmd.io/_uploads/rJ3vFSUokx.png)

![image](https://hackmd.io/_uploads/rJ8sYSLoyx.png)

The EIP now locate somewhere it shouldn't be along with a PE, following the memory map then dumping out the memory, if you look carefully this header is somekind of **M8Z**

![image](https://hackmd.io/_uploads/Bkhx9BUoJl.png)

Dumping the memory out and checking for the M8Z header we got this result

![image](https://hackmd.io/_uploads/HyAC3rUjkg.png)

Using this repo to decompressed the Dumped Memory -> [Aplib.py](https://github.com/snemes/aplib)

After getting the decompressed DLL, load it back in IDA again, we can see the function clearly now, the function currently showing in the screenshot below is a function where it sending your, ID, Windows version, IP.

![image](https://hackmd.io/_uploads/BJM3CBLsJg.png)

![image](https://hackmd.io/_uploads/B1Qf1U8skl.png)

![image](https://hackmd.io/_uploads/H1e2-L8j1l.png)


UserAgent, Getting the Data back from the C2 server.

![image](https://hackmd.io/_uploads/SkzmJULiJe.png)

![image](https://hackmd.io/_uploads/Bk1SJLUsyl.png)

This is the config function I think.

![image](https://hackmd.io/_uploads/Byv31IIiyx.png)

There are something cool while digging in these function, I found where it decrypt or connect to the C2 server.

![image](https://hackmd.io/_uploads/SJT1eUIi1g.png)

![image](https://hackmd.io/_uploads/rJcSx8Uskx.png)

It take 0x2000 bytes of the Encrypted Data then use 0x8 bytes from the key to decrypt the whole Encrypted Data.

![image](https://hackmd.io/_uploads/B1eYxL8jke.png)

We can dump this Data out using Ida python, then write a script to get back the data that it encrypted.

```cpp!
#include <iostream>
#include <windows.h>
#include <wincrypt.h>
#include <string>
#include <fstream>
using namespace std;

DWORD __cdecl crypt(BYTE* pbData, DWORD pdwDataLen, BYTE* pbDataa, DWORD dwDataLen)
{
    DWORD pdwDataLen_1; // esi
    HCRYPTPROV phProv; // [esp+8h] [ebp-Ch] BYREF
    HCRYPTKEY phKey; // [esp+Ch] [ebp-8h] BYREF
    HCRYPTHASH phHash; // [esp+10h] [ebp-4h] BYREF

    phKey = 0;
    pdwDataLen_1 = 0;
    phHash = 0;
    phProv = 0;
	if (CryptAcquireContextA(&phProv, 0, 0, 1u, 0xF0000000)
		&& CryptCreateHash(phProv, 0x8004u, 0, 0, &phHash)
		&& CryptHashData(phHash, pbDataa, dwDataLen, 0)
		&& CryptDeriveKey(phProv, 0x6801u, phHash, 0x280011u, &phKey)
		&& CryptDecrypt(phKey, 0, 1, 0, pbData, &pdwDataLen))
	{
        pdwDataLen_1 = pdwDataLen;
    }
    if (phHash)
    {
        CryptDestroyHash(phHash);
        phHash = 0;
    }
    if (phKey)
    {
        CryptDestroyKey(phKey);
        phKey = 0;
    }
    if (phProv)
        CryptReleaseContext(phProv, 0);
    return pdwDataLen_1;
}

int main()
{
	BYTE pbData[0x2001];
	DWORD pdwDataLen;
	BYTE pbDataa[0x1000];
	DWORD dwDataLen;
	string input;
	
	// Read the encrypted data from the file
	ifstream file("dump.bin");
	if (file.is_open())
	{
		getline(file, input);
	}
	else
	{
		cout << "Unable to open file" << endl;
		return 1;
	}
	dwDataLen = input.length();
	for (int i = 0; i < dwDataLen; i++)
	{
		pbData[i] = input[i];
	}

    // read key byte
	ifstream file2("key.bin");
	if (file2.is_open())
	{
		getline(file2, input);
		file2.close();
	}
	else
	{
		cout << "Unable to open file" << endl;
		return 1;
	}
	dwDataLen = input.length();
	for (int i = 0; i < dwDataLen; i++)
	{
		pbDataa[i] = input[i];
	}
	pdwDataLen = crypt(pbData, 0x2000, pbDataa, 0x8);
		
	ofstream file3("decrypted.bin", ios::binary);
	if (file3.is_open())
	{
		file3.write((char*)pbData, pdwDataLen);
		file3.close();
	}
	else
	{
		cout << "Unable to open file" << endl;
		return 1;
	}

	return 0;
}
```

Decrypted:
```!
1910_nsw http://newnucapi.com/8/forum.php|http://gintlyba.ru/8/forum.php|http://stralonz.ru/8/forum.php|
```

Also this is where it's looping around those url that seperated by "|"

![image](https://hackmd.io/_uploads/Bya0Z8LiJl.png)

We can also see this way more clearer by debugging

![image](https://hackmd.io/_uploads/rkLLGLIsyg.png)

![image](https://hackmd.io/_uploads/SyNwMIUsJl.png)

So I think this is it for this part, Next part I will try re-creating the Server it connect to and play around with it.

POC:
```
HTTP:
POST http://stralonz.ru/8/forum.php 
GET http://api.ipify.org/
POST http://newnucapi.com/8/forum.php
DNS record:
api.ipify.org
gintlyba.ru
newnucapi.com
stralonz.ru
Sample:
8ff43b6ddf6243bd5ee073f9987920fa223809f589d151d7e438fd8cc08ce292 (Cool.DLL)
da84c5550d4ac64b1f45bd90b222145eef6ba5071ba354b58a6a6f03d566e4df (Hancitor)
```
--- 

Thank you so much Table for helping, explaining and guiding me.

![image](https://hackmd.io/_uploads/Syx0zL8sJg.png)