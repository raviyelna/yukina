---
title:  TET CTF 2024
published: 2024-04-04
description:  TET CTF 2024
tags: [CTFs, DFIR]
category: CTFs Write-up
draft: false
---

# TETctf
## Forensics - 4n6

![image](https://hackmd.io/_uploads/HyLWLIhyR.png)

The chall gives us 2 files one is Ad1 file and the other one is Raw file

you can use the Ad1 file in [FTK-imager](https://www.exterro.com/) and Raw image in [Volatility3](https://github.com/volatilityfoundation/volatility3) (I would recommand you using FTK cause it has UI and you can see all the file and path clearly).
For me I will be using the FTK imager cause It really help me solve DFIR chall easier and faster

![image](https://hackmd.io/_uploads/rJ5XvUn1R.png)

Ok the first thing we need to do is read the Challenge description to know where to start.

**"After reading the rules, my computer seemed unusual"** Remember this line.

The victim's Computer seem to be infected after reading some word files so this maybe the clue for our problem, and we have an evidence thats the malicious code may in the docx file so its must **VBA macro**.

![image](https://hackmd.io/_uploads/S1roKU3y0.png)

Checking the **Recent folder** We can see that the victim download some files and "TetCTF2024-Rules" seem to be Word file that was said to be had the malicous code.

![image](https://hackmd.io/_uploads/BkPqxv31R.png)

(You can search Google to know where the macros stored)

![image](https://hackmd.io/_uploads/SyMzMv310.png)

export The dotm file then copy it to Linux to check Macros with [Olevba](https://github.com/volatilityfoundation/volatility3) we can see the Ip and Port. At the end you can see a hex string look suspicous

![image](https://hackmd.io/_uploads/Bki5zv3yR.png)

![image](https://hackmd.io/_uploads/rJKRMP31A.png)

![image](https://hackmd.io/_uploads/SyumQv3J0.png)

Decode the strings with base64 5 times and you will got the full First flag

**TETctf{172.20.25.15:4444_VBA-M4cR0**


## My route to find second part of the Flag is unintentional!!!
    
### The victim said that He had registerd an Account but He no longer remember the password

->So the First thing we need to know that What site did he created the account by checking the history file stored in chrome

![image](https://hackmd.io/_uploads/rkunEPnJA.png)

Export this file then Open it with SQLite checking the URl visited

![image](https://hackmd.io/_uploads/HkJMuD21A.png)

Then we can see the 2nd part of the flag

**REMEMBER THIS IS AN UNINTENTIONAL ROUTE IT SHOULDNT BE SOLVED LIKE THIS**



## Flag: **TETctf{172.20.25.15:4444_VBA-M4cR0_R3c0v3rry_34sy_R1ght?}**





