---
title: Malware Analyzing Series Blog 05
published: 2025-04-17
description: Xworm Analyze Blog.
tags: [PE, Blogging, Malware Analyze, C2 server emulating]
category: Malware Analyze
draft: false
---


# C217042025 Dive into Xworm, Emulating C2 Server

## Overview

XWorm is a multi-functional malware family, commonly used as remote access trojan. It allows cybercriminals to gain unauthorized access to devices, steal sensitive information such as login credentials and passwords, or even install ransomware and launch DDoS attacks. This modular design makes XWorm a sophisticated and highly customizable piece of malware.

## Sample

Sample: ```1c795db3d251600f7529200896cf0b8b80ebfb8172cd0fa1851f094871027fd6```

## Analysis

The sample is an average Xworm written in VBNet

![alt text](https://raw.githubusercontent.com/raviyelna/Journey-into-the-Fundamental-of-Malware-Analysing/refs/heads/main/Asset/17042025_Xworm/images/image.png)

If you haven't know about the Xworm yet? They alway have a config, that let you make change to the malware such as encryption key, C2 domain,... You can see this part clearly in the picture below.

![alt text](https://raw.githubusercontent.com/raviyelna/Journey-into-the-Fundamental-of-Malware-Analysing/refs/heads/main/Asset/17042025_Xworm/images/image-1.png)

These config setting will be decrypt in the main function by using AES ECB mode with the hardcoded key as mutex string.

![alt text](https://raw.githubusercontent.com/raviyelna/Journey-into-the-Fundamental-of-Malware-Analysing/refs/heads/main/Asset/17042025_Xworm/images/image-2.png)

![alt text](https://raw.githubusercontent.com/raviyelna/Journey-into-the-Fundamental-of-Malware-Analysing/refs/heads/main/Asset/17042025_Xworm/images/image-3.png)

![alt text](https://raw.githubusercontent.com/raviyelna/Journey-into-the-Fundamental-of-Malware-Analysing/refs/heads/main/Asset/17042025_Xworm/images/image-4.png)

Look at the Function where the connection start establishing, basically the malware will try to connect to the domain:port, if fail it will sleep and try again later, the way it work will be describe as the flow chart below

![alt text](https://raw.githubusercontent.com/raviyelna/Journey-into-the-Fundamental-of-Malware-Analysing/refs/heads/main/Asset/17042025_Xworm/images/image-5.png)

There isn't to talk about since all the function are kinda clear to read, there are lots of thing you can do with this malware, even use it to deploy another kind of malware on the victim system.

![alt text](https://raw.githubusercontent.com/raviyelna/Journey-into-the-Fundamental-of-Malware-Analysing/refs/heads/main/Asset/17042025_Xworm/images/image-6.png)

So since there nothing else left to do, I decided I will try to Emulating the C2 server.

## Emulating the C2 Server

Since the traffic between the server and the malware is encrypted, we need to understand what it does and how it sends and receives data between the server and the client.

Let's take a look at the Sending Function here, it will encrypt the data using AES ECB with the key hardcoded (note: this key is from the config not the mutex), the interesting part here is that, the way the ```AES_Encryptor``` function return a string in a particular format, that is ```len(encryptedData) + '/x00' +encryptedData```

![alt text](https://raw.githubusercontent.com/raviyelna/Journey-into-the-Fundamental-of-Malware-Analysing/refs/heads/main/Asset/17042025_Xworm/images/image-7.png)

![alt text](https://raw.githubusercontent.com/raviyelna/Journey-into-the-Fundamental-of-Malware-Analysing/refs/heads/main/Asset/17042025_Xworm/images/image-8.png)

This is also the way the Malware will receive bytes from the server, same format ```len(encryptedData) + '/x00' +encryptedData```

![alt text](https://raw.githubusercontent.com/raviyelna/Journey-into-the-Fundamental-of-Malware-Analysing/refs/heads/main/Asset/17042025_Xworm/images/image-9.png)

After checking all correct then it will start reading the bytes, if there is more than argument got input, they are separated by the ```SPL```.

![alt text](https://raw.githubusercontent.com/raviyelna/Journey-into-the-Fundamental-of-Malware-Analysing/refs/heads/main/Asset/17042025_Xworm/images/image-10.png)

You can check the script by click [here](https://raw.githubusercontent.com/raviyelna/Journey-into-the-Fundamental-of-Malware-Analysing/refs/heads/main/Asset/17042025_Xworm/script/local_server.py)

Test Video: 


![poc](https://raw.githubusercontent.com/raviyelna/Journey-into-the-Fundamental-of-Malware-Analysing/refs/heads/main/Asset/17042025_Xworm/videos/poc.gif)
