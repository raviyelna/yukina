---
title: Malware Analyzing Series Blog 02
published: 2025-03-10
description: Metatrader.exe Analyze Blog.
tags: [PE, Blogging, Malware Analyze]
category: Malware Analyze
draft: false
---

# Malware Analyzing Series Blog 02
## Blog02: Metatrader.exe

note: sorry I couldn't continue with the part 2 of the Blog01, if I want to continue to play around with the Malware I have to set-up a domain then analyze how the C2 work, but sadly I'm kind of busy that week so I couldn't investigate more, so to make it up to y'all I decided to log on MalwareBazaar, while I'm on there I found a very interesting one so this is that one, hope you like it, it's a bit short so... I'm sorry :< 
```
Ravi, Mar 10, 2025, 10:23PM GMT+7
```
---

![image](https://hackmd.io/_uploads/rkQJpPhjJe.png)

By openning the PE file in IDA, after analyze and rename some of the functions, we can clearly know what this malware is.

![image](https://hackmd.io/_uploads/r1NTed2okl.png)

![image](https://hackmd.io/_uploads/SyXJ-Onjkx.png)

![image](https://hackmd.io/_uploads/Skyj7u2okg.png)

### Cookie stealer function: 

![image](https://hackmd.io/_uploads/B1ACrO2jyg.png)

### Get Information Functions 

![image](https://hackmd.io/_uploads/r1gZDO3j1e.png)


After, gathering all the data that it needed the 2nd phase begin, it will try to call and recursive into every programfile that in your computer.

![image](https://hackmd.io/_uploads/BkWd4_hsJx.png)

```
10:09:19.1047407 PM	metatrader.exe	7324	Process Start		SUCCESS	Parent PID: 6500, Command line: "C:\Users\Raviel\Desktop\194247b2d4724928446b4cdea53167be6cf0ebd60858ca0c2d4bdc6cdb5a4c54\metatrader.exe" , Current directory: C:\Users\Raviel\Desktop\194247b2d4724928446b4cdea53167be6cf0ebd60858ca0c2d4bdc6cdb5a4c54\, Environment: 
	=::=::\
	ALLUSERSPROFILE=C:\ProgramData
	APPDATA=C:\Users\Raviel\AppData\Roaming
	CommonProgramFiles=C:\Program Files\Common Files
	CommonProgramFiles(x86)=C:\Program Files (x86)\Common Files
	CommonProgramW6432=C:\Program Files\Common Files
	COMPUTERNAME=DESKTOP-Q1QOHS1
	ComSpec=C:\Windows\system32\cmd.exe
	DriverData=C:\Windows\System32\Drivers\DriverData
	FPS_BROWSER_APP_PROFILE_STRING=Internet Explorer
	FPS_BROWSER_USER_PROFILE_STRING=Default
	HOMEDRIVE=C:
	HOMEPATH=\Users\Raviel
	LOCALAPPDATA=C:\Users\Raviel\AppData\Local
	LOGONSERVER=\\DESKTOP-Q1QOHS1
	NUMBER_OF_PROCESSORS=2
	OneDrive=C:\Users\Raviel\OneDrive
	OS=Windows_NT
	Path=C:\Program Files\Common Files\Oracle\Java\javapath;C:\Program Files (x86)\Common Files\Oracle\Java\javapath;C:\Windows\system32;C:\Windows;C:\Windows\System32\Wbem;C:\Windows\System32\WindowsPowerShell\v1.0\;C:\Windows\System32\OpenSSH\;C:\Users\Raviel\AppData\Local\Programs\Python\Python312;C:\Users\Raviel\AppData\Local\Programs\Python\Python312\Scripts;C:\Users\Raviel\AppData\Local\Programs\Python\Python311\Scripts\;C:\Users\Raviel\AppData\Local\Programs\Python\Python311\;C:\Users\Raviel\AppData\Local\Programs\Python\Python312\Scripts\;C:\Users\Raviel\AppData\Local\Programs\Python\Python312\;C:\Users\Raviel\AppData\Local\Microsoft\WindowsApps;
	PATHEXT=.COM;.EXE;.BAT;.CMD;.VBS;.VBE;.JS;.JSE;.WSF;.WSH;.MSC
	PROCESSOR_ARCHITECTURE=AMD64
	PROCESSOR_IDENTIFIER=Intel64 Family 6 Model 140 Stepping 1, GenuineIntel
	PROCESSOR_LEVEL=6
	PROCESSOR_REVISION=8c01
	ProgramData=C:\ProgramData
	ProgramFiles=C:\Program Files
	ProgramFiles(x86)=C:\Program Files (x86)
	ProgramW6432=C:\Program Files
	PSModulePath=C:\Program Files\WindowsPowerShell\Modules;C:\Windows\system32\WindowsPowerShell\v1.0\Modules
	PUBLIC=C:\Users\Public
	SESSIONNAME=Console
	SystemDrive=C:
	SystemRoot=C:\Windows
	TEMP=C:\Users\Raviel\AppData\Local\Temp
	TMP=C:\Users\Raviel\AppData\Local\Temp
	USERDOMAIN=DESKTOP-Q1QOHS1
	USERDOMAIN_ROAMINGPROFILE=DESKTOP-Q1QOHS1
	USERNAME=Raviel
	USERPROFILE=C:\Users\Raviel
	windir=C:\Windows	1168	C:\Users\Raviel\Desktop\194247b2d4724928446b4cdea53167be6cf0ebd60858ca0c2d4bdc6cdb5a4c54\metatrader.exe
```

![image](https://hackmd.io/_uploads/S1ytWt3okl.png)


Then send it to the Receiver sever, luckily the IP address of that domain got hard coded inside the malware.


![metatrader_getData](https://hackmd.io/_uploads/Bk7EBd2s1l.png)

![image](https://hackmd.io/_uploads/SkKyOOhsyl.png)

![metrader_ConnectIP](https://hackmd.io/_uploads/BJuZudhoyl.png)

### Family name

While searching around the PE, I actually found this string, this determine it's own Family

![image](https://hackmd.io/_uploads/H1D3uu2s1l.png)

**Poverty is the parent of crime.** This is the String that dedicated it's own family name -> **[PovertyStealer](https://www.broadcom.com/support/security-center/protection-bulletin/poverty-stealer)**

### Connection

So the main target right now is how does it send the data through the hard-coded IP&port **(185.244.212.106:2227)**

![image](https://hackmd.io/_uploads/rJMHcOnsJl.png)

So, at this part, I started Debugging a little bit to understand how the Malware run, after jumpping in the function where it start connecting to the server, I found something quite interesting

![Metatrader_connect](https://hackmd.io/_uploads/S1Duidnikx.png)

![start_Socket](https://hackmd.io/_uploads/ryPjs_hokl.png)

It used "Winsock 2.0" calling the "connect()" funtion to connect to the hard-coded IP and port, it will loop infinitely if it can't connect to the server, to continue from this part we need to setup a fake server to receive the data that the Stealer sent. So I have my Kali-Linux set-up as a fake endpoint receiver.

![image](https://hackmd.io/_uploads/B1LA0O2o1g.png)

![image](https://hackmd.io/_uploads/ByYq3_3iyg.png)

![image](https://hackmd.io/_uploads/Sy17pu3iJg.png)

Extracting the Pkzip from the received data, open it up we can get the following information

![image](https://hackmd.io/_uploads/Hkt1Auhskx.png)

### POC:
```
PovertyStealer
185[.]244[.]212[.]106
Sample:
194247b2d4724928446b4cdea53167be6cf0ebd60858ca0c2d4bdc6cdb5a4c54 (Metatrader.exe)
```
![image](https://hackmd.io/_uploads/BySlethikg.png)

--- 

Thank you for reading till this point, It's my honor that I have y'all as my readers, also thanks my friends those who have been sticking around every night when I livestream doing reverse & analyze, thanks Sol, Deit, Sinido and Table.

![image](https://hackmd.io/_uploads/HylnGt3jyx.png)
