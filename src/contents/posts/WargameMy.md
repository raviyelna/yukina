---
title:  Wargame.MY CTF 2025
published: 2024-12-29
description:  Wargame.MY CTF 2025 with BlitzHack
tags: [CTFs, DFIR]
category: CTFs Write-up
draft: false
---

# Wargame.MY

![456666392_1947220782370035_7180211514117222458_n - Copy](https://hackmd.io/_uploads/SyJN7A6Hkx.png)

## I CANT MANIPULATE PEOPLE

![chall_1](https://hackmd.io/_uploads/ByfIlTTH1e.png)

This challenge just straight up gave us the flag since it's was too obvious from the beginning, tons of ICMP, just some basic ICMP exfiltration.

![image](https://hackmd.io/_uploads/r1ptgTprye.png)

**Flag: WGMY{4a4be40c96ac6341e91d93f38043a634}**

## Unwanted Meow

![chall_2](https://hackmd.io/_uploads/SyCybapHkl.png)

Okay this time the challenge gave us a file seem like corrupted, when opened in hexedit it, there some 'meow' in the hexadecimal just get rid of them then got the flag, I will use cyberchef instead since I'm lazy.

![image](https://hackmd.io/_uploads/rJzQbTaH1l.png)

![image](https://hackmd.io/_uploads/S1btZT6Byl.png)

## Tricky Malware

![chall_4](https://hackmd.io/_uploads/BJ2jZ66S1g.png)

For this challenge, they gave us a memory dump file along with a pcap but there nothing much in the pcap so I will start analyzing the dump first.

![image](https://hackmd.io/_uploads/ByJ8GT6HJg.png)

From there I saw something weird about the process named "crypt.exe", so I dump it out so investigate, you can get the PID with filescan but I'm lazy to do it again so do it by yourself.

![image](https://hackmd.io/_uploads/Skqx76TH1x.png)

There an error but it still give me the dump file dkw? but Okay. Using DiE I know it was written in python.

![image](https://hackmd.io/_uploads/HyTFXT6B1l.png)

So the next step is just use pyinstxtractor then using pylingal to rebuild the script.

![image](https://hackmd.io/_uploads/ByKCXTpSJl.png)

There a pastebin link, open it and got the flag.

**Flag: WGMY{8b9777c8d7da5b10b65165489302af32}**

## Oh Man

![chall_3](https://hackmd.io/_uploads/SkUWEpTHJx.png)

After going around the pcap file, I noticed 2 things, the thing got executed name "nano.exe" sound like **Nanocore RAT**, second this has tons of SMB3 so maybe I need to decrypt the SMB3 protocol.

![image](https://hackmd.io/_uploads/rk2_4pTrkl.png)

![image](https://hackmd.io/_uploads/SJDoNTaryx.png)

```cmd!
/Q /c C:\Windows\Temp\nanoexe --pid 840 --write C:\Windows\Temp\20241225_1939log 1> \\127001\C$\Windows\Temp\RxHmEj 2>&1C:\5pQd
```

First let find away to decrypt this SMB3, also I found something that look like this challenge while research on the internet

https://malwarelab.eu/posts/tryhackme-smb-decryption/#method-3-decrypting-smb-with-the-captured-traffic-only

```bash!
┌──(raviel㉿kali)-[~/Desktop/temp2]
└─$ tshark -n -r wgmy-ohman.pcapng -Y 'ntlmssp.messagetype == 0x00000003' -T fields -e ntlmssp.auth.username -e ntlmssp.auth.domain -e ntlmssp.ntlmv2_response.ntproofstr -e ntlmssp.auth.ntresponse > lmao.txt
                                                                                                                                                                                                                                           
┌──(raviel㉿kali)-[~/Desktop/temp2]
└─$ cat lmao.txt 
NULL    NULL            0000000041000000
Administrator   DESKTOP-PMNU0JK ae62a57caaa5dd94b68def8fb1c192f3        ae62a57caaa5dd94b68def8fb1c192f301010000000000008675779b2e57db01376f686e57504d770000000002001e004400450053004b0054004f0050002d0050004d004e00550030004a004b0001001e004400450053004b0054004f0050002d0050004d004e00550030004a004b0004001e004400450053004b0054004f0050002d0050004d004e00550030004a004b0003001e004400450053004b0054004f0050002d0050004d004e00550030004a004b00070008008675779b2e57db010900280063006900660073002f004400450053004b0054004f0050002d0050004d004e00550030004a004b000000000000000000
Administrator   DESKTOP-PMNU0JK d43050f791ffabb9000c94bc5261ec52        d43050f791ffabb9000c94bc5261ec520101000000000000fffb809b2e57db015569395a4c546b720000000002001e004400450053004b0054004f0050002d0050004d004e00550030004a004b0001001e004400450053004b0054004f0050002d0050004d004e00550030004a004b0004001e004400450053004b0054004f0050002d0050004d004e00550030004a004b0003001e004400450053004b0054004f0050002d0050004d004e00550030004a004b0007000800fffb809b2e57db010900280063006900660073002f004400450053004b0054004f0050002d0050004d004e00550030004a004b000000000000000000
Administrator   DESKTOP-PMNU0JK 4dd18b7e39dfe0538da53182e84a2f7c        4dd18b7e39dfe0538da53182e84a2f7c010100000000000035878a9b2e57db0179363032797135620000000002001e004400450053004b0054004f0050002d0050004d004e00550030004a004b0001001e004400450053004b0054004f0050002d0050004d004e00550030004a004b0004001e004400450053004b0054004f0050002d0050004d004e00550030004a004b0003001e004400450053004b0054004f0050002d0050004d004e00550030004a004b000700080035878a9b2e57db010900280063006900660073002f004400450053004b0054004f0050002d0050004d004e00550030004a004b000000000000000000
Administrator   DESKTOP-PMNU0JK f1de649eca87cd4430df45334ede036b        f1de649eca87cd4430df45334ede036b0101000000000000c312949b2e57db01514b36414d6e6b6f0000000002001e004400450053004b0054004f0050002d0050004d004e00550030004a004b0001001e004400450053004b0054004f0050002d0050004d004e00550030004a004b0004001e004400450053004b0054004f0050002d0050004d004e00550030004a004b0003001e004400450053004b0054004f0050002d0050004d004e00550030004a004b0007000800c312949b2e57db010900280063006900660073002f004400450053004b0054004f0050002d0050004d004e00550030004a004b000000000000000000
Administrator   DESKTOP-PMNU0JK 6035de8eeaaccc30c4d0cf61c2ff1857        6035de8eeaaccc30c4d0cf61c2ff18570101000000000000e3479b9b2e57db015630475a6e64616a0000000002001e004400450053004b0054004f0050002d0050004d004e00550030004a004b0001001e004400450053004b0054004f0050002d0050004d004e00550030004a004b0004001e004400450053004b0054004f0050002d0050004d004e00550030004a004b0003001e004400450053004b0054004f0050002d0050004d004e00550030004a004b0007000800e3479b9b2e57db010900280063006900660073002f004400450053004b0054004f0050002d0050004d004e00550030004a004b000000000000000000
Administrator   DESKTOP-PMNU0JK d3b84a34cd713b950bae5dd8a9fb1523        d3b84a34cd713b950bae5dd8a9fb15230101000000000000e68df29c2e57db01436a6e6a5a5763420000000002001e004400450053004b0054004f0050002d0050004d004e00550030004a004b0001001e004400450053004b0054004f0050002d0050004d004e00550030004a004b0004001e004400450053004b0054004f0050002d0050004d004e00550030004a004b0003001e004400450053004b0054004f0050002d0050004d004e00550030004a004b0007000800e68df29c2e57db010900280063006900660073002f004400450053004b0054004f0050002d0050004d004e00550030004a004b000000000000000000
Administrator   DESKTOP-PMNU0JK e840e74381ba416e3388006dce09a68d        e840e74381ba416e3388006dce09a68d0101000000000000cb78fe9c2e57db0134436f45673271510000000002001e004400450053004b0054004f0050002d0050004d004e00550030004a004b0001001e004400450053004b0054004f0050002d0050004d004e00550030004a004b0004001e004400450053004b0054004f0050002d0050004d004e00550030004a004b0003001e004400450053004b0054004f0050002d0050004d004e00550030004a004b0007000800cb78fe9c2e57db010900280063006900660073002f004400450053004b0054004f0050002d0050004d004e00550030004a004b000000000000000000
Administrator   DESKTOP-PMNU0JK 7e3b131e980a621eddb57dd19c7565ba        7e3b131e980a621eddb57dd19c7565ba0101000000000000c303089d2e57db0163597878514a54790000000002001e004400450053004b0054004f0050002d0050004d004e00550030004a004b0001001e004400450053004b0054004f0050002d0050004d004e00550030004a004b0004001e004400450053004b0054004f0050002d0050004d004e00550030004a004b0003001e004400450053004b0054004f0050002d0050004d004e00550030004a004b0007000800c303089d2e57db010900280063006900660073002f004400450053004b0054004f0050002d0050004d004e00550030004a004b000000000000000000
Administrator   DESKTOP-PMNU0JK e0e5937fef061d32f900e88d4d646b31        e0e5937fef061d32f900e88d4d646b310101000000000000bf390f9d2e57db0159584666475750510000000002001e004400450053004b0054004f0050002d0050004d004e00550030004a004b0001001e004400450053004b0054004f0050002d0050004d004e00550030004a004b0004001e004400450053004b0054004f0050002d0050004d004e00550030004a004b0003001e004400450053004b0054004f0050002d0050004d004e00550030004a004b0007000800bf390f9d2e57db010900280063006900660073002f004400450053004b0054004f0050002d0050004d004e00550030004a004b000000000000000000

┌──(raviel㉿kali)-[~/Desktop/temp2]
└─$ tshark -n -r wgmy-ohman.pcapng -Y 'ntlmssp.messagetype == 0x00000002' -T fields -e ntlmssp.ntlmserverchallenge  > lmao2.txt 

┌──(raviel㉿kali)-[~/Desktop/temp2]
└─$ cat lmao2.txt 
21bf7dbd40d05620
7aaff6ea26301fc3
a1adc9d0bfe2c7c1
e9cc7c3171bb95b9
ce1e228fd442539e
87c2136c9e0cfc7c
ad2f8a3f8191cfd6
e3badcd0e2b0bde3
fec80d9eb9c0249b
fd50cb1c5db59df1
```

![image](https://hackmd.io/_uploads/HkrzqT6r1x.png)

from here you can crack the password

```bash!

┌──(raviel㉿kali)-[~/Desktop/temp2]
└─$ john --format=netntlmv2 --wordlist=/home/raviel/Desktop/wordlist/rockyou.txt lmao.txt
Using default input encoding: UTF-8
Loaded 9 password hashes with 9 different salts (netntlmv2, NTLMv2 C/R [MD4 HMAC-MD5 32/64])
Will run 8 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
password<3       (Administrator)     
password<3       (Administrator)     
password<3       (Administrator)     
password<3       (Administrator)     
password<3       (Administrator)     
password<3       (Administrator)     
password<3       (Administrator)     
password<3       (Administrator)     
password<3       (Administrator)     
9g 0:00:00:00 DONE (2024-12-28 14:04) 450.0g/s 204800p/s 1843Kc/s 1843KC/s 123456..bigman
Use the "--show --format=netntlmv2" options to display all of the cracked passwords reliably
Session completed. 
                                                                                                                                                                                                                                            
┌──(raviel㉿kali)-[~/Desktop/temp2]
└─$ cat lmao.txt 
Administrator::DESKTOP-PMNU0JK:7aaff6ea26301fc3:ae62a57caaa5dd94b68def8fb1c192f3:01010000000000008675779b2e57db01376f686e57504d770000000002001e004400450053004b0054004f0050002d0050004d004e00550030004a004b0001001e004400450053004b0054004f0050002d0050004d004e00550030004a004b0004001e004400450053004b0054004f0050002d0050004d004e00550030004a004b0003001e004400450053004b0054004f0050002d0050004d004e00550030004a004b00070008008675779b2e57db010900280063006900660073002f004400450053004b0054004f0050002d0050004d004e00550030004a004b000000000000000000
Administrator::DESKTOP-PMNU0JK:a1adc9d0bfe2c7c1:d43050f791ffabb9000c94bc5261ec52:0101000000000000fffb809b2e57db015569395a4c546b720000000002001e004400450053004b0054004f0050002d0050004d004e00550030004a004b0001001e004400450053004b0054004f0050002d0050004d004e00550030004a004b0004001e004400450053004b0054004f0050002d0050004d004e00550030004a004b0003001e004400450053004b0054004f0050002d0050004d004e00550030004a004b0007000800fffb809b2e57db010900280063006900660073002f004400450053004b0054004f0050002d0050004d004e00550030004a004b000000000000000000
Administrator::DESKTOP-PMNU0JK:e9cc7c3171bb95b9:4dd18b7e39dfe0538da53182e84a2f7c:010100000000000035878a9b2e57db0179363032797135620000000002001e004400450053004b0054004f0050002d0050004d004e00550030004a004b0001001e004400450053004b0054004f0050002d0050004d004e00550030004a004b0004001e004400450053004b0054004f0050002d0050004d004e00550030004a004b0003001e004400450053004b0054004f0050002d0050004d004e00550030004a004b000700080035878a9b2e57db010900280063006900660073002f004400450053004b0054004f0050002d0050004d004e00550030004a004b000000000000000000
Administrator::DESKTOP-PMNU0JK:ce1e228fd442539e:f1de649eca87cd4430df45334ede036b:0101000000000000c312949b2e57db01514b36414d6e6b6f0000000002001e004400450053004b0054004f0050002d0050004d004e00550030004a004b0001001e004400450053004b0054004f0050002d0050004d004e00550030004a004b0004001e004400450053004b0054004f0050002d0050004d004e00550030004a004b0003001e004400450053004b0054004f0050002d0050004d004e00550030004a004b0007000800c312949b2e57db010900280063006900660073002f004400450053004b0054004f0050002d0050004d004e00550030004a004b000000000000000000
Administrator::DESKTOP-PMNU0JK:87c2136c9e0cfc7c:6035de8eeaaccc30c4d0cf61c2ff1857:0101000000000000e3479b9b2e57db015630475a6e64616a0000000002001e004400450053004b0054004f0050002d0050004d004e00550030004a004b0001001e004400450053004b0054004f0050002d0050004d004e00550030004a004b0004001e004400450053004b0054004f0050002d0050004d004e00550030004a004b0003001e004400450053004b0054004f0050002d0050004d004e00550030004a004b0007000800e3479b9b2e57db010900280063006900660073002f004400450053004b0054004f0050002d0050004d004e00550030004a004b000000000000000000
Administrator::DESKTOP-PMNU0JK:ad2f8a3f8191cfd6:d3b84a34cd713b950bae5dd8a9fb1523:0101000000000000e68df29c2e57db01436a6e6a5a5763420000000002001e004400450053004b0054004f0050002d0050004d004e00550030004a004b0001001e004400450053004b0054004f0050002d0050004d004e00550030004a004b0004001e004400450053004b0054004f0050002d0050004d004e00550030004a004b0003001e004400450053004b0054004f0050002d0050004d004e00550030004a004b0007000800e68df29c2e57db010900280063006900660073002f004400450053004b0054004f0050002d0050004d004e00550030004a004b000000000000000000
Administrator::DESKTOP-PMNU0JK:e3badcd0e2b0bde3:e840e74381ba416e3388006dce09a68d:0101000000000000cb78fe9c2e57db0134436f45673271510000000002001e004400450053004b0054004f0050002d0050004d004e00550030004a004b0001001e004400450053004b0054004f0050002d0050004d004e00550030004a004b0004001e004400450053004b0054004f0050002d0050004d004e00550030004a004b0003001e004400450053004b0054004f0050002d0050004d004e00550030004a004b0007000800cb78fe9c2e57db010900280063006900660073002f004400450053004b0054004f0050002d0050004d004e00550030004a004b000000000000000000
Administrator::DESKTOP-PMNU0JK:fec80d9eb9c0249b:7e3b131e980a621eddb57dd19c7565ba:0101000000000000c303089d2e57db0163597878514a54790000000002001e004400450053004b0054004f0050002d0050004d004e00550030004a004b0001001e004400450053004b0054004f0050002d0050004d004e00550030004a004b0004001e004400450053004b0054004f0050002d0050004d004e00550030004a004b0003001e004400450053004b0054004f0050002d0050004d004e00550030004a004b0007000800c303089d2e57db010900280063006900660073002f004400450053004b0054004f0050002d0050004d004e00550030004a004b000000000000000000
Administrator::DESKTOP-PMNU0JK:fd50cb1c5db59df1:e0e5937fef061d32f900e88d4d646b31:0101000000000000bf390f9d2e57db0159584666475750510000000002001e004400450053004b0054004f0050002d0050004d004e00550030004a004b0001001e004400450053004b0054004f0050002d0050004d004e00550030004a004b0004001e004400450053004b0054004f0050002d0050004d004e00550030004a004b0003001e004400450053004b0054004f0050002d0050004d004e00550030004a004b0007000800bf390f9d2e57db010900280063006900660073002f004400450053004b0054004f0050002d0050004d004e00550030004a004b000000000000000000
```

we got the password its **"password<3"**, time to decrypt SMB3, wireshark > edit > preferences > protocols > NTLMSSP

![image](https://hackmd.io/_uploads/BJ-F3TTSJx.png)

![image](https://hackmd.io/_uploads/HJwc3p6H1g.png)

Now we can take out the log and stuffs.

![image](https://hackmd.io/_uploads/SkGM6pprkl.png)

I saw it said something about restore signature so I opened it in hexadecimal and saw that the hex header was wrong, after fixing it, by using the pypykatz then we got the flag.

![image](https://hackmd.io/_uploads/SJ4URppBkx.png)

![image](https://hackmd.io/_uploads/rk6WyA6Bkx.png)


```bash!
┌──(raviel㉿kali)-[~/Desktop/temp2]
└─$ pypykatz lsa minidump troll.log                            
INFO:pypykatz:Parsing file troll.log
FILE: ======== troll.log =======
== LogonSession ==
authentication_id 2822152 (2b1008)
session_id 0
username Administrator
domainname DESKTOP-PMNU0JK
logon_server DESKTOP-PMNU0JK
logon_time 2024-12-26T00:39:25.269446+00:00
sid S-1-5-21-152657954-3457636215-2968948465-500
luid 2822152
        == Kerberos ==
                Username: Administrator
                Domain: DESKTOP-PMNU0JK

== LogonSession ==
authentication_id 2822120 (2b0fe8)
session_id 0
username Administrator
domainname DESKTOP-PMNU0JK
logon_server DESKTOP-PMNU0JK
logon_time 2024-12-26T00:39:25.222189+00:00
sid S-1-5-21-152657954-3457636215-2968948465-500
luid 2822120

== LogonSession ==
authentication_id 2822087 (2b0fc7)
session_id 0
username Administrator
domainname DESKTOP-PMNU0JK
logon_server DESKTOP-PMNU0JK
logon_time 2024-12-26T00:39:25.159649+00:00
sid S-1-5-21-152657954-3457636215-2968948465-500
luid 2822087

== LogonSession ==
authentication_id 2822046 (2b0f9e)
session_id 0
username Administrator
domainname DESKTOP-PMNU0JK
logon_server DESKTOP-PMNU0JK
logon_time 2024-12-26T00:39:25.081546+00:00
sid S-1-5-21-152657954-3457636215-2968948465-500
luid 2822046

== LogonSession ==
authentication_id 2808451 (2ada83)
session_id 0
username Administrator
domainname DESKTOP-PMNU0JK
logon_server DESKTOP-PMNU0JK
logon_time 2024-12-26T00:39:22.831869+00:00
sid S-1-5-21-152657954-3457636215-2968948465-500
luid 2808451
        == Kerberos ==
                Username: Administrator
                Domain: DESKTOP-PMNU0JK

== LogonSession ==
authentication_id 2808296 (2ad9e8)
session_id 0
username Administrator
domainname DESKTOP-PMNU0JK
logon_server DESKTOP-PMNU0JK
logon_time 2024-12-26T00:39:22.597108+00:00
sid S-1-5-21-152657954-3457636215-2968948465-500
luid 2808296

== LogonSession ==
authentication_id 1153600 (119a40)
session_id 0
username Administrator
domainname DESKTOP-PMNU0JK
logon_server DESKTOP-PMNU0JK
logon_time 2024-12-26T00:10:43.614433+00:00
sid S-1-5-21-152657954-3457636215-2968948465-500
luid 1153600
        == Kerberos ==
                Username: Administrator
                Domain: DESKTOP-PMNU0JK

== LogonSession ==
authentication_id 339242 (52d2a)
session_id 1
username Administrator
domainname DESKTOP-PMNU0JK
logon_server DESKTOP-PMNU0JK
logon_time 2024-12-26T00:08:48.302370+00:00
sid S-1-5-21-152657954-3457636215-2968948465-500
luid 339242
        == MSV ==
                Username: Administrator
                Domain: DESKTOP-PMNU0JK
                LM: NA
                NT: 2bbbf69f28445b3d64405f83e609a3b5
                SHA1: 7770d8429ec1f82cee34855e4ca95f499a06a8f3
                DPAPI: 7770d8429ec1f82cee34855e4ca95f49
        == WDIGEST [52d2a]==
                username Administrator
                domainname DESKTOP-PMNU0JK
                password None
                password (hex)
        == Kerberos ==
                Username: Administrator
                Domain: DESKTOP-PMNU0JK
        == WDIGEST [52d2a]==
                username Administrator
                domainname DESKTOP-PMNU0JK
                password None
                password (hex)
        == CREDMAN [52d2a]==
                luid 339242
                username wgmy
                domain wargames.my
                password wgmy{fbba48bee397414246f864fe4d2925e4}
                password (hex)770067006d0079007b00660062006200610034003800620065006500330039003700340031003400320034003600660038003600340066006500340064003200390032003500650034007d0000000000
        == DPAPI [52d2a]==
                luid 339242
                key_guid 3f2e1f8e-6e46-401f-9eaf-c04ae5fce736
                masterkey b44f25f6d196a92f77f22ecc14db19b574b3f266b44a48ed132b8268d3241a966b15d937cbfc6b6c364222743fd93b3f0ecb1c6c4ebe326727f981376c34c7f0
                sha1_masterkey adc7c99f9546f4374b9ee78d6a56fea568cea802

== LogonSession ==
authentication_id 997 (3e5)
session_id 0
username LOCAL SERVICE
domainname NT AUTHORITY
logon_server 
logon_time 2024-12-26T00:08:18.879757+00:00
sid S-1-5-19
luid 997
        == Kerberos ==
                Username: 
                Domain: 

== LogonSession ==
authentication_id 74393 (12299)
session_id 1
username DWM-1
domainname Window Manager
logon_server 
logon_time 2024-12-26T00:08:17.831149+00:00
sid S-1-5-90-0-1
luid 74393
        == WDIGEST [12299]==
                username DESKTOP-PMNU0JK$
                domainname WORKGROUP
                password None
                password (hex)
        == WDIGEST [12299]==
                username DESKTOP-PMNU0JK$
                domainname WORKGROUP
                password None
                password (hex)

== LogonSession ==
authentication_id 74347 (1226b)
session_id 1
username DWM-1
domainname Window Manager
logon_server 
logon_time 2024-12-26T00:08:17.831149+00:00
sid S-1-5-90-0-1
luid 74347
        == WDIGEST [1226b]==
                username DESKTOP-PMNU0JK$
                domainname WORKGROUP
                password None
                password (hex)
        == WDIGEST [1226b]==
                username DESKTOP-PMNU0JK$
                domainname WORKGROUP
                password None
                password (hex)

== LogonSession ==
authentication_id 996 (3e4)
session_id 0
username DESKTOP-PMNU0JK$
domainname WORKGROUP
logon_server 
logon_time 2024-12-26T00:08:17.347654+00:00
sid S-1-5-20
luid 996
        == WDIGEST [3e4]==
                username DESKTOP-PMNU0JK$
                domainname WORKGROUP
                password None
                password (hex)
        == Kerberos ==
                Username: desktop-pmnu0jk$
                Domain: WORKGROUP
        == WDIGEST [3e4]==
                username DESKTOP-PMNU0JK$
                domainname WORKGROUP
                password None
                password (hex)

== LogonSession ==
authentication_id 51300 (c864)
session_id 1
username UMFD-1
domainname Font Driver Host
logon_server 
logon_time 2024-12-26T00:08:16.801677+00:00
sid S-1-5-96-0-1
luid 51300
        == WDIGEST [c864]==
                username DESKTOP-PMNU0JK$
                domainname WORKGROUP
                password None
                password (hex)
        == WDIGEST [c864]==
                username DESKTOP-PMNU0JK$
                domainname WORKGROUP
                password None
                password (hex)

== LogonSession ==
authentication_id 51291 (c85b)
session_id 0
username UMFD-0
domainname Font Driver Host
logon_server 
logon_time 2024-12-26T00:08:16.801677+00:00
sid S-1-5-96-0-0
luid 51291
        == WDIGEST [c85b]==
                username DESKTOP-PMNU0JK$
                domainname WORKGROUP
                password None
                password (hex)
        == WDIGEST [c85b]==
                username DESKTOP-PMNU0JK$
                domainname WORKGROUP
                password None
                password (hex)

== LogonSession ==
authentication_id 50299 (c47b)
session_id 0
username 
domainname 
logon_server 
logon_time 2024-12-26T00:08:16.129161+00:00
sid None
luid 50299

== LogonSession ==
authentication_id 999 (3e7)
session_id 0
username DESKTOP-PMNU0JK$
domainname WORKGROUP
logon_server 
logon_time 2024-12-26T00:08:15.987512+00:00
sid S-1-5-18
luid 999
        == WDIGEST [3e7]==
                username DESKTOP-PMNU0JK$
                domainname WORKGROUP
                password None
                password (hex)
        == Kerberos ==
                Username: desktop-pmnu0jk$
                Domain: WORKGROUP
        == WDIGEST [3e7]==
                username DESKTOP-PMNU0JK$
                domainname WORKGROUP
                password None
                password (hex)
        == DPAPI [3e7]==
                luid 999
                key_guid 1ecf710d-4fa5-495f-ab24-535d23cbd6bd
                masterkey d6812ea081f4e6ae7f29d2af403b45e0a5b575ac62e0e6cd02f3007174ffc2c6057c2177f52322101fe5b39385be240c9e66458f485a3c23cb02a85c83e6cd04
                sha1_masterkey 73c4578d173e08687fa50fc1aca346ffca687810


```

**FLAG: wgmy{fbba48bee397414246f864fe4d2925e4}**

Okay one final word, I hate Stegs

![image](https://hackmd.io/_uploads/HyUA-CaHkg.png)

![image](https://hackmd.io/_uploads/rJxkM0TByl.png)

---

Fun fact: I join this CTFs when its about to end

![image](https://hackmd.io/_uploads/S1N4MCTBkx.png)

If they didn't tag me in =)) I would still be playing Nier Replicant while they were participating in the CTFs lmao

![image](https://hackmd.io/_uploads/Hk5dMCpBJe.png)


![image](https://hackmd.io/_uploads/HJNMMRaBkl.png)

Thank you for reading my Write-up, love y'all <3

![6123678659592](https://hackmd.io/_uploads/ryKTfCaSkg.gif)
