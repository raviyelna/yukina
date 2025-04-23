---
title:  1337 UP LIVE CTF & P3rf3ctr00t CTF 2024
published: 2024-11-17
description:  1337 UP LIVE CTF & P3rf3ctr00t CTF 2024 with BlitzHack
tags: [CTFs, DFIR]
category: CTFs Write-up
draft: false
---


# 1337 UP LIVE CTF & P3rf3ctr00t CTF

## 1337 UP LIVE CTF
### CTF MIND TRICK

![image](https://hackmd.io/_uploads/By1CrDwfke.png)

The challenge gave us a Pcap file, after checking the potocol, I saw there a SMB protocol

![image](https://hackmd.io/_uploads/rJQQPPPzJl.png)

Immediately filter the smb and checking it packet data and I found that it was sending a wav file, you can take it out easily in Wireshark so I won't say much about this phase.

![image](https://hackmd.io/_uploads/HJItDvwzye.png)

it a AI generated song I guessed but I heard there some noise in the song ||(I don't think this is the reason but maybe thanks to my equipment Moondrop ARIA 2 & Moondrop Dawn Pro or perhaps it's just my instinct)||
So I open it in Sonic Visualiser then open spectogram layer and got the Flag

![image](https://hackmd.io/_uploads/rkA1uPvzJx.png)

Flag: INTIGRITI{hidden_in_music_1337}

---

### Logging

![image](https://hackmd.io/_uploads/H1htOwDfyg.png)

note: in my perspective, this was a very fun chall I got first blood on this (')> hehe

![image](https://hackmd.io/_uploads/BkgCYPDMyx.png)

So the challenge gave us a log file of a website that got SQL injection attack

![image](https://hackmd.io/_uploads/H1ZM5PvMJg.png)

I immediately thought of the idea that the flag is in some table Database but there so many tables so I check for the Flag format like "{" is CHAR(123)

![image](https://hackmd.io/_uploads/Hykh9vDG1e.png)

So I wrote a script just to filter when ever there "%3DCHAR\((\d+)\)" take out that number and convert to ascii

```py!
import re

def char_to_ascii(line):
    pattern = r"%3DCHAR\((\d+)\)"
    matches = re.findall(pattern, line)
    converted = []

    for match in matches:
        try:
            ascii_char = chr(int(match))
            converted.append(ascii_char)
        except ValueError:
            pass  

    return converted

log_file = "app.log"

try:
    with open(log_file, "r") as file:
        for line in file:
            converted_values = char_to_ascii(line)
            if converted_values:
                for value in converted_values:
                    print(f"{value}",end='')
except FileNotFoundError:
    print(f"Error: {log_file} not found.")
except Exception as e:
    print(f"An error occurred: {e}")
```

![image](https://hackmd.io/_uploads/BJM_oDvfJe.png)

FLAG: INTIGRITI{5q1_log_analys1s_f0r_7h3_w1n!}

---

### Hoarded Flag

![image](https://hackmd.io/_uploads/HJbRoPvG1x.png)

The challenge gave us a memory dump file and say something about the flag got a password on it maybe it a zip file? so I just filescan then grep the "flag" and found 2 zip file I dump both of them out

![image](https://hackmd.io/_uploads/Hkhy6wwzkl.png)

The 7z doesn't have anything in it so I will toss it aside and focus on the password of the flag.zip, at first I thought it was a common password so I used wordlist rockyou to crack it but nah, its not in the rockyou.txt, so I see its a **7z** then next to it a **zip** but the 7z is empty so maybe it used 7z -p <pass/> -mhe flag.7z flag.zip, so I grep the flag.7z since it a cmd so it will be readable

![image](https://hackmd.io/_uploads/SyO4CDvz1g.png)

![image](https://hackmd.io/_uploads/rJB81uvfke.png)

Flag: INTIGRITI{7h3_m3m0ry_h0ld5_7h3_53cr375}

---

### Password Management

![image](https://hackmd.io/_uploads/HygBg_vfJx.png)

The challenge gave us a ad disk file and my god its a 5gb file

![image](https://hackmd.io/_uploads/H14oedDz1g.png)

It also said something about **deleted** so I used Autopsy to solve this, after booting it up I immediately check in the recycle bin and found this

![image](https://hackmd.io/_uploads/BkKXbuvz1l.png)

this maybe a password to something, after going around I also found this

![image](https://hackmd.io/_uploads/HynIb_wzJg.png)

![image](https://hackmd.io/_uploads/HycD-dDGke.png)

![image](https://hackmd.io/_uploads/BJWObdwfkg.png)

So the flag is in his account or its the password(the challenge name said about password) I keep wandering around and found this

![image](https://hackmd.io/_uploads/rkWsbuPMyx.png)

So he using Firefox as the browser at this moment I was devastated so... instead of keep going I just toss it away and go play AfterImage =))))) sorry team

After that my teammate found the solution to this

![image](https://hackmd.io/_uploads/HkSGz_vfye.png)

Shoutout to Omar! So he found a [tool](https://github.com/raviyelna/firefox_decrypt) that can decrypt the [Firefox password encryption](https://github.com/raviyelna/firefox_decrypt)

So I dump his Firefox profile out and used that tool and also the password for the profile is in the image that I found above

![image](https://hackmd.io/_uploads/rJShMOPGkl.png)

![image](https://hackmd.io/_uploads/rk4pM_wz1e.png)

Flag: INTIGRITI{4n_unf0r7un473_53r135_0f_m1574k35}

---

## P3rf3ctr00t CTF
### Streams and Secrets Series (1-5)

![image](https://hackmd.io/_uploads/B15KQuvzkx.png)

The challenge gave us a $MFT file, this is very simple, you can use any MFT parser there are on the internet but I would alway use [EricZimmerman tool](https://github.com/EricZimmerman/MFTECmd), using the tool will output a CSV file so let open it up

Also the Challenge said something about a secret.txt so I just find it and it also came with the username of the User

![image](https://hackmd.io/_uploads/H1S7dOPGyg.png)

Flag 1: r00t{Analyst}

![image](https://hackmd.io/_uploads/BJ8LuuDfyl.png)

Now it asked for last modified date, you can also use that csv file to

![image](https://hackmd.io/_uploads/rkVJF_DGJg.png)

![image](https://hackmd.io/_uploads/r14n9_wMyx.png)

Flag 2: r00t{2024-10-07_21:52:47}

![image](https://hackmd.io/_uploads/BkDJiuvGkg.png)

for this challenge I used [MFTexplorer](https://ericzimmerman.github.io/#!index.md) to see the detail of the file

![image](https://hackmd.io/_uploads/H13eHcwzyl.png)

![image](https://hackmd.io/_uploads/HJ4zBqwz1g.png)

the logical size was 0x22 so it is 34

Flag 3: r00t{34}

![image](https://hackmd.io/_uploads/HkvSDQ_G1l.png)
![image](https://hackmd.io/_uploads/HyBUw7_fyl.png)


![image](https://hackmd.io/_uploads/rymqtQuf1e.png)

as for Flag 4 and 5 we can do this in the same time cause we already have the data in the image above

```py!
key: 'MVJhfcwOV33RxMzyF1H6J9X5IVbyfzHbVHMqXP6HN7Q='
Flag: 'gAAAAABnBFRI3Z3tfxy7hD4tfW_8Lkd4hwFOXxGkguaty3Z2zTzehVjBZhs9Q57y8g--0rTvkaZw44o-Nc0NxLFHqEYPiLab0FYXf7Y-34Rz27tKq_IFClITfXafCFR5BQb07PawxhP-'
```

So how do we decrypt this?, let check back what the first Stream and secrets said

![image](https://hackmd.io/_uploads/H1wjdmOMyg.png)

```py!
from cryptography.fernet import Fernet
import os
import sys

key = Fernet.generate_key()
cipher = Fernet(key)


def encrypt_file(file_path):
    with open(file_path, 'rb') as file:
        data = file.read()
    encrypted_data = cipher.encrypt(data)
    with open(file_path, 'wb') as file:
        file.write(encrypted_data)
    return key


try:
    targetfile = sys.argv[1].strip()
    encryption_key = encrypt_file(targetfile)  
    print("Your file has been encrypted Losers! This should teach you a lesson")  
except IndexError as e:
    print(e)
```
We can clearly see here that its used Fernet encryption with key, we got the flag and also got the key just write a simple decryption, I will use cyberchef instead since I'm lazy

![image](https://hackmd.io/_uploads/HJRfYQdz1g.png)

Flag 4: r00t{MVJhfcwOV33RxMzyF1H6J9X5IVbyfzHbVHMqXP6HN7Q=}

Flag 5: r00t{M4st3r_F1l3_t4bl3_1n_ntfs}

---

### Message

![image](https://hackmd.io/_uploads/S1eNj_wzJe.png)

The challenge gave us a corrupted file open it in Hexedit, we can see some hint of the original file, by looking at those byte I guessed it a WAV file

![image](https://hackmd.io/_uploads/rkhWh_wfyx.png)

![WAV](https://hackmd.io/_uploads/BkVX3OwGkx.png)

Just change it back like the structure above and you got a morse code audio file, convert it to ascii then you will notice it was Ceaser cipher encoded, this is it finally, sorry Im too lazy to write the flag again.

![image](https://hackmd.io/_uploads/r1ItTOvG1l.png)

---

### Ten*2

![image](https://hackmd.io/_uploads/BJLr0uPMyl.png)

The challenge gave us a ad01 file, if you have ever heard of this file or used to it then you know you can use FTK to open it, but the problem is...
it got a password

![image](https://hackmd.io/_uploads/HksC0dDGyg.png)

**I swear to God that I have no fucking idea what the password was**, until my teammate found the password it was **tenten** like ten*2 = tenten? shouldn't it ten^2? shoutout to 0x1337 (h4cky0u)

![image](https://hackmd.io/_uploads/S1EOJYvGyg.png)

open it up there a file name ten with tons of data

```!
8bo1tJZ2UNQpYvtU9uWkCJtzZ8B3Wh3YEF5tJCcSSrVn9SC1Y5hNTWv5dgdJRZsko4YGYyvfq4Ee5P5ga4To9osKxWAwqYVKqMxJBiurfXriT1qYLJymqrMwj67gQVioJ3NnZVWo5X638xAU8h2Kj2n4HyrM1GefeHyEXN6ETHw2JA46WKCKW5Jc2HQLqJEJhZRyN3je2KQJ1YonKzvXhHyicZoB2Xc553WagiWCgxumYdJ1ujQYzPZUfTABJTBmApkMM5GrsCyLzCsxdft5w8r4XVdjnpdTCSAG57MQZTHbW7toQsdKepWJMSWQpWxpsh9dWif2C7ZtXmQ6Sx22Sdnps8Qn3zJ4W3Ghrs8QgHkApnrhfmQwgRD6uhcdRpgPbYJatix1u2FeM7FrS4UpVewMsUsRCdPss6X6ivUe1LXUuuui4AafhrZG2ykBftunVW6mZafsjDjfcDaVjEam7PajdGBiVWfnbw1an6RRjsiXYXjsKHgLfkYRF11pnFVB35guMd3rjsYFmbV3sUAuPZXpLSQX3P56ypTDpa39oFARdJDTxh9gFk9XrvcCFjkgFZMQfN3eJhiDor2Tr9M81nrJeQ4yqtXHCGjPYokLfqE3QjiPFTnhE3BiHDFDkFRkmnnDbL8jZUim2SN2hQgS7ruKjr91jPuJ7RjPjWiTY2xVHgj1Z6qYk8MTfruLdy2aYRrE7EZTz7A7NFXsbfryJjmeZpv3BKKtkBr6Bd8vk4rVyTGMCgvHaJo24cRvRnMSNADYHQXZLFbH9FHtK7bWBW58BZUFwDQUTooNSeUL76oH824w2N8cdtecdQiccTodTUkEbm7dFRAYZJmAhagXqadXH2XF8c9b9PnxUAxVEA2L4g2jfpcvoXQuXZapE67SW3UPPWP8WpUxEn2VGA9VSqvLXovYh5Wf7v91yZPNQ23QSp31hiJ1qYc9Kf9NCRZqaRvgTCbHYmc9Fw3oruovQP6yGbaYvCnTpj36y67obmRXSyoj
```
using [dcode](https://www.dcode.fr/cipher-identifier) to identify the encryption type, it was base58

![image](https://hackmd.io/_uploads/rJ2zlKDf1g.png)

![image](https://hackmd.io/_uploads/SJC4eYwMJl.png)

```xml!
<?xml version="1.0" encoding="utf-8" standalone="no"?>
<!DOCTYPE users SYSTEM>
<users max="82">
   <user>
       <loginname>p3rf3ctr00tctf</loginname>
       <password>$6$8FLxcJkWoi9kU6Zw$k4a5ExeU0OAeiSOOzBU9HLf.qChCKPbvvTw07pnzL8tJR8tjNfzlqG7fHUQ91qG5IVs3Nr4rEGlU7LkQcsvah.</password>
       <4cr_encrypt>50 e7 02 4c da 24 1d 0c 44 87 d5 1b 43 fa 47 2c fe 2e 28 fc 68 75 87 04 02 b6 0f e4 7e 74 f3 2c 27 cd 93 06 0f 9e f5 5c e5 03 0b 2d 0d 34 3e 6c 2a b0 58 a1 51 88 77 68 45 3a 7c c8 dd 2c 43 f9 f0 e0 68 60 97 4a b1 16 5e 6a 6c c1 bf d3 1a 00 bf 54 c4 85 d5 d1 a0 3a df 1c 1d 89 5b fe f0 3c 43 55 b5 99 8e 79 7b 39 ec ab 7b 74 91 9b 3e 20 d2 00 1e 74 71 d0 </4cr_encrypt>
   </user>
</users>
<!-- p3rf3ctr00t CTF 2024 -->
```
So we got the password encrypted with SHA512 with the salt is 8FLxcJkWoi9kU6Zw also with a rc4 encrypted data, but first I will use john to de-hash the password, the password is **naruto** we need this for later

![image](https://hackmd.io/_uploads/SJ3k-tPzyl.png)

Next lets decrypt rc4 with the password we found, I will be using cyberchef

![image](https://hackmd.io/_uploads/H17dWFPGyl.png)

Flag: r00t{V1c70ry_1s_34rn3d}

---
**Thanks for reading anyway I will continue clearing AfterImage**

![image](https://media.discordapp.net/attachments/1234789877258649671/1307724237154418869/image.png?ex=673b589a&is=673a071a&hm=34fd49ddae94b2ec936f183b7950f1e7ca253880ba506e86cd5d35b5c0427d74&=&format=webp&quality=lossless&width=848&height=476)
