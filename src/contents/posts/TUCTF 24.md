---
title:  TUCTF 24
published: 2025-01-27
description:  TUCTF '24 with BlitzHack
tags: [CTFs, DFIR]
category: CTFs Write-up
draft: false
---

# TUCTF 24

Happy Lunar new years, this will be a short write-up since the challenges isn't that hard 

---

### Mystery Presentation

![image](https://hackmd.io/_uploads/SJF0TFVuJe.png)

![image](https://hackmd.io/_uploads/S15Z0FEuJg.png)

![image](https://hackmd.io/_uploads/r16GCYVd1x.png)

The given file look like a PKzip instead of a PPTX so just rename the extention to zip then open it up there a secret_data inside, also this is a polygot file

![image](https://hackmd.io/_uploads/HyujRt4_ye.png)

![image](https://hackmd.io/_uploads/BkOu0tNdkg.png)

open the secret data there a flag inside: 
```
TUCTF{p01yg10+_fi1e5_hiddin9_in_p1@in_5i9h+}
```

### Packet Detective

![image](https://hackmd.io/_uploads/rJ-NJqEdkg.png)

Just open the pcap file and the last packet contains the flag

![image](https://hackmd.io/_uploads/r15uycNOye.png)

```
TUCTF{N3tw0rk_M4st3r}
```

### Security Rocks

![image](https://hackmd.io/_uploads/ryPhkqN_1x.png)

open the network capture file this is a 802.11 capture file

![image](https://hackmd.io/_uploads/SyWmg5Ndkx.png)

there are some encrypted connection, we have to use [aircrack](https://www.kali.org/tools/aircrack-ng/) to find the key then decrypt the traffic

```
┌──(raviel㉿kali)-[~/Desktop]
└─$ aircrack-ng -w /home/raviel/Desktop/wordlist/rockyou.txt dump-05.cap

```

![image](https://hackmd.io/_uploads/ryvLNqEO1e.png)


Go to Edit > preferences > protocol > IEEE 802.11 > Decryption key > key type (wpa-pwd)

![image](https://hackmd.io/_uploads/r1TLbcNuyl.png)

apply this then go back to the capture file you will see some TCP packets

![image](https://hackmd.io/_uploads/rJD4GcN_yx.png)

```
Heres my super secret flag, I made it extra secure ;)
1KZTi2ZV7tO6yNxslvQbjRGL54BsPVyskwv4QaR29UMKj
```
using cipher identifier we can know that this is encoded in base62

![image](https://hackmd.io/_uploads/r15Ym94dkx.png)

![image](https://hackmd.io/_uploads/S1TiQcEOJl.png)

```
TUCTF{w1f1_15_d3f1n173ly_53cure3}
```

### Bunker

![image](https://hackmd.io/_uploads/BkXOE5N_yg.png)

![image](https://hackmd.io/_uploads/HJi_PqNOkx.png)

![image](https://hackmd.io/_uploads/SyBZOqN_ke.png)

This look like a clean PE so let's do some recon first, if you wandering around the internet you will see this https://github.com/vdohney/keepass-password-dumper and this https://nvd.nist.gov/vuln/detail/CVE-2023-32784

from that we can dump out the password of the keePass, there are some missing word at the beginning but we can guess it

![image](https://hackmd.io/_uploads/HyKvsoE_yg.png)

```
password: gL0Ry_2_M4nk1Nd!_Y0RH4
```

Open the DB file with keepass then input the password

![image](https://hackmd.io/_uploads/r1wino4O1l.png)

![image](https://hackmd.io/_uploads/Sy-U6sNuyg.png)

There a bunker record in the bunker, open it up and check the history entry, there a password change, from there we got the flag
