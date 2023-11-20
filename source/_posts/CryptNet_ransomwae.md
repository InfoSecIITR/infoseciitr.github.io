---
layout: post
title: CryptNET Ransomware
readtime: true
date: 2023-06-11
subtitle: -- written by P0ch1ta
tags: [Malware,Ransomware,.NET Reversing, Malware Analysis]
---

# Overview

CryptNET is a .NET Ransomware which has leaks at the site `http[:]//blog6zw62uijolee7e6aqqnqaszs3ckr5iphzdzsazgrpvtqtjwqryid[.]onion/`. The detials of the malware are as below.

# Metadata

`Malware Sample` : <a href="https://www.unpac.me/results/fccb073a-009a-4048-b097-54b5ffff6639#/">here</a> <br>
`MD5` : 733a808bc1be9d56026fd39b6e587ce4<br>
`SHA1` : 323c2d8db7a1104a6631f420b3dfa98f693058a0<br>
`SHA256` : 2e37320ed43e99835caa1b851e963ebbf153f16cbe395f259bd2200d14c7b775<br>

# Initial Analysis

When we try to analyse the malware inside of `DnSpy` we get some obfuscated code like following:

<img src="https://raw.githubusercontent.com/manasghandat/InfoSecImages/main/CryptNET/1.png" alt="Obfuscated Code">

We can dump the strings of the malware to see if we can get any hints about the obfucation. We can find that the malware is obfuscated using <a href="https://www.eziriz.com/dotnet_reactor.htm">.NET Reactor</a>.

<img src="https://raw.githubusercontent.com/manasghandat/InfoSecImages/main/CryptNET/2.png" alt="Strings">

We can deobfuscate the code using tools like <a href = "https://github.com/SychicBoy/NETReactorSlayer" >NET Reactor Slayer</a>. Afterwards we get the proper disassembled view.

```c#
private static void Main(string[] args)
{
	bool flag;
	new Mutex(true, Environment.MachineName, ref flag);
	if (flag)
	{
		Class0.mwMessage_base64enc = Class0.smethod_15();
		Class0.mwMessage = Class0.string_4.Replace(Class2.smethod_14(0), Class2.smethod_14(12) + Class0.smethod_9(28) + Class2.smethod_14(20));
		Class0.smethod_0();
		Class0.smethod_12(Class0.string_6);
		if (Class0.smethod_8())
		{
			Class0.smethod_14();
			Class0.smethod_11();
		}
		Class0.smethod_13();
	}
}
```

Here the first two lines are just messages from the malware that it writes in the readme.

# Encryption

## Directory Ennumeration

`Class0.smethod_0()` is used for directory ennumeration and encryption. The malware first finds all the drives that are present of the system and then proceeds to encrpyt the drives one by one. It also checks that if we are present in the root directory and in case we are then it excludes the following directories.

```
windows.old
windows.old.old
amd
nvidia
program files
program files (x86)
windows
$recycle.bin
documents and settings
intel
perflogs
programdata
boot
games
msocach
```

<img src="https://raw.githubusercontent.com/manasghandat/InfoSecImages/main/CryptNET/3.png" alt="Directory Ennumeration">

It then proceeds to check if the extention of the file is present in `Class0.string_3` and in case it is then it proceeds to encrypt it. 

``` 
.myd .ndf .qry .sdb .sdf .tmd .tgz .lzo .txt .jar .dat .contact .settings .doc .docx .xls .xlsx .ppt .pptx .odt .jpg .mka .mhtml .oqy .png .csv .py .sql .indd .cs .mp3 .mp4 .dwg .zip .rar .mov .rtf .bmp .mkv .avi .apk .lnk .dib .dic .dif .mdb .php .asp .aspx .html .htm .xml .psd .pdf .xla .cub .dae .divx .iso .7zip .pdb .ico .pas .db .wmv .swf .cer .bak .backup .accdb .bay .p7c .exif .vss .raw .m4a .wma .ace .arj .bz2 .cab .gzip .lzh .tar .jpeg .xz .mpeg .torrent .mpg .core .flv .sie .sum .ibank .wallet .css .js .rb .crt .xlsm .xlsb .7z .cpp .java .jpe .ini .blob .wps .docm .wav .3gp .gif .log .gz .config .vb .m1v .sln .pst .obj .xlam .djvu .inc .cvs .dbf .tbi .wpd .dot .dotx .webm .m4v .amv .m4p .svg .ods .bk .vdi .vmdk .onepkg .accde .jsp .json .xltx .vsdx .uxdc .udl .3ds .3fr .3g2 .accda .accdc .accdw .adp .ai .ai3 .ai4 .ai5 .ai6 .ai7 .ai8 .arw .ascx .asm .asmx .avs .bin .cfm .dbx .dcm .dcr .pict .rgbe .dwt .f4v .exr .kwm .max .mda .mde .mdf .mdw .mht .mpv .msg .myi .nef .odc .geo .swift .odm .odp .oft .orf .pfx .p12 .pl .pls .safe .tab .vbs .xlk .xlm .xlt .xltm .svgz .slk .tar.gz .dmg .ps .psb .tif .rss .key .vob .epsp .dc3 .iff .opt .onetoc2 .nrw .pptm .potx .potm .pot .xlw .xps .xsd .xsf .xsl .kmz .accdr .stm .accdt .ppam .pps .ppsm .1cd .p7b .wdb .sqlite .sqlite3 .db-shm .db-wal .dacpac .zipx .lzma .z .tar.xz .pam .r3d .ova .1c .dt .c .vmx .xhtml .ckp .db3 .dbc .dbs .dbt .dbv .frm .mwb .mrg .txz .mrg .vbox .wmf .wim .xtp2 .xsn .xslt
```

The malware also does not encrypt the following files

```
iconcache.db
autorun.inf
thumbs.db
boot.ini
bootfont.bin
ntuser.ini
bootmgr
bootmgr.efi
bootmgfw.efi
desktop.ini
ntuser.dat
```

## File Encryption

If the length of the file is less than `524288` bytes then it encrypts the file using `Class0.smethod_4` which encrypts the entire file. The malware uses `AES CBC 256` algorithm to encrypt the files. The `IV` and `Key` is generated and it encrypted using a hardcoded `RSA` key. The `RSA Key` is as follows:

```
<RSAKeyValue><Modulus>8TO8tQQRyFqQ0VShtSpLkDqtDVsrxS8SfdOsqRAj8mWF7sVoGzyZMcv501DF6iZUdKYsFDlaSMnuckG9+MJmD2ldZwU/0H6Xztkta1BkJWSO2qHg2JAGDp9ZsFGP1wDR9oRb1w7wtBe7Db3wf7q848+qKPWiTP/2R/jlR4evW73M65Jdo9uOzQnbmvw+blsloXeszuYlW2nCcwQ7WarzAK29UmM9ZHS0/lqzU0KHNU+DvyfGwmMJgtb2HN6GFGXq9Z0n3dNBCQVzdUl2G/7fLAMoFbJeExn5USZdFHr2ygheTilo/shmfq7tcPCZM8C4zqBtb0Nbct0f/M48+H920Q==</Modulus><Exponent>AQAB</Exponent></RSAKeyValue>
```

<img src="https://raw.githubusercontent.com/manasghandat/InfoSecImages/main/CryptNET/4.png" alt="File encryption">

In case the file is larger than the limit then the function `Class0.smethod_4` encrypts it. It encrypts only the starting part of the file using the same encryption method as before. The file is moved and the extension of the files is changed as well.

<img src="https://raw.githubusercontent.com/manasghandat/InfoSecImages/main/CryptNET/5.png" alt="Large File encryption">

<img src="https://raw.githubusercontent.com/manasghandat/InfoSecImages/main/CryptNET/ex.png" alt="Encrypted Files">

# Background Image

The malware then proceeds to change the background image and replaces it with something as follows:

<img src="https://raw.githubusercontent.com/manasghandat/InfoSecImages/main/CryptNET/8.png" alt="Background Image">

This image is generated dyanmically inside of the malware and the generation is done inside the `Class0.smethod_12`. The image is then saved at the path `C:\Users\(Current_User_Name)\AppData\Local\Temp`

<img src="https://raw.githubusercontent.com/manasghandat/InfoSecImages/main/CryptNET/9.png" alt="Image Gen">

# Killing Services

Inside of `Class0.smethod_8` the malware checks if it has admin privileges or not. In case it has admin privileges then it proceeds to kill the following services

```
BackupExecAgentBrowser
veeam
VeeamDeploymentSvc
PDVFSService
BackupExecVSSProvider
BackupExecAgentAccelerator
vss
sql
svc$
AcrSch2Svc
AcronisAgent
Veeam.EndPoint.Service
CASAD2DWebSvc
CAARCUpdateSvc
YooIT
memtas
sophos
veeam
DefWatch
ccEvtMgr
SavRoam
RTVscan
QBFCService
Intuit.QuickBooks.FCS
YooBackup
BackupExecAgentBrowser
BackupExecRPCService
MSSQLSERVER
backup
GxVss
GxBlr
GxFWD
GxCVD
GxCIMgr
VeeamNFSSvc
BackupExecDiveciMediaService
SQLBrowser
SQLAgent$VEEAMSQL2008R2
SQLAgent$VEEAMSQL2012
VeeamDeploymentService
BackupExecJobEngine
Veeam.EndPoint.Tray
BackupExecManagementService
SQLAgent$SQL_2008
BackupExecRPCService
zhudongfangyu
sophos
stc_raw_agent
VSNAPVSS
QBCFMonitorService
VeeamTransportSvc
```

<img src="https://raw.githubusercontent.com/manasghandat/InfoSecImages/main/CryptNET/6.png" alt="Kill Services">

# Kill Process

The malware at last proceeds to kill other certain processess that might be running on the deivce inside of `Class0.smethod_13`. The processes it kills are as follows:

```
sqlwriter
sqbcoreservice
VirtualBoxVM
sqlagent
sqlbrowser
sqlservr
code
steam
zoolz
agntsvc
firefoxconfig
infopath
synctime
VBoxSVC
tbirdconfig
thebat
thebat64
isqlplussvc
mydesktopservice
mysqld
ocssd
onenote
mspub
mydesktopqos
CNTAoSMgr
Ntrtscan
vmplayer
oracle
outlook
powerpnt
wps
xfssvccon
ProcessHacker
dbeng50
dbsnmp
encsvc
excel
tmlisten
PccNTMon
mysqld-nt
mysqld-opt
ocautoupds
ocomm
msaccess
msftesql
thunderbird
visio
winword
wordpad
mbamtray
```

<img src="https://raw.githubusercontent.com/manasghandat/InfoSecImages/main/CryptNET/7.png" alt="Kill Process">
