## Quarantined Anti Virus Files

a lot will talk about that in Digital Forensics section but I wrote it here because I faced that in a different manner

it's not about going to the quarantined path and pull the files then take it for investigation, it is a very different story

Microsoft ATP indicate hundreds of alarms on many devices for a lot of files, it was like the entity is fully compromised, but when I took a sample from this files and I opened it, I found that it's not executable and actually it's garbage 

![EncryptedFile](C:\Users\Noname\Desktop\L2 Work\Use Cases\SMUC\Quarentied AV files\Misc\EncryptedFile.JPG)

this file will never execute by itself, so I believed that this encrypted file will be loaded by another process then this file will be decrypted in memory and run

but now how can I decrypt it !, I don't know any thing except the security team gives me those files and told me to investigate and there are hundreds of alarms like those files, while I looking to the file I notices many `0xFF`,  if It was encrypted using Advanced encryption algorithm, the output must be looks like it selected with uniform distribution, what I was looking at was not like that, so I said there are many 0xFF and it should be many 0x00 so why not XOR with 0xFF

I used File Insight Hex editor for that

![DecryptedFile](C:\Users\Noname\Desktop\L2 Work\Use Cases\SMUC\Quarentied AV files\Misc\DecryptedFile.JPG)

and here is ASCII characters, so now what is this file with VSBX magic header ? it is the magic header for quarantined files of trend micro and we can see the path of the file before being quarantined 
`F:\System Volume Information\DFSR\Private\{C214EE99-BB13-4EC8-AB33-E0DD355598D8}-{48063213-07E7-499F-A6F8-068B1D4B80C3}\Installing\12-3-RE Inventorizat-{2E938AF9-6026-4F6D-8255-228F0D1F7E83}-v1261374.msg`

from here I downloaded VSBX encoder from TrendMicro[Link](https://docs.trendmicro.com/all/ent/iwsva/v5.5/en-us/iwsva_5.5_olh/decrypt_encrypted_quarantine_files.htm)

```powershell
.\VSEncode.exe /d /i C:\Users\Noname\Downloads\Maicious_Files\Trend\Trend.txt
```

Trend.txt contains the path of the files I want to decrypt "the original files not the file I decrypted using XOR" "Read The ReadMe which will be downloaded with the tool"

*I run it once for every time, it can not decrypt all file with one run*

When I run it I got the file and I could read it

![Outlook](C:\Users\Noname\Desktop\L2 Work\Use Cases\SMUC\Quarentied AV files\Misc\Outlook.JPG)


There is another generic way to deal with quaeritated files from any Antivirus

Using dexRay tool from hexacorn [Link](http://www.hexacorn.com/blog/category/software-releases/dexray/)

it 's Perl script  run it 

```powershell
perl dexray.pl <filename or directory>
```

then you will find three files on the current directory

- VBSX decrypted file
- Actual file that has been quarantined
- file contains meta data about the quarantined file

 

if dexray.pl showed error while running, it maybe because you need some modules to be installed

**Install Perl Modules**

```powershell
perl -MCPAN -e shell    "this will open perl shell"
```

```powershell
install Crypt::RC4 Digest::CRC Digest::MD5 Crypt::Blowfish Archive::Zip MIME::Base64 Compress::Raw::Zlib OLE::Storage_Lite
```

```powershell
exit 					"to exit perl shell" 
```









