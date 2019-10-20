## Alternate Data Stream (ADS)

it's introduced with Windows NT 3.1, it's file attribute in NTFS which contains meta data about files

Any file has Data stream which contains the actual data of the file, any other Data stream is called **Alternate** so it's Alternate Data stream, the ADS size is not added to the file size and it's hidden, could only be viewed using some commands

```
dir /R  or dir /R [filename]
```

```powershell
Get-Item -Path [filepath] -Stream *
```
>Alternate streams are not listed in Windows Explorer, and their size is not included in the file’s size.
>When the file is copied or moved to another file system without ADS support the user is warned that alternate data streams cannot be preserved.
>
>-- Andrea fortuna

for any file there is fully qualified file name

`<filename>:<streamname>:<streamtype>`



one of the default ADS is Zone.Identifier which tells the URL which is used to download the file, it's supported since Win XP sp2
to get the URL of file use this command

```powershell
Get-Content -Path [filepath] -Stream Zone.Identifier
```

```powershell
notepad.exe file.txt:Zone.Identifier
```

![Zone Identifier](https://raw.githubusercontent.com/karemfaisal/SMUC---Simplified-Mitre-Use-Cases/master/ADS/Misc/ZoneIdentifier.jpg)

- Zone.Identifer is not set when copying file from USB driver or downloading it from torrent -- **I tested it**

- some old browsers just place zone id in the Zone.Identifier ADS
- Any Application can set ADS, many Applications do
- Sysinternal has tool called streams that check for ADS



to create ADS

```powershell
set-content -Path {path to the file} - Stream {name of the stream} -Value {Value}
```

```powershell
Remove-Item –Path {path to the file} –Stream {name of the stream}
```



## ADS in Malwares

ADS is used a lot in malwares because it's not listed in windows explorer 

to append ADS

```powershell
echo "empty file" > c:\ADS\file.txt
makecab c:\ADS\procexp.exe c:\ADS\procexp.cab
extrac32 C:\ADS\procexp.cab c:\ADS\file.txt:procexp.exe
wmic process call create '"c:\ADS\file.txt:procexp.exe"
```

in Windows vista you could start the exe in the ADS just using start command

in Win 10 All ADS tricks to execute executables are **batched**  



### ADS Monitoring

Using sysmon we can monitor Adding files to streams using FileCreateStreamHash





### Reference

[Link1]: https://www.varonis.com/blog/the-malware-hiding-in-your-windows-system32-folder-more-alternate-data-streams-and-rundll32/	"Tricks to run executables in ADS"



[Link2]: https://oddvar.moe/2018/04/11/putting-data-in-alternate-data-streams-and-how-to-execute-it-part-2/	"Tricks to run executables in ADS"



[Link3]: https://www.andreafortuna.org/2017/10/11/some-thoughts-about-ntfs-filesystem/	"Check ADs Part"



[Link4]: https://blog.malwarebytes.com/101/2015/07/introduction-to-alternate-data-streams/	"Explanation for ADS"



[Link5]: https://cyberforensicator.com/2018/06/26/where-did-it-come-from-forensic-analysis-of-zone-identifier/	"Zone Identifier"



[Link6]: https://gist.github.com/api0cradle/cdd2d0d0ec9abb686f0e89306e277b8f	"Command for creating and executing ADS"

