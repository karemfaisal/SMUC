## PSEXEC

> PsExec is a light-weight telnet-replacement that lets you execute processes on other systems, complete with full interactivity for console applications, without having to manually install client software
>
> -- Sysinternal

Like all tools/methods that let the good people to some staff remotely, it's used by bad people to do some staff remotely.

PSExec is a tool that is used heavily in Lateral movement

### Attack



the following command is all what you need to get shell on the remote device

```bash
.\PsExec.exe \\DESKTOP-QTEKH69 -u <username> -p <password> powershell
```

![PSexec_powershell](https://raw.githubusercontent.com/karemfaisal/SMUC---Simplified-Mitre-Use-Cases/master/PSExec/Misc/PSexec_powershell.JPG)

![PSexec_cmd](https://raw.githubusercontent.com/karemfaisal/SMUC---Simplified-Mitre-Use-Cases/master/PSExec/Misc/PSexec_cmd.JPG)

*firewall in win 10 will stop you, even if your target in private network it will stop every thing actually, even ping*



### Detection

this simple and powerful attack is very noisy, there are alot of logs and traces it leaves behind

first lets' talk about the theory it uses to work





1- Authenticate to the target device

![Authenticate](https://raw.githubusercontent.com/karemfaisal/SMUC---Simplified-Mitre-Use-Cases/master/PSExec/Misc/Authenticate.JPG)

2- it will connect to the target device share ADMIN$ (c:\windows) to drop a file (PSEXESVC.exe)

3- it will connect to the target device share IPC$ (Hidden network share used for IPC/Named Pipes)

 	*IPC$ is not mapped to physical disk, Microsoft use it to store temporary file in Named Pipes, as Named 	 Pipes are file eventually*

![Connect_to_IPC_ADMIN](https://raw.githubusercontent.com/karemfaisal/SMUC---Simplified-Mitre-Use-Cases/master/PSExec/Misc/Connect_to_IPC_ADMIN.JPG)



4- Send PSEXECSVC.exe ![SendPSEXESVC](https://raw.githubusercontent.com/karemfaisal/SMUC---Simplified-Mitre-Use-Cases/master/PSExec/Misc/SendPSEXESVC.JPG)

5- start PSEXESVC service

- Encrypted Traffic

![CreateService](https://raw.githubusercontent.com/karemfaisal/SMUC---Simplified-Mitre-Use-Cases/master/PSExec/Misc/CreateService.JPG)

- Not encrypted Traffic
 ![CreateServiceNotEncrypted](https://raw.githubusercontent.com/karemfaisal/SMUC---Simplified-Mitre-Use-Cases/master/PSExec/Misc/CreateServiceNotEncrypted.JPG)

***Encrypted and not encrypted traffic for SVCCTL (Service creation) are two separate captures and I don't know why it's some time encrypted and some time not encrypted, but majority of time according to my test, it was plaintext connection (not encrypted)***



6- Create 3 other Named Pipes for communication

*I filtered on Named pipes creation to fit all of them in one pic,but there is many packets in between*

*There is forth Named pipe named PSEXESVC*

![Create_NamedPipes](https://raw.githubusercontent.com/karemfaisal/SMUC---Simplified-Mitre-Use-Cases/master/PSExec/Misc/Create_NamedPipes.JPG)







from the above we can conclude the following artifacts

1- Network Login

- 4624 event id with logon type 3

2- File Create to ADMIN$ (C:\Windows) with name ```PSEXESVC.exe```

- sysmon file create event

3-Service Create with Name ```PSEXESVC``` 

- event id 4967
- Registry key creation (Service name and info are stored in registry)

4- (4) Named Pipes

- PSEXESVC
- PSEXESVC-<Target Device Name>-<Number>-stdin (ex: PSEXESVC-DESKTOP-55OETQV-22384-stdin)
- PSEXESVC-<Target Device Name>-<Number>-stdout
- PSEXESVC-<Target Device Name>-<Number>-stderr

  





#### Detection Rules

- sysmon

  - File Creation

  - Registry Modification (Service creation)

  - Named Pipes (Creation and Connection)

   ```xml
    <Sysmon schemaversion="4.22">
    	<!--SYSMON META CONFIG-->
    	<HashAlgorithms>md5,sha256,IMPHASH</HashAlgorithms>
    	<EventFiltering>
    	
    		<RuleGroup name="" groupRelation="or">
    			<ProcessCreate onmatch="include">
    				<Image name="PSEXEC" condition="contains">PSEXESVC.exe</Image>
    			</ProcessCreate>
    		</RuleGroup>
    		
    		<RuleGroup name="" groupRelation="or">
    			<FileCreate onmatch="include">
    				<TargetFilename name="PSEXEC" condition="contains">C:\Windows\PSEXESVC.exe</TargetFilename>
    			</FileCreate>
    		</RuleGroup>
    		
    		<RuleGroup name="" groupRelation="or">
    			<PipeEvent onmatch="include">
    				<PipeName name="PSEXEC" condition="contains">PSEXESVC</PipeName>
    			</PipeEvent>
    		</RuleGroup>
    		
    		<RuleGroup name="" groupRelation="or">
    			<RegistryEvent onmatch="include">
    				<TargetObject name="PSEXEC" condition="contains">\SYSTEM\CurrentControlSet\Services\PSEXESVC</TargetObject> 
    			</RegistryEvent>
    		</RuleGroup>
    		
    	  <ProcessTerminate onmatch="include"></ProcessTerminate>
    
    
    		
    	</EventFiltering>
    	
    </Sysmon>
   ```

    

- suricata

  - ```bash
    alert smb any any -> $HOME_NET any (msg: "PSEXEC"; content: "|50 00 53 00 45 00 58 00 45 00 53 00 56 00 43 00 2e 00 65 00 78 00 65 00|" ; sid:22000005;rev:1;)
    ```


