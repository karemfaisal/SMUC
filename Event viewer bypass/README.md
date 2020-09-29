## Event Log service

> ​	Event viewer is the preinstalled application in windows to view windows logs, it depends on a event log service to function



### EventLog service

![PS_Query](.\Misc\PS_Query.PNG)

Service configuration:

- **STOPPABLE**, AcceptPause, AcceptStop
- Binary path : ```svchost.exe -k LocalServiceNetworkRestricted -p``` 
  - -k LocalServiceNetworkRestricted is the responsible for running eventlog service plus many other services
    - will post link in *resources* explaining How svchost is working
- ProcessId: 1732



## Anti-forensics

> ​	one of the primary anti forensics techniques is clearing logs, and disable logging, attacker can approach this  by many methods



**Clearing Logs**: I just need to say that only security and system logs that have event for event clear

1102 for security

104 for system

![1102](.\Misc\1102.PNG)



![104](.\Misc\104.PNG)



To Test:

1- run the following command to clear all events

```cmd
for /F "tokens=*" %1 in ('wevtutil.exe el') DO wevtutil.exe cl "%1"
```

2- check what logs have more than 0 log

```powershell
Get-WinEvent -ListLog *
```



![SecSysClearOnly](I:\GIT\SMUC\eventvwr\Misc\SecSysClearOnly.PNG)

----

***All methods require administration privileges***

### Method 1 (Terminate Event log process)

as we say the process responsible for logging is 

```svchost -k LocalServiceNetworkRestricted -p -s eventlog```

![LogProcess](.\Misc\LogProcess.PNG)

if we suspend this process, the event viewer will be paused, also you will not be able to open new CMD or PowerShell, but you can use the shell you already open.

event viewer will be paused but logs will appear just after resuming the process , the same if you kill the process then start the services again

so if attacker tried to stop logs like that, you just have to restart the service and every thing will be there



#### Detection

- Live analysis
  - Windows Event Log service is not running (service will be stopped automatically after killing the process )
  - ```Svchost -k LocalServiceNetworkRestricted -p -s event log``` is not running
- Sysmon
  - Sysmon exit process doesn't provide command line and monitoring for all svchost process exit will be noisy and not useful as we will not be able to distinguish between svchost processes 
- Killing the Process like this will pause the service of event log **but will not generate 6006 EID**

----



### Method 2 (Invoke-Phant0m)

> ​	This is PowerShell script that is used to kill thread of the svchost process that responsible for event logging
>
> this technique is good for stopping a lot of security controls not just event viewer



Download: [Invoke-Phat0m](https://github.com/hlldz/Invoke-Phant0m)

Test Environment: Win 10 1909, build 18363.1016

of course any AV will detect Invoke-Phant0m as malware, so as attacker you have to find your way to bypass detection

```powershell
. ./Invoke-Phant0m
```

```powershell
Invoke-Phant0m
```



![Phant0m](I:\GIT\SMUC\eventvwr\Misc\Phant0m.PNG)



as you see in the above image: Invoke phant0m find the PID for svchost responsible for event logging

 and killed its threads and this caused total of 20 events that we will rely on for detection



after killing the threads: **No log entries are logged**

![TestPhant0m](.\Misc\TestPhant0m.gif)



#### Detection

- PowerShell Logs (EID 4104 - Script Block log -- not enabled by default)

  - manual: it's very easy to recognize the code for Invoke-Phant0m if no obfuscation occurs 

    - but of course attacker can also clear PowerShell logs
  - if we have SIEM then it would 
  
  - Automatic: we will catch any of the strings of the code
  
    ```yaml
    title: Detect Invoke-Phant0m
    id: 1f44f2ab-20bc-7234-93cc-d8ffbc93eadf
    status: experimental
    description: Detects part of the code of Invoke-Phant0m
    date: 2020/09/16
    author: Karem Ali
    references:
        - https://github.com/hlldz/Invoke-Phant0m
        - https://github.com/karemfaisal/SMUC/tree/master/eventvwr
    tags:
        - attack.DefenseEvasion
        - attack.T1070.001
    logsource:
        product: windows
        service: powershell
        definition: 'It is recommended to use the new "Script Block Logging" of PowerShell v5 https://adsecurity.org/?p=2277. Monitor for EventID 4104'
    detection:
        selection:
            EventLog: powershell
            EventID: 4104
        keywords:
            Command:
            	- "*$ContextRecord.ContextFlags = 0x10003B*"
            	
        condition: selection and keywords 
    falsepositives:
        - Penetration tests
    level: high
    ```



- Live Analysis

  - Process svchost with command line ```-k LocalServiceNetworkRestricted -p -s eventlog``` would have no threads related to eventlog service

    

![TestPhant0m1](.\Misc\TestPhant0m1.gif)



***Important notice about Invoke-Phant0m that although it will prevent any log from being created but clear logs (1102,104) will be created***



![1102](I:\GIT\SMUC\eventvwr\Misc\1102.PNG)

----



### Method 3 (Mimikatz event::drop)

>Mimikatz is wide used tool for dumping credentials but it also have other usages like stopping the event logging in windows
>
>you can check more details about mimikatz and credential dumping from here [Mimikatz](https://github.com/karemfaisal/SMUC/tree/master/Mimikatz)



this technique patch the service so it stops logging windows clear event (1102 , 104)

Event Log service still logging all other logs
following GIF shows that 1102 is no more generated but logs in PowerShell still be generated, the same as security events ..etc

![TestMimi](.\Misc\TestMimi.gif)



#### Detection

First of all if SIEM exists, then clearing logs is not important, we always can find the logs in the SIEM

- Sysmon

  - Process Access

    - Mimikatz will access svchost

      - correlate PID of svchost with PIDs of process creation in SIEM if it's svchost of event log

      ![ProcessAccess](.\Misc\ProcessAccess.PNG)
	

	- Module Loading (Detect Mimikatz not necessary to be event::drop)
	
	
	    - bcryptprimitives.dll
	    - vaultsvc.dll
	    - all DLLs for SSPs like [schannel.dll, credssp.dll, gpapi.dll, wdigest.dll, tspkg.dll, samsrv.dll]
	    - *If the process loaded all the modules in sysmon then it's highly likely to be mimikatz, but if only one or two modules then it's could be regular process*
	
	  ```xml
	  <Sysmon schemaversion="4.00">
	  <HashAlgorithms>md5,sha256,IMPHASH</HashAlgorithms>
	    <EventFiltering>
	  		<ProcessAccess onmatch="include">
	  			<TargetImage condition="is">C:\Windows\System32\svchost.exe</TargetImage>
	  		</ProcessAccess>
	  		
	  		
	  		<ImageLoad onmatch="include"> 
	  			<ImageLoaded condition="contains">schannel.dll</ImageLoaded>
	              <ImageLoaded condition="contains">credssp.dll</ImageLoaded>
	              <ImageLoaded condition="contains">gpapi.dll</ImageLoaded>
	              <ImageLoaded condition="contains">wdigest.dll</ImageLoaded>
	              <ImageLoaded condition="contains">tspkg.dll</ImageLoaded>
	  			<ImageLoaded condition="contains">samsrv.dll</ImageLoaded>
	  		</ImageLoad>
	  		
	  		
	  	</EventFiltering>
	  </Sysmon>
	  ```
	
- Process Access: x1438 which is

  - **PROCESS_SUSPEND_RESUME** (0x800) | **PROCESS_SET_INFORMATION** (0x200) | **PROCESS_QUERY_INFORMATION** (0x400) | **PROCESS_VM_WRITE** (0x20) | **PROCESS_VM_READ** (0x10)  | **PROCESS_VM_OPERATION** (0x8)

    Which is sufficient access to do the patching

***Patching svchost in on run time on disk, so restarting the service or computer will remove the effect of mimikatz***



