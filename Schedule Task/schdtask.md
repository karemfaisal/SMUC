## Schedule Task

in Windows OS there is an option to create tasks that run on specific time and run any program you want

**Create Schedule Task**

```powershell
$InterfaceNummber = 7
$Path = $env:APPDATA + "\Output.pcap"
$Action = New-ScheduledTaskAction -Execute 'C:\Program Files\Wireshark\tshark.exe' -Argument " -i $InterfaceNummber -w $Path -a duration:10"
$Trigger = New-ScheduledTaskTrigger -Once -At "8/26/2019 4:00:00 AM"
$setting = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
Register-ScheduledTask -Action $Action -Trigger $Trigger -TaskName "Tshark Network Traffic" -Description "Run Tshark" -Settings $setting
```

the above PowerShell code is responsible for creating schedule tasks, of course we can create schedule tasks using GUI (RUN -> taskschd.msc) but if we are talking about malicious activity then it would be creating using command line


the following code to list schedule tasks in path \

```powershell
$Tasks = Get-ScheduledTask -TaskPath \ | select TaskName,Actions,Triggers
foreach($task in $Tasks){
$task.TaskName | Out-String 
$task.Actions | Out-String  
$task.Triggers | Out-String 
}


```


Create schedule task on remote machine

```powershell
SCHTASKS /Create /S [Remote Machine Hostname] /U domain\user /P password /SC Daily /Evil /TR c:\evil.exe /ST 18:30 
```

Schedule tasks are created in XML file in C:\Windows\System32\Tasks and C:\Windows\Tasks for compatibility issue
so we can create Tasks by Creating XML files in the above path

the following  XML is the XML created by the first PowerShell code

```xml
<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.3" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <Description>Run Tshark to Capture Network Traffic for RDP analysis</Description>
    <URI>\Tshark Network Traffic</URI>
  </RegistrationInfo>
  <Principals>
    <Principal id="Author">
      <UserId>S-1-5-21-837408008-3244565575-2305096649-1001</UserId>
      <LogonType>InteractiveToken</LogonType>
    </Principal>
  </Principals>
  <Settings>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <Enabled>false</Enabled>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <IdleSettings>
      <Duration>PT10M</Duration>
      <WaitTimeout>PT1H</WaitTimeout>
      <StopOnIdleEnd>true</StopOnIdleEnd>
      <RestartOnIdle>false</RestartOnIdle>
    </IdleSettings>
    <UseUnifiedSchedulingEngine>true</UseUnifiedSchedulingEngine>
  </Settings>
  <Triggers>
    <TimeTrigger>
      <StartBoundary>2019-08-23T19:53:35+02:00</StartBoundary>
    </TimeTrigger>
  </Triggers>
  <Actions Context="Author">
    <Exec>
      <Command>C:\Program Files\Wireshark\tshark.exe</Command>
      <Arguments>-i 7 -w C:\Users\Noname\AppData\Roaming\Output.pcap -a duration:10</Arguments>
    </Exec>
  </Actions>
</Task>
```



### Detection

- sysmon
  - File Create
    - file create in C:\Windows\System32\Tasks
  - Process Create
    - cmd with schtasks.exe in command line
    - process for schtasks.exe
    - PowerShell with some of schedule tasks cmdlets



![Mermaid](https://raw.githubusercontent.com/karemfaisal/SMUC---Simplified-Mitre-Use-Cases/master/Schedule Task/Misc/Mermaid.svg)

### Reference

[Link1]: https://www.robvanderwoude.com/schtasks.php	"schdtask Commands"

