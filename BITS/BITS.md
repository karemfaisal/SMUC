## BITS

BITS is used for downloading and uploading in the background, one of its great features that it use only the ideal of the network bandwidth, what make it very stealthily

 

[BITS Documentation]: https://msdn.microsoft.com/en-us/ie/aa362813(v=vs.94)
[BITS Admin]: https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/bitsadmin-examples


### Attack

We can use BITS task to download a file and run it after downloading and it will be repeated after every restart so we can use BITS for execution and persistence

We can create BITS task using

- bitsadmin.exe
- BITS-Job in PowerShell
- Windows API call 



[BITS creation]: http://0xthem.blogspot.com/2014/03/t-emporal-persistence-with-and-schtasks.html	"Link 1"
[BITS creation]: https://mgreen27.github.io/posts/2018/02/18/Sharing_my_BITS.html	"Link 2"
[BITS creation]: https://github.com/3gstudent/bitsadminexec	"Link 3"



### Detect

- bitsadmin.exe

  - sysmon 
  	 		- process create for bitsadmin.exe with cmd or PowerShell as parent process
- process create for cmd or PowerShell with bitsadmin.exe in command line
  - Event viewer
       - Event in BITS-Client under Microsoft-Windows-Bits-Client/Operational
            - Will show the URL of the download, but will not show the destination nor the SetNotifyCmdLine command which will responsible for running the executable after downloading it
  - NIDS
       - Microsoft-Bits as User Agent
  - qmgr[0-9].dat
       - before win 10 we could parse it using bits_parser, but in win 10 it's ESE database and could be viewed using ESEDatabaseViewer from Nirsoft
- PowerShell start-BitsTransfer
  - sysmon
    - process create for powershell with start-BitsTransfer  in the command line
  - Event Viewer
    - Like Bitsadmin.exe
  - NIDS
    - Like Bitsadmin.exe
  - qmgr[0-9].dat
    - same as Bitsadmin.exe
- Windows API
  - Event Viewer
    - same as Bitsadmin.exe
  - NIDS
    - same as Bitsadmin.exe
  - qmgr[0-9].dat
    - same as Bitsadmin.exe





Mathew Green wrote PowerShell script to extract suspicious URLs from from BITS-Client Events

[Extract suspicious URLs ]: https://github.com/mgreen27/Invoke-BitsParser/blob/master/Invoke-BitsDetection.ps1	"PowerShell"









