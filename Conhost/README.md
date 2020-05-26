## Conhost

> The conhost.exe process sitting in the middle between CSRSS and cmd.exe allows Windows 7 to fix both of the problems in previous versions of Windows—not only do the scrollbars draw correctly, but you can actually drag and drop a file from Explorer straight into the command prompt
>
> -Rob Kock (Microsoft forum)



luckily for attackers, that there is new feature in conhost that make it lolbin.

In some versions of windows 10 version (I tested on 1809 "Red stone 5" and hexacorn which was the source of this info tested on 1909 "19H2" so I think that also versions in between will have the same feature)



```powershell
conhost.exe notepad.exe
```

this will make notepad show up, of course this will happen with any executable 

![output](https://raw.githubusercontent.com/karemfaisal/SMUC---Simplified-Mitre-Use-Cases/master/Conhost/Misc/RunConhost.gif)

### Detection

- sysmon

  - process create

    - look for every sysmon process create event (eventID=1) that conhost is parent image and check the image 

    - ![sysmon](https://raw.githubusercontent.com/karemfaisal/SMUC---Simplified-Mitre-Use-Cases/master/Conhost/Misc/sysmon.PNG)

    - ```xml
      <Sysmon schemaversion="4.00">
          <HashAlgorithms>md5,sha256,IMPHASH</HashAlgorithms>
          <EventFiltering>
            		<ProcessCreate default="include">
      				<ParentImage condition="contains">conhost.exe</ParentImage>
      			</ProcessCreate>	
          </EventFiltering>
      </Sysmon> 
      ```

*the above rules is just for demonstration, we should not include certain process in process create, we should include all and exclude just some annoying legitimate processes*

*the process of finding the evil will be through threat hunting by applying some query to certain hypothesis*



**Important Note:**

monitoring such event will not generate noisy events, in production, we have to **exclude** process creation events for conhost.exe but this exclusion will not effect generating events for other processes when conhost.exe is parent, I made a test on active machine running sysmon for a month with conhost.exe creation exclusion and all events I got when searching for "conhost.exe" were process creation for notepad that I made to test this technique

![NotNoisy](https://raw.githubusercontent.com/karemfaisal/SMUC---Simplified-Mitre-Use-Cases/master/Conhost/Misc/NotNoisy.jpg)





### Resources

1- [http://www.hexacorn.com/blog/2020/05/25/how-to-con-your-host/](hexacorn post about it)

