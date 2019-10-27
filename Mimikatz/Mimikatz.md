## Mimikatz

> 	 It's well known to [extract plaintexts passwords, hash, PIN code and kerberos tickets](https://github.com/gentilkiwi/mimikatz/wiki/module-~-sekurlsa) from memory.
>
> `mimikatz` can also perform [pass-the-hash](https://github.com/gentilkiwi/mimikatz/wiki/module-~-sekurlsa#pth), [pass-the-ticket](https://github.com/gentilkiwi/mimikatz/wiki/module-~-kerberos#ptt), build [Golden tickets](https://github.com/gentilkiwi/mimikatz/wiki/module-~-kerberos#golden), play with certificates or private keys, vault, ... *maybe make coffee?* 
>
> 
>
> -- Benjamin DELPY "Mimikatz Author" 


To understand how mimikatz works we need to understand the following 

- Authentication systems in windows
  - SSPI and SSPs
- LSASS

### Authentication systems in windows

#### SSPI

SSPI " security  support provider interface" is WIN32 API that handle many security related task such as authentication.

it's the first thing that authentication request accesses, because it is responsible to handle the authentication protocol that the other device trying to authenticate with it.

#### SSPs

>  A Security Support Provider is a dynamic linking library (DLL) that makes one or more security packages available to applications. 
>
> -- Wikipedia

Microsoft provides many SSPs that SSPI handle them [Link](https://docs.microsoft.com/en-us/windows/win32/secauthn/ssp-packages-provided-by-microsoft?redirectedfrom=MSDN)

- NTLM \**Challenge response authentication system has two version v1 and v2*\* 
- Kerberos \**Semi ZKPP Authentication system that depending on Tickets, only in Domain Environment*\*
- WDigest \**Challenge Response authentication system that works on http*\*
- CredSSP \**Enable TLS over the channel so credentials is transmitted in secure way*\*
- Secure Channel
- Negotiate \**Negotiation between Devices, it chooses Kerberos if two system accept it otherwise NTLM*\*

Next Paragraph demonstrate the steps for authentication in Windows

![Mermaid](https://raw.githubusercontent.com/karemfaisal/SMUC---Simplified-Mitre-Use-Cases/master/Mimikatz/Misc/Mermaid.jpg)

Device 2 try to authenticate on Device 1, so SSPI check the protocol that Device2 offers to authenticate with.

then it picks the SSP that matches the Device 2 request and establish the channel for authentication.

*the above is happing for local authentication also*

so on every Device there are SSPI and many SSPs and some SSPs



### LSASS

> **Local Security Authority Subsystem Service** (**LSASS**) is a process in Microsoft Windows operating systems that is responsible for enforcing the security policy on the system. It verifies users logging on to a Windows computer or server, handles password changes, and creates access tokens. It also writes to the Windows Security Log.
>
> 
>
> -- Wikipedia



LSASS process handle the authentication and any process runs in the memory, so the credentials are stored in memory for all SSPs mentioned above and more



Mimikatz tries to access this process to dump credentials from memory, more over some SSPs needs password in plain text so LSASS contains some plain text password *that is changed a little in newer versions of windows*



the following photo  shows what SSPs have it's credentials in the memory

>  Benjamin DELPY posted an Excel chart on OneDrive (no longer available, but shown below) that shows what type of credential data is available in memory (LSASS), including on Windows 8.1 and Windows 2012 R2 which have enhanced protection mechanisms reducing the amount and type of credentials kept in memory. 
>
> 
>
> -- adsecurity.org

![Delpy-CredentialDataChart](https://raw.githubusercontent.com/karemfaisal/SMUC---Simplified-Mitre-Use-Cases/master/Mimikatz/Misc/Delpy-CredentialDataChart.png)

SSPs with **Plain text password** in Memory

- WDigest
- Credential Manager  *Not SSP actually*



**WDigest**

WDigest needs plain text password and no fix for that, if you don't want plain text password then you have to Disable WDigest using registry, and of course what you can disable, attacker can enable

**Disable WDigest so no clear text in memory**

```powershell
New-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest -PropertyType DWORD -Name UseLogonCredential -Value 0
```
**Enable WDigest**

```powershell
Remove-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest -Name UseLogonCredential
```



**Credential Manager**

it's used to manage credentials on windows as any password manager, but password are clear text in memory and there is vaultcli.dll that has exported functions that let programmers access, create and retrieve passwords from credential manager



### Execution of Mimikatz

It could be executed via

- mimikatz.exe
- Invoke-Mimikatz \**PowerShell script*\*
- Invoke-PSImage \**PowerShell script*\*
- Dump the LSASS and send it over network and use Mimikatz sekurlsa::minidump command

## Detection

- **mimikatz.exe**

  - sysmon

    - process create

      - Parent image cmd or PowerShell or any other legitimate windows executable (ex: regsrv32)

      - original file name is mimikatz

      - Product is mimikatz

      - company is gentilkiwi

      - IMP hash is one of the following \**generated using the following script*\* [script](https://github.com/karemfaisal/Hybrid-Analysis-API) 

        ```bash
         Count Name
        	7 91c58525e2b08a41627faf84ecb6c4cc
            6 d32c24cc381d21effdebb8fce9278112
            4 fcf758bdc8e91a946e344d06fd667418
            4 f7abe7caa05d6228ab1165ac08af485f
            3 66ee036df5fc1004d9ed5e9a94a1086a
            2 e073e25e16aa7b93510ca9c84a1124f9
            2 c5f52083704cde071984221fb3766d0d
            2 d6babc3862261c87ce2d504a3eb31724
            2 f34d5f2d4577ed6d9ceec516c1f5a744
            1 2d2c317e2c7d2089fac59277e229f901
            1 2e5304cc5ba3b5273c0fd8c1dcf015e6
            1 b600a8b79d9101e71fc0d81b9a4be4be
            1 f1bd9209a8f9c0191c41aa160e183b47
            1 1528a9c3172755d31b6ac63a8bca3b4e
            1 f0d0a258ef4645aabe53a8c67d59a6e0
            1 1e4543b94f902fb1e062932841a7f90c
            1 6cdd00f156ea030f9d8c8e520acb4eba
        ```

    - Process Access

      - Process access to LSASS process

    - Module Loading

      - vaultcli.dll
      - bcryptprimitives.dll

The following is the sysmon rules for Detection, the part of Process create is just here for Illustration, you should log all process creates and exclude the noisy safe process \**take care that some legitimate processes are used to run malicious code (ex: rundll32, hh.exe, cmstp.exe etc.*\*

```xml
<Sysmon schemaversion="4.00">
<HashAlgorithms>md5,sha256,IMPHASH</HashAlgorithms>
  <EventFiltering>
		<ProcessAccess onmatch="include">
			<SourceImage condition="contains">mimikat</SourceImage>
			<TargetImage condition="contains">mimikat</TargetImage>
			<SourceImage condition="is">C:\Windows\System32\lsass.exe</SourceImage>
			<TargetImage condition="is">C:\Windows\System32\lsass.exe</TargetImage>
		</ProcessAccess>
		
		
		<ProcessCreate onmatch="include">
			
			<Product condition="contains">mimikat</Product>
			<Company condition="contains">gentilkiwi</Company>	
		</ProcessCreate>
		
		
		<ImageLoad onmatch="include"> 
			<ImageLoaded condition="contains">vaultcli.dll</ImageLoaded>
			<ImageLoaded condition="contains">bcryptprimitives.dll</ImageLoaded>
		</ImageLoad>
		
		
	</EventFiltering>
</Sysmon>
```

- **Invoke-Mimikatz**
  - sysmon
    - process create
      - PowerShell process with command line contains Invoke-Mimikatz \**of course any one can change it easily*\*
    - Network connection
      - Connection on 5985 or 5986 port *if the Invoke-Mimikatz run remotely using WinRM in PowerShell*
    - Process Access
      - Access LSASS
    - Module Loading
      - vaultcli.dll
      - bcryptprimitives.dll
  - PowerShell Logging
    - Event 4104 will have an event with the function call



- **Dump LSASS using procdump**

  - sysmon

    - Process create

      - Parent process is cmd or PowerShell or any other legitimate process 

      - Company is Sysinternals 

      - original file name procdump

      - command line contains -ma or -mm and lsass.exe (ma for full dump and -mm for mini dump, mimikatz needs full dump but the option in mimikatz called minidump)

      - IMP hash is one of those \**generated using the following script*\* [script](https://github.com/karemfaisal/Hybrid-Analysis-API) 

        ```bash
        Count Name
           13 f8dd5bf0d3ba604276d0cb674673c3b1
           12 fad4245d83e8982f975b4b8f2f4d5719
            4 1cf691685cd8d58a4b3236259e116df7
            2 6219f0a9591135f771a712374981aa3f
            1 e2561e425e0c0718f5f102b48351047b
            1 5ae7cced40af988bd85baeaa5d9b99ec
        ```

      - SHA256 hash is one of those \**generated using the following script*\* [script](https://github.com/karemfaisal/Hybrid-Analysis-API) 

        ```bash
        Count Name
           12 010e32be0f86545e116a8bc3381a8428933eb8789f32c261c81fd5e7857d4a77
           12 05732e84de58a3cc142535431b3aa04efbe034cc96e837f93c360a6387d8faad
            4 aca007d451fbd3921e2221745eb9b9ac516cac758b825da7487ccd8348be07d3
            2 16f413862efda3aba631d8a7ae2bfff6d84acd9f454a7adaa518c7a8a6f375a5
            1 9243c35f3b11fe988761e50b1b5b32debc1e2703fec149f518161e4466ce4091
            1 44f4e5a9738cb24e289b3a1e524af4449143730d37d0336db1cb54c5b7ef5e9e
            1 074be3d159df82c05cf76a1ed32cfc563f7cf2bfd8fe2f01983b7fbf4667cbf9
        ```

    - Process Access

      - Access to LSASS process always with granted access 0x1fffff

    - Process Terminate

      - Usually procdump is closed after it opens

    - Module Loading

      - bcryptprimitives.dll
      - vaultsvc.dll
      - all DLLs for SSPs like [schannel.dll, credssp.dll, gpapi.dll, wdigest.dll, tspkg.dll, samsrv.dll, **lsass.exe** ]

    ```xml
    <Sysmon schemaversion="4.00">
    <HashAlgorithms>md5,sha256,IMPHASH</HashAlgorithms>
      <EventFiltering>
    		<ProcessAccess onmatch="include">
    			<SourceImage condition="contains">procdump</SourceImage>
    			<TargetImage condition="contains">procdump</TargetImage>
    			<SourceImage condition="is">C:\Windows\System32\lsass.exe</SourceImage>
    			<TargetImage condition="is">C:\Windows\System32\lsass.exe</TargetImage>
    		</ProcessAccess>
    		
    		
    		<ImageLoad onmatch="include"> 
    			<ImageLoaded condition="contains">schannel.dll</ImageLoaded>
                <ImageLoaded condition="contains">credssp.dll</ImageLoaded>
                <ImageLoaded condition="contains">gpapi.dll</ImageLoaded>
                <ImageLoaded condition="contains">wdigest.dll</ImageLoaded>
                <ImageLoaded condition="contains">tspkg.dll</ImageLoaded>
    			<ImageLoaded condition="contains">samsrv.dll</ImageLoaded>
                <ImageLoaded condition="contains">lsass.exe</ImageLoaded>
    		</ImageLoad>
    		
    		
    	</EventFiltering>
    </Sysmon>
    ```

    

- **Invoke-PSImage**

  - sysmon
  - PowerShell logging
    - Event 4104 Script Block logging
      - it's usually contains Sal (allies for set alias)
      - .png image, usually it's downloaded from internet



### Protection Against Password Dumping

Microsoft introduced two level of security to defend against Password Dumping

- LSA protection
  - LSASS process is now protected and no other non-protected process can read or inject code in it
- Credential Guard
  - it's obfuscate the Credentials in memory, so when you dump the memory of LSASS you could encrypted hashes





### References

 [Very informative blog about every part of mimikatz] https://adsecurity.org/?page_id=1821 

[Invoke-Mimikatz from PNG] https://pentestlab.blog/2018/01/02/command-and-control-images/ 

[Many ways to dump LSASS] https://medium.com/@markmotig/some-ways-to-dump-lsass-exe-c4a75fdc49bf 

[Mimikatz plugin for volatility] https://medium.com/@ali.bawazeeer/using-mimikatz-to-get-cleartext-password-from-offline-memory-dump-76ed09fd3330

[Every thing about Credentials and Authentication Process ] https://docs.microsoft.com/en-us/windows-server/security/windows-authentication/credentials-processes-in-windows-authentication 

