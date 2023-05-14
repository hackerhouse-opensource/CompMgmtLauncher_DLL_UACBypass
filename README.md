# CompMgmtLauncher & Sharepoint DLL Search Order hijacking UAC/persist via OneDrive

CompMgmtLauncher.exe is vulnerable to to a DLL Search Order hijacking 
vulnerability. The binary, will perform a search within user env for 
the DLL's Secur32.dll or Wininet.dll when Onedrive is installed. 
CompMgmtLauncher.exe has autoelavate enabled on some versions of Windows 
10. This can be exploited using a Proxy DLL to execute code as autoelevate
is enabled and OneDrive is installed by default on Windows 10 Desktop. On
Windows 11 this provides a useful persistence capability in Microsoft.Sharepoint.exe. 

This issue has a fix in Windows 10 1703 and up as the manifest runs 
asInvoker, preventing misuse for UAC elevation. OneDrive must be installed 
to exploit this issue, which is a default configuration on Windows 10.
 
Injecting into CompMgtLauncher.exe behaves differently on x64 and x86,
DLL sideloading maybe most stable with wininet x86. You can also use this 
to persist and sideload via Microsoft.Sharepoint.exe which reads from 
the OneDrive location. To exploit via OneDrive, you have to find OneDrive
version for path which is a moving target but could be enumerated from the 
host.
 
This exploit has been tested against the following product versions:

* Windows 10 1507 x64 (tested - not vuln.)
* Windows 10 1511 x64 (vulnerable) 
* Windows 10 1607 x64 (tested - not vuln)
* Windows 11 21996.1 x64 (Persistence / LOLbin / Microsoft.Sharepoint.exe)

These files are available under a Attribution-NonCommercial-NoDerivatives 4.0 International license.
