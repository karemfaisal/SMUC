## TLS Callback

>  **Thread Local Storage** (**TLS**) is the mechanism by which each thread in a given multithreaded process allocates storage for thread-specific data. In standard multithreaded programs, data is shared among all threads of a given process, whereas thread local storage is the mechanism for allocating per-thread data 
>
> -Microsoft

> **Thread-local storage** (**TLS**) is a computer programming method that uses static or global memory local to a thread.
>
> -Wikipedia



some times you need global variable in your code but you need it to be global per thread not for all threads(by default all threads share the same memory), what I means that you have 2 threads and each thread contains code, you want each thread's code to have a global variable but it's different from the same global variable in the other thread despite that two variables have the same name, so we have TLS.



**TLS in Malwares**

TLS is used for another thing, because it's related to threads and variables and because every process run must go and check what in the TLS so it gets the appropriate initialization, that makes TLS runs before the main entry point, so any code in TLS will run before the main function of the executable or **what I prefer to say it will run regardless the state of the entry point, it can run in 4 different scenarios**

- Process start  // *this is the case that what in TLS is executed before the main entry point*
- Process End
- Thread Start
- Thread End

**so you can use TLS call back to run code before main and after main**

so malware writers use TLS call back for two things

- Anti-debugging technique
  - run anti-debugger checks before the main entry point, so the entry point goes in a different way if the debugger present
- infect the malware analyst device if he doesn't know about TLS callback because the malicious code will run before his first entry point he set which would be the main entry point



### How to use it

Just use this simple code and compile it in Visual Studio "I use VS2013"

```C++
// TLSCallback.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include <Windows.h>

__declspec(thread) BOOL Debugger;
__declspec(thread) WCHAR *evil;
void NTAPI funfun(void* dll, DWORD reason, void* reserved)
{
	if (reason == DLL_PROCESS_ATTACH){
		Debugger = IsDebuggerPresent();
		evil = L"Evil";
	}
}

#pragma comment (linker, "/INCLUDE:__tls_used")
#pragma comment (linker, "/INCLUDE:__xl_b")
#pragma data_seg(".CRT$XLB")
EXTERN_C
PIMAGE_TLS_CALLBACK _xl_b = funfun;
#pragma data_seg()

int main()
{
	if (Debugger){
		printf("Debugger Present, go out Mr Reverser\n");
		system("pause");
	}
	else{
		MessageBox(nullptr, L"This is Evil Work", evil, MB_ICONWARNING);
	
	}
	
	return 0;
}

```



### Detect TLS Callbacks while analysis

- PE header will contain directory data for TLS
- PE will contains .tls section, *of course it's name could be changed* *using CFF as example*
- IDA pro will detect it just check the entry points using CTRL+E
- x32/64dbg will detect it and list it in Break points section



### References

- 1- [Microsfot Docs](https://docs.microsoft.com/en-us/cpp/c-language/thread-local-storage?view=vs-2019)
- 2- [Intro to TLS](http://www.nynaeve.net/?p=180)





