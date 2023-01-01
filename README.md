## **TermProc**  

The purpose of the code in this repository is both to distinguish between Conhost and Windows Terminal processes and to determine which terminal instance is connected to the current console process. Third-party terminal apps are not supported.  
The source files are transcriptions of pretty much the same core code in different programming languages.  
<br>
### **Minimum requirements to compile/run the code:**  

Source files in `Windows Batch`, `C`, `C++`, `C#.Net`, `PowerShell`, and `VB.Net` are published in the [src](./src) folder. They all depend on Windows being the target operating system. Other specific dependencies are listed below.  

| **File** | **Requirement** |
| :--- | :--- |
| `*.bat` | *Windows PowerShell 2* |
| `*.c` | *C99* |
| `*.cpp` | *C++20* |
| `*.cs` | *.NET Framework 4.5* |
| `*.ps1` | *Windows PowerShell 2* |
| `*.vb` | *.NET Framework 4.5* |

<br>

### **Relevant code:**  

The source files in this repository contain fully functional code that demonstrates how to use the search procedure. However, if you intend to use it in your own code, it might be useful to know which essential pieces of code you need to include.  

| **File** | **Code of interest** | **Value of interest** |
| :--- | :--- | :--- |
| `*.bat` | *`TermPid`* macro defined in the `:init_TermPid` routine | the errorlevel returned by the *`TermPid`* macro is the PID of the hosting terminal (`0` or PowerShell exception if an error occurred) |
| `*.c` | *`GetTermPid`* function, along with structure `SYSTEM_HANDLE` and functions `GetProcBaseName`, `GetPidOfNamedProcWithOpenProcHandle` | the value returned by the *`GetTermPid`* function is the PID of the hosting terminal (`0` if an error occurred) |
| `*.cpp` | everything in namespace *`termpid`*, along with namespace `saferes` and the `GetProcBaseName` function | the value returned by the *`GetTermPid`* function is the PID of the hosting terminal (`0` or exception if an error occurred) |
| `*.cs` | class *`WinTerm`* | the value of property *`WinTerm.TermProc`* refers to the hosting terminal process (`null` or exception if an error occurred) |
| `*.ps1` | Type referencing class *`WinTerm`* | the value of property *`[WinTerm]::TermProc`* refers to the hosting terminal process (`$null` or exception if an error occurred) |
| `*.vb` | Module *`WinTerm`* | the value of property *`WinTerm.TermProc`* refers to the hosting terminal process (`Nothing` or exception if an error occurred) |

<br>

### **Background:**  
A few years ago Microsoft began to develop a new terminal application - [Windows Terminal](https://github.com/microsoft/terminal). The installation is available for Windows 10, and Windows 11 already ships with it. By an update in October '22 Microsoft turned it into the default terminal app on Windows 11.  
As of now, Windows Terminal coexists with the good old Conhost. Users are able to choose which is taken as their default terminal app.  

In the past, it has been easy to figure out which terminal process is connected to the shell/console application. Behind the scenes it was always Conhost and thus, Microsoft made the Windows API reporting the process which spawned the conhost process as the terminal process, and reporting the window of the shell application as the console window. While all this is technically incorrect, it is quite comfortable at the same time.  
However, no such convenience functionality is implemented for the Windows Terminal. And if Windows Terminal is set as the default terminal, we cannot infer from the process tree which terminal process is communicating with our shell process.  

Using Process Explorer I observed that the Windows Terminal process has a handle to the shell process open. Assuming that this is always the case I tried to write a piece of code that enumerates all open handles searching for the right process handle. This requires to involve some undocumented API. I left a couple of comments in the code that roughly explain how this all works.  

In each file is also a piece of unrelated code that fades the window out and in again. I found it an impressive way of proving that the right process had been found.  
<br>
![example output](./termproc.gif)

<br>

### **Search procedure:**  
This is a brief explanation of how searching is implemented in the source codes.  
1. Determine the handle to the console window.  
2. Try to get its icon.  
   - If we got a valid handle then our application is running in a Conhost window, and we return the PID of the process for which the window has been created. (The Windows API is special-cased to handle the hosted process as owner of the window rather than the Conhost process itself.)  
   - If the handle is a null pointer we assume that the Conhost window is hidden (ConPTY), and we have to proceed searching under the assumption that Windows Terminal hosts our application.  
3. The `NtQuerySystemInformation` API function is used to get a snapshot of all open handles in all running processes. (This is not officially documented.)  
   - The information is provided as array of structures that contain the type of the open handle, the PID of the process which opened the handle, and a pseudo handle that identifies the opened handle (along with further information that we don't use).  
4. Iterate over the array in a loop.  
   - Continue with the next structure if the type of the open handle does not meet the type we are looking for.  
   - Duplicate the pseudo handle. Continue with the next structure if the duplicated handle and the handle to the application which owns the hidden Console window don't point to the same kernel object.  
   - Get the name of the process that opened the handle. Continue with the next structure if the name is not "WindowsTerminal".  
   - Return either the PID of the found "WindowsTerminal" process or 0 if we didn't find it.  

