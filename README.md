# SharpProcessDump

Dump memory regions of a process which are readable (*PAGE_READWRITE* protection) and are commited (*MEM_COMMIT* state) using only native API calls: [NtOpenProcess](https://learn.microsoft.com/es-es/windows-hardware/drivers/ddi/ntddk/nf-ntddk-ntopenprocess), [NtQueryVirtualMemory](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-ntqueryvirtualmemory), [NtReadVirtualMemory](http://undocumented.ntinternals.net/index.html?page=UserMode%2FUndocumented%20Functions%2FMemory%20Management%2FVirtual%20Memory%2FNtReadVirtualMemory.html), [NtCreateFile](https://learn.microsoft.com/es-es/windows/win32/api/winternl/nf-winternl-ntcreatefile) and [NtWriteFile](https://learn.microsoft.com/es-es/windows-hardware/drivers/ddi/ntifs/nf-ntifs-ntwritefile).

![img0](https://raw.githubusercontent.com/ricardojoserf/ricardojoserf.github.io/master/images/sharpprocessdump/Screenshot_0.png)

It generates one file per memory region and one file containing all the memory chunks.

```
SharpProcessDump.exe [PROCESS] [FILE]
```

The default value for the process is "lsass" and for the file containing all memory chunks it is *"Process_PID_allinone.dmp"*.


--------------------------

### Example: Dumping lsass

```
SharpProcessDump.exe lsass lsass_allinone.dmp
```

![img3](https://raw.githubusercontent.com/ricardojoserf/ricardojoserf.github.io/master/images/sharpprocessdump/Screenshot_3.png)

It generates one file per memory region using the process name, PID and memory address for the name (the syntax is *"Process_PID_MEMADDRESS.dmp"*) and the file "lsass_allinone.dmp" containing all the memory chunks:

![img4](https://raw.githubusercontent.com/ricardojoserf/ricardojoserf.github.io/master/images/sharpprocessdump/Screenshot_4.png)

As you can see in the image above, the size between the dump file created using Process Hacker and this tool have almost the same size.
