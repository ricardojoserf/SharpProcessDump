# SharpProcessDump

Dump memory regions of a process which are readable (*PAGE_READWRITE* protection) and are commited (*MEM_COMMIT* state) using [VirtualQueryEx](https://learn.microsoft.com/es-es/windows/win32/api/memoryapi/nf-memoryapi-virtualqueryex) and [NtReadVirtualMemory](http://undocumented.ntinternals.net/index.html?page=UserMode%2FUndocumented%20Functions%2FMemory%20Management%2FVirtual%20Memory%2FNtReadVirtualMemory.html).

It generates one file per memory region and one file containing all the memory chunks.

```
SharpProcessDump.exe [PROCESS] [FILE]
```

The default value for the process is "lsass" and for the file containing all memory chunks it is "dump.dmp".


--------------------------

### Example: Dumping notepad

```
SharpProcessDump.exe notepad notepad_all.dmp
```

![img1](https://raw.githubusercontent.com/ricardojoserf/ricardojoserf.github.io/master/images/sharpprocessdump/Screenshot_1.png)

It generates one file per memory region using the process name, PID and memory address for the name (the syntax is *"Process_PID_MEMADDRESS.dmp"*) and the file "notepad_all.dmp" containing all the memory chunks:

![img2](https://raw.githubusercontent.com/ricardojoserf/ricardojoserf.github.io/master/images/sharpprocessdump/Screenshot_2.png)

