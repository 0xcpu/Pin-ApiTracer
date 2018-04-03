[ApiTracer](https://github.com/hasherezade/MyPinTools/tree/master/ApiTracer) Pin tool for Pin version 3.6

The idea for instrumenting API functions from an arguments format file the file itself(apiargs.txt) is taken from [pinlog](https://github.com/int0/pinlog). This feature is available only for x86 32 bit executables, the behaviour of the tool on x86 64 bit is unknown(/will crash for sure?)

## Current issues

Function `GetProcAddress` crashes the tool on some calls, especially on GUI executables.
