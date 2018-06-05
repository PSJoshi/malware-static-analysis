### Analysis of compiler security flags using Dumpbin 

Dumpbin is a powerful utility and is available as a part of Visual C++ tools. This python script uses "dumpbin" program to get the status of compiler security flags like ASLR, DEP, CFG etc.

* Download Visual C++ tools for python from the following site - https://wiki.python.org/moin/WindowsCompilers

Typical dumpbin usage on Windows command line is done as follows:

```
cd C:\Users\Joshi\AppData\Local\Programs\Common\Microsoft\Visual C++ for Python\9.0\VC\bin>
C:\Users\Joshi\AppData\Local\Programs\Common\Microsoft\Visual C++ for Python\9.0\VC\bin> dumpbin.exe /headers xxx.exe 
```

Basically, you are looking for following characteristics in EXE/DLL files:
* Dynamic base(ASLR)
* NX Compatible(DEP)
* Guard(CFG)
* Look them in optional header values section

The python script can be used to automate this process.
