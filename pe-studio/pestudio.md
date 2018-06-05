## PEStudio (https://www.winitor.com/index.html)
For malware analysis, PEStudio is a great tool for novice as well as experienced security people. The static analysis tool scans the file and creates a nicely organized list of file headers information and alerts the user if there are any anomalies in the file headers. Typical output contains:
* Hashes – md5, SHA-1, and SHA-256 hashes of file
* Virustotal -PEStudio automatically submits file hash to virustotal and list its results.
* DOS-STUB - This section displays DOS stub - section between MZ and PE header and this section is responsible for famous message - "This file requires Windows to run" in case user is trying to run the program on old DOS system or non-DOS system.
* File-header - General information about file header - CPU architecture, 32-bit/64-bit, size of optional header, compiler options etc.
* Directories - Relative virutal address locations and size of each.
* Sections - Sections in file. Malicious files may have strange section names and PE studio will display it in different color.
* Libraries - DLL files that the program uses/references while being analyzed.
* Imports - List of all OS/Win32 API calls the program uses. This gives us idea about program capabilities and the possible use-cases. e.g. if there are many calls like socket, connect, send, it is highly likely that program is using network communication in a big way.
* Exports - These are functions that PE file exports for other PE files to use. Many times, there is only one export but in some DLL files case, you will see many export functions if the DLL is being used by many other programs.
* Resources - It list out the resources like bitmaps, icons used by program.
* Strings - This parses each string present in the file into a nice and sortable list. It also checks the list against blacklisted strings and raise the alert when any suspicious string is found.
* Debug, version, certificate, overlay etc - The program also checks if any debugging options are enabled, checks its version and certificate authrority etc. Certificate checks are useful as it is possible to raise alert in case a Microsoft Windows file (usually owned by Microsoft) is signed by some third party/ Unknown party.

The features that are available in PEstudio are described here:
https://www.winitor.com/features.html

Some other useful tools that are commonly used for static analysis are listed here - https://toddcullumresearch.com/2017/07/01/todds-giant-intro-of-windows-malware-analysis-tools/

