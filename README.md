# malware-static-analyzer

It is a malware analyzer written in Python2.x for detection of malicious files.

### Features
* Detect presence of IP addresses and check if IP is blacklisted using virustotal, ipvoid ( IP reputation checks)
* Detect presence of Domains and check if they are blacklisted in databases like virustotal, urlvoid. (Domain reputation checks)
* Searches for possible e-mail addresses (E-mail reputation checks using SpamAssassin)
* Get results from Virustotal database (Virustotal integration using Virustotal Public API)
* Checks if the file is packed using software packer programs
* Yara rule based checks for viruses, exploits, web shells, anti-debug functionalities etc.
* Analyze PE file header and sections(number of sections, entropy of sections, suspicious section names, suspicious flags in characterstics of PE file etc)
* Detection of anti-virtualization techniques 
* Detection of Windows API calls commonly used by malware
* JSON based report
* Checks for viruses,spyware using clamd and pyclamd
* PEStudio integration and extraction of malicious indicators from PEStudio report
* Checks for compiler flags in EXE/DLL. Most reputed programs usually make use of these flags.
  * Dynamic base(ASLR)
  * NX Compatible(DEP)
  * Guard(CFG)
  * (Look them in optional header values section)


### Usage

### To do
* Clamd integration
* Virustotal integration - file report(hash report), ip report, url report, domain report
* Analyze ELF file for linux malware analysis using tools such as ldd,readlef, string etc
* Find strings in PE file using sysinternal 'strings' utility(https://docs.microsoft.com/en-us/sysinternals/downloads/strings)
* Check if IP address or domain is listed in DNSBL servers like spamhaus etc.
* PE studio professional for initial malware assessment - purchase license - https://www.winitor.com/tools/pestudio/current/pestudio.zip
* CISCO threat intelligence search - https://talosintelligence.com/reputation_center/lookup?search=igcar.gov.in

### Many Thanks to wonderful people behind the following projects:
* https://github.com/secrary/SSMA
* https://github.com/ClickSecurity/data_hacking/blob/master/pefile_classification/pe_features.py#L317
* https://github.com/hiddenillusion/AnalyzePE/blob/master/AnalyzePE.py
* https://github.com/Ice3man543/MalScan/blob/master/malscan.py

### Clamd and pyclamd installation
* https://gist.github.com/AfroThundr3007730/91a3e2cbfc848088b70d731133ff3f2a
* https://linux-audit.com/install-clamav-on-centos-7-using-freshclam/
* https://geekdecoder.com/clamav-on-centos-6/
* https://www.decalage.info/python/pyclamd
* https://www.moshe-schmidt.de/linux/clamav-permission-denied-how-to-fix-it/
* https://frankfu.click/web-develop/python/autoadmin-chapter4-python-and-security.html
