## Clamd and pyclamd installation on CentOS 7.0 or later
#### Enable EPEL repository:
```
[root@joshi]# yum install epel-release
[root@joshi]# yum install clamav clamd clamav-data
[root@joshi]# yum install clamav-scanner
```
Typical rpms you will find on the system:
```
[root@joshi]# rpm -qa |grep clam
clamav-server-0.99.4-1.el7.x86_64
clamav-scanner-0.99.4-1.el7.noarch
clamav-scanner-systemd-0.99.4-1.el7.noarch
clamav-data-0.99.4-1.el7.noarch
clamav-filesystem-0.99.4-1.el7.noarch
clamav-0.99.4-1.el7.x86_64
clamav-lib-0.99.4-1.el7.x86_64
clamav-server-systemd-0.99.4-1.el7.noarch
```
#### Write logs to a separate file and change its owner to clamscan user:
```
[root@joshi]# touch  /var/log/clamd.scan
[root@joshi]# chown clamscan:clamscan /var/log/clamd.scan
```
#### Create unix socket for communication
```
[root@joshi]# touch /var/run/clamd.scan/clamd.sock
[root@joshi]# chown clamscan:clamscan /var/run/clamd.scan/clamd.sock
[root@joshi]# ls -l /var/run/clamd.scan/clamd.sock
srw-rw-rw- 1 clamscan clamscan 0 May 14 13:05 /var/run/clamd.scan/clamd.sock
```
Now, rename clamd services:
```
[root@joshi]# ls -l /usr/lib/systemd/system/clam*
-rw-r--r-- 1 root root 135 May 14 13:04 /usr/lib/systemd/system/clamd@scan.service
-rw-r--r-- 1 root root 217 May 14 13:03 /usr/lib/systemd/system/clamd@.service

# mv /usr/lib/systemd/system/clamd@scan.service /usr/lib/systemd/system/clamdscan.service
# mv /usr/lib/systemd/system/clamd@.service /usr/lib/systemd/system/clamd.service
```
Do not forget to change service name in clamdscan.service (remove @ in service name)
#### Clamdscan service
```
[root@joshi]# cat /usr/lib/systemd/system/clamdscan.service
.include /lib/systemd/system/clamd.service

[Unit]
Description = Generic clamav scanner daemon

[Install]
WantedBy = multi-user.target
```
#### Clamd service
```
[root@joshi]# cat /usr/lib/systemd/system/clamd.service
[Unit]
Description = clamd scanner daemon
After = syslog.target nss-lookup.target network.target

[Service]
Type = forking
ExecStart = /usr/sbin/clamd -c /etc/clamd.d/scan.conf
Restart = on-failure
PrivateTmp = true
```
### enable and start clamd services 
```
# systemctl enable clamdscan.service 
# systemctl start clamdscan.service 
## systemctl enable clamd.service -- this step is not required
# systemctl start clamd.service 
```
### Typical Clamd configuration file:
```
[root@joshi]# cat /etc/clamd.d/scan.conf |grep -v ^#|grep -v ^$
LogFile /var/log/clamd.scan
LogSyslog yes
LocalSocket /var/run/clamd.scan/clamd.sock
User clamscan
AllowSupplementaryGroups yes
```
Note - If this above file contains a line with 'Example', comment it with '#' or remove the line.
 
### Now, scan home directory for any viruses:
```
[root@joshi]# clamscan -r /home/joshi/
```
### Check logs by default under /var/log/messages:
```
[root@ joshi]# cat /var/log/messages
```
Typical errors that you might encounter while installing clamd are:
### lstat() failed: Permission denied. ERROR
```
[root@joshi]# clamdscan -c /etc/clamd.d/scan.conf clamd.conf
/home/joshi/clamd.conf: lstat() failed: Permission denied. ERROR

----------- SCAN SUMMARY -----------
Infected files: 0
Total errors: 1
Time: 0.000 sec (0 m 0 s)

This happens when directory or file permissions are not OK. e.g. 

[root@joshi]# ls -l /home
total 4
drwx------ 9 joshi email 4096 May 14 12:44 joshi
```
You have to remember - basically, there are two commands: clamscan and clamdscan.
* clamdscan uses clamd daemon service which is run under clamscan user. The user permissions will come in picture here!
* clamscan runs as a normal program on a host machine.

### Install python client for clamd - pyclamd 
```
[root@joshi]# easy_install --index-url=http://osrepo.gov.in/pypi/simple pip
[root@joshi]# pip3 install pyclamd --trusted-host=osrepo.gov.in
```
