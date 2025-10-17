@echo off
REM Windows CMD Commands Batch Script - All 100 Commands
REM Commands with placeholders are commented out with examples
REM All output saved to a single organized text file

echo ================================================
echo Windows CMD - 100 Commands Execution Script
echo ================================================
echo.

REM Create output file with timestamp
set timestamp=%date:~-4,4%%date:~-10,2%%date:~-7,2%*%time:~0,2%%time:~3,2%%time:~6,2%
set timestamp=%timestamp: =0%
set output_file=cmd_output*%timestamp%.txt

echo All results will be saved to: %output_file%
echo.
echo Starting execution…
echo.

REM Initialize output file with header
echo ======================================================================== > %output_file%
echo                  WINDOWS CMD - 100 COMMANDS OUTPUT                      >> %output_file%
echo ======================================================================== >> %output_file%
echo Execution Date: %date% >> %output_file%
echo Execution Time: %time% >> %output_file%
echo Computer: %COMPUTERNAME% >> %output_file%
echo User: %USERNAME% >> %output_file%
echo ======================================================================== >> %output_file%
echo. >> %output_file%
echo. >> %output_file%

REM ============================================
REM SYSTEM INFORMATION COMMANDS (1-15)
REM ============================================

echo ======================================================================== >> %output_file%
echo                        SYSTEM INFORMATION COMMANDS                      >> %output_file%
echo ======================================================================== >> %output_file%
echo. >> %output_file%

echo [1/100] systeminfo
echo ———————————————————————— >> %output_file%
echo [1/100] COMMAND: systeminfo >> %output_file%
echo ———————————————————————— >> %output_file%
systeminfo >> %output_file% 2>&1
echo. >> %output_file%
echo. >> %output_file%

echo [2/100] hostname
echo ———————————————————————— >> %output_file%
echo [2/100] COMMAND: hostname >> %output_file%
echo ———————————————————————— >> %output_file%
hostname >> %output_file% 2>&1
echo. >> %output_file%
echo. >> %output_file%

echo [3/100] whoami
echo ———————————————————————— >> %output_file%
echo [3/100] COMMAND: whoami >> %output_file%
echo ———————————————————————— >> %output_file%
whoami >> %output_file% 2>&1
echo. >> %output_file%
echo. >> %output_file%

echo [4/100] whoami /all
echo ———————————————————————— >> %output_file%
echo [4/100] COMMAND: whoami /all >> %output_file%
echo ———————————————————————— >> %output_file%
whoami /all >> %output_file% 2>&1
echo. >> %output_file%
echo. >> %output_file%

echo [5/100] whoami /priv
echo ———————————————————————— >> %output_file%
echo [5/100] COMMAND: whoami /priv >> %output_file%
echo ———————————————————————— >> %output_file%
whoami /priv >> %output_file% 2>&1
echo. >> %output_file%
echo. >> %output_file%

echo [6/100] whoami /groups
echo ———————————————————————— >> %output_file%
echo [6/100] COMMAND: whoami /groups >> %output_file%
echo ———————————————————————— >> %output_file%
whoami /groups >> %output_file% 2>&1
echo. >> %output_file%
echo. >> %output_file%

echo [7/100] set
echo ———————————————————————— >> %output_file%
echo [7/100] COMMAND: set >> %output_file%
echo ———————————————————————— >> %output_file%
set >> %output_file% 2>&1
echo. >> %output_file%
echo. >> %output_file%

echo [8/100] ver
echo ———————————————————————— >> %output_file%
echo [8/100] COMMAND: ver >> %output_file%
echo ———————————————————————— >> %output_file%
ver >> %output_file% 2>&1
echo. >> %output_file%
echo. >> %output_file%

echo [9/100] wmic os get caption,version
echo ———————————————————————— >> %output_file%
echo [9/100] COMMAND: wmic os get caption,version >> %output_file%
echo ———————————————————————— >> %output_file%
wmic os get caption,version >> %output_file% 2>&1
echo. >> %output_file%
echo. >> %output_file%

echo [10/100] wmic bios get serialnumber
echo ———————————————————————— >> %output_file%
echo [10/100] COMMAND: wmic bios get serialnumber >> %output_file%
echo ———————————————————————— >> %output_file%
wmic bios get serialnumber >> %output_file% 2>&1
echo. >> %output_file%
echo. >> %output_file%

echo [11/100] wmic cpu get name
echo ———————————————————————— >> %output_file%
echo [11/100] COMMAND: wmic cpu get name >> %output_file%
echo ———————————————————————— >> %output_file%
wmic cpu get name >> %output_file% 2>&1
echo. >> %output_file%
echo. >> %output_file%

echo [12/100] wmic memorychip get capacity
echo ———————————————————————— >> %output_file%
echo [12/100] COMMAND: wmic memorychip get capacity >> %output_file%
echo ———————————————————————— >> %output_file%
wmic memorychip get capacity >> %output_file% 2>&1
echo. >> %output_file%
echo. >> %output_file%

echo [13/100] wmic diskdrive get model,size
echo ———————————————————————— >> %output_file%
echo [13/100] COMMAND: wmic diskdrive get model,size >> %output_file%
echo ———————————————————————— >> %output_file%
wmic diskdrive get model,size >> %output_file% 2>&1
echo. >> %output_file%
echo. >> %output_file%

echo [14/100] wmic logicaldisk get caption,freespace,size
echo ———————————————————————— >> %output_file%
echo [14/100] COMMAND: wmic logicaldisk get caption,freespace,size >> %output_file%
echo ———————————————————————— >> %output_file%
wmic logicaldisk get caption,freespace,size >> %output_file% 2>&1
echo. >> %output_file%
echo. >> %output_file%

echo [15/100] date /t and time /t
echo ———————————————————————— >> %output_file%
echo [15/100] COMMAND: date /t and time /t >> %output_file%
echo ———————————————————————— >> %output_file%
date /t >> %output_file% 2>&1
time /t >> %output_file% 2>&1
echo. >> %output_file%
echo. >> %output_file%

REM ============================================
REM NETWORK COMMANDS (16-40)
REM ============================================

echo. >> %output_file%
echo ======================================================================== >> %output_file%
echo                           NETWORK COMMANDS                              >> %output_file%
echo ======================================================================== >> %output_file%
echo. >> %output_file%

echo [16/100] ipconfig
echo ———————————————————————— >> %output_file%
echo [16/100] COMMAND: ipconfig >> %output_file%
echo ———————————————————————— >> %output_file%
ipconfig >> %output_file% 2>&1
echo. >> %output_file%
echo. >> %output_file%

echo [17/100] ipconfig /all
echo ———————————————————————— >> %output_file%
echo [17/100] COMMAND: ipconfig /all >> %output_file%
echo ———————————————————————— >> %output_file%
ipconfig /all >> %output_file% 2>&1
echo. >> %output_file%
echo. >> %output_file%

echo [18/100] ipconfig /displaydns
echo ———————————————————————— >> %output_file%
echo [18/100] COMMAND: ipconfig /displaydns >> %output_file%
echo ———————————————————————— >> %output_file%
ipconfig /displaydns >> %output_file% 2>&1
echo. >> %output_file%
echo. >> %output_file%

echo [19/100] ipconfig /flushdns
echo ———————————————————————— >> %output_file%
echo [19/100] COMMAND: ipconfig /flushdns >> %output_file%
echo ———————————————————————— >> %output_file%
ipconfig /flushdns >> %output_file% 2>&1
echo. >> %output_file%
echo. >> %output_file%

echo ———————————————————————— >> %output_file%
echo [20/100] COMMAND: ipconfig /release (COMMENTED - will disconnect network) >> %output_file%
echo ———————————————————————— >> %output_file%
echo SKIPPED: This command would disconnect the network >> %output_file%
echo. >> %output_file%
echo. >> %output_file%

echo ———————————————————————— >> %output_file%
echo [21/100] COMMAND: ipconfig /renew (COMMENTED - requires release first) >> %output_file%
echo ———————————————————————— >> %output_file%
echo SKIPPED: This command requires network to be released first >> %output_file%
echo. >> %output_file%
echo. >> %output_file%

echo [22/100] netstat -an
echo ———————————————————————— >> %output_file%
echo [22/100] COMMAND: netstat -an >> %output_file%
echo ———————————————————————— >> %output_file%
netstat -an >> %output_file% 2>&1
echo. >> %output_file%
echo. >> %output_file%

echo [23/100] netstat -ano
echo ———————————————————————— >> %output_file%
echo [23/100] COMMAND: netstat -ano >> %output_file%
echo ———————————————————————— >> %output_file%
netstat -ano >> %output_file% 2>&1
echo. >> %output_file%
echo. >> %output_file%

echo [24/100] netstat -r
echo ———————————————————————— >> %output_file%
echo [24/100] COMMAND: netstat -r >> %output_file%
echo ———————————————————————— >> %output_file%
netstat -r >> %output_file% 2>&1
echo. >> %output_file%
echo. >> %output_file%

echo [25/100] route print
echo ———————————————————————— >> %output_file%
echo [25/100] COMMAND: route print >> %output_file%
echo ———————————————————————— >> %output_file%
route print >> %output_file% 2>&1
echo. >> %output_file%
echo. >> %output_file%

echo ———————————————————————— >> %output_file%
echo [26/100] COMMAND: route add [destination] MASK [netmask] [gateway] >> %output_file%
echo ———————————————————————— >> %output_file%
echo SKIPPED: Requires placeholder values >> %output_file%
echo Example: route add 192.168.2.0 MASK 255.255.255.0 192.168.1.1 >> %output_file%
echo. >> %output_file%
echo. >> %output_file%

echo ———————————————————————— >> %output_file%
echo [27/100] COMMAND: route delete [destination] >> %output_file%
echo ———————————————————————— >> %output_file%
echo SKIPPED: Requires placeholder values >> %output_file%
echo Example: route delete 192.168.2.0 >> %output_file%
echo. >> %output_file%
echo. >> %output_file%

echo [28/100] arp -a
echo ———————————————————————— >> %output_file%
echo [28/100] COMMAND: arp -a >> %output_file%
echo ———————————————————————— >> %output_file%
arp -a >> %output_file% 2>&1
echo. >> %output_file%
echo. >> %output_file%

echo ———————————————————————— >> %output_file%
echo [29/100] COMMAND: arp -d [ip_address] >> %output_file%
echo ———————————————————————— >> %output_file%
echo SKIPPED: Requires placeholder values >> %output_file%
echo Example: arp -d 192.168.1.100 >> %output_file%
echo. >> %output_file%
echo. >> %output_file%

echo [30/100] nslookup localhost
echo ———————————————————————— >> %output_file%
echo [30/100] COMMAND: nslookup localhost >> %output_file%
echo ———————————————————————— >> %output_file%
nslookup localhost >> %output_file% 2>&1
echo. >> %output_file%
echo. >> %output_file%

echo ———————————————————————— >> %output_file%
echo [31/100] COMMAND: nslookup [domain] >> %output_file%
echo ———————————————————————— >> %output_file%
echo SKIPPED: Requires placeholder values >> %output_file%
echo Example: nslookup google.com >> %output_file%
echo. >> %output_file%
echo. >> %output_file%

echo ———————————————————————— >> %output_file%
echo [32/100] COMMAND: ping [host] >> %output_file%
echo ———————————————————————— >> %output_file%
echo SKIPPED: Requires placeholder values >> %output_file%
echo Example: ping 8.8.8.8 >> %output_file%
echo. >> %output_file%
echo. >> %output_file%

echo ———————————————————————— >> %output_file%
echo [33/100] COMMAND: ping -t [host] >> %output_file%
echo ———————————————————————— >> %output_file%
echo SKIPPED: Continuous ping - requires placeholder and manual stop >> %output_file%
echo Example: ping -t 8.8.8.8 >> %output_file%
echo. >> %output_file%
echo. >> %output_file%

echo ———————————————————————— >> %output_file%
echo [34/100] COMMAND: tracert [host] >> %output_file%
echo ———————————————————————— >> %output_file%
echo SKIPPED: Requires placeholder values >> %output_file%
echo Example: tracert google.com >> %output_file%
echo. >> %output_file%
echo. >> %output_file%

echo ———————————————————————— >> %output_file%
echo [35/100] COMMAND: pathping [host] >> %output_file%
echo ———————————————————————— >> %output_file%
echo SKIPPED: Requires placeholder values >> %output_file%
echo Example: pathping google.com >> %output_file%
echo. >> %output_file%
echo. >> %output_file%

echo [36/100] netsh interface show interface
echo ———————————————————————— >> %output_file%
echo [36/100] COMMAND: netsh interface show interface >> %output_file%
echo ———————————————————————— >> %output_file%
netsh interface show interface >> %output_file% 2>&1
echo. >> %output_file%
echo. >> %output_file%

echo [37/100] netsh wlan show profiles
echo ———————————————————————— >> %output_file%
echo [37/100] COMMAND: netsh wlan show profiles >> %output_file%
echo ———————————————————————— >> %output_file%
netsh wlan show profiles >> %output_file% 2>&1
echo. >> %output_file%
echo. >> %output_file%

echo ———————————————————————— >> %output_file%
echo [38/100] COMMAND: netsh wlan show profile [profile_name] key=clear >> %output_file%
echo ———————————————————————— >> %output_file%
echo SKIPPED: Requires placeholder values >> %output_file%
echo Example: netsh wlan show profile “WiFi-Name” key=clear >> %output_file%
echo. >> %output_file%
echo. >> %output_file%

echo [39/100] netsh advfirewall show allprofiles
echo ———————————————————————— >> %output_file%
echo [39/100] COMMAND: netsh advfirewall show allprofiles >> %output_file%
echo ———————————————————————— >> %output_file%
netsh advfirewall show allprofiles >> %output_file% 2>&1
echo. >> %output_file%
echo. >> %output_file%

echo ———————————————————————— >> %output_file%
echo [40/100] COMMAND: netsh advfirewall set allprofiles state off >> %output_file%
echo ———————————————————————— >> %output_file%
echo SKIPPED: This command would disable the firewall >> %output_file%
echo. >> %output_file%
echo. >> %output_file%

REM ============================================
REM USER AND GROUP COMMANDS (41-50)
REM ============================================

echo. >> %output_file%
echo ======================================================================== >> %output_file%
echo                        USER AND GROUP COMMANDS                          >> %output_file%
echo ======================================================================== >> %output_file%
echo. >> %output_file%

echo [41/100] net user
echo ———————————————————————— >> %output_file%
echo [41/100] COMMAND: net user >> %output_file%
echo ———————————————————————— >> %output_file%
net user >> %output_file% 2>&1
echo. >> %output_file%
echo. >> %output_file%

echo ———————————————————————— >> %output_file%
echo [42/100] COMMAND: net user [username] >> %output_file%
echo ———————————————————————— >> %output_file%
echo SKIPPED: Requires placeholder values >> %output_file%
echo Example: net user Administrator >> %output_file%
echo. >> %output_file%
echo. >> %output_file%

echo ———————————————————————— >> %output_file%
echo [43/100] COMMAND: net user [username] [password] >> %output_file%
echo ———————————————————————— >> %output_file%
echo SKIPPED: Requires placeholder values >> %output_file%
echo Example: net user TestUser NewPassword123 >> %output_file%
echo. >> %output_file%
echo. >> %output_file%

echo ———————————————————————— >> %output_file%
echo [44/100] COMMAND: net user [username] /add >> %output_file%
echo ———————————————————————— >> %output_file%
echo SKIPPED: Requires placeholder values >> %output_file%
echo Example: net user NewUser Password123 /add >> %output_file%
echo. >> %output_file%
echo. >> %output_file%

echo ———————————————————————— >> %output_file%
echo [45/100] COMMAND: net user [username] /delete >> %output_file%
echo ———————————————————————— >> %output_file%
echo SKIPPED: Requires placeholder values >> %output_file%
echo Example: net user OldUser /delete >> %output_file%
echo. >> %output_file%
echo. >> %output_file%

echo [46/100] net localgroup
echo ———————————————————————— >> %output_file%
echo [46/100] COMMAND: net localgroup >> %output_file%
echo ———————————————————————— >> %output_file%
net localgroup >> %output_file% 2>&1
echo. >> %output_file%
echo. >> %output_file%

echo [47/100] net localgroup administrators
echo ———————————————————————— >> %output_file%
echo [47/100] COMMAND: net localgroup administrators >> %output_file%
echo ———————————————————————— >> %output_file%
net localgroup administrators >> %output_file% 2>&1
echo. >> %output_file%
echo. >> %output_file%

echo ———————————————————————— >> %output_file%
echo [48/100] COMMAND: net localgroup [group] [username] /add >> %output_file%
echo ———————————————————————— >> %output_file%
echo SKIPPED: Requires placeholder values >> %output_file%
echo Example: net localgroup administrators NewUser /add >> %output_file%
echo. >> %output_file%
echo. >> %output_file%

echo ———————————————————————— >> %output_file%
echo [49/100] COMMAND: net localgroup [group] [username] /delete >> %output_file%
echo ———————————————————————— >> %output_file%
echo SKIPPED: Requires placeholder values >> %output_file%
echo Example: net localgroup administrators OldUser /delete >> %output_file%
echo. >> %output_file%
echo. >> %output_file%

echo [50/100] net accounts
echo ———————————————————————— >> %output_file%
echo [50/100] COMMAND: net accounts >> %output_file%
echo ———————————————————————— >> %output_file%
net accounts >> %output_file% 2>&1
echo. >> %output_file%
echo. >> %output_file%

REM ============================================
REM PROCESS AND SERVICE COMMANDS (51-65)
REM ============================================

echo. >> %output_file%
echo ======================================================================== >> %output_file%
echo                      PROCESS AND SERVICE COMMANDS                       >> %output_file%
echo ======================================================================== >> %output_file%
echo. >> %output_file%

echo [51/100] tasklist
echo ———————————————————————— >> %output_file%
echo [51/100] COMMAND: tasklist >> %output_file%
echo ———————————————————————— >> %output_file%
tasklist >> %output_file% 2>&1
echo. >> %output_file%
echo. >> %output_file%

echo [52/100] tasklist /v
echo ———————————————————————— >> %output_file%
echo [52/100] COMMAND: tasklist /v >> %output_file%
echo ———————————————————————— >> %output_file%
tasklist /v >> %output_file% 2>&1
echo. >> %output_file%
echo. >> %output_file%

echo [53/100] tasklist /svc
echo ———————————————————————— >> %output_file%
echo [53/100] COMMAND: tasklist /svc >> %output_file%
echo ———————————————————————— >> %output_file%
tasklist /svc >> %output_file% 2>&1
echo. >> %output_file%
echo. >> %output_file%

echo ———————————————————————— >> %output_file%
echo [54/100] COMMAND: taskkill /PID [process_id] >> %output_file%
echo ———————————————————————— >> %output_file%
echo SKIPPED: Requires placeholder values >> %output_file%
echo Example: taskkill /PID 1234 >> %output_file%
echo. >> %output_file%
echo. >> %output_file%

echo ———————————————————————— >> %output_file%
echo [55/100] COMMAND: taskkill /IM [process_name] >> %output_file%
echo ———————————————————————— >> %output_file%
echo SKIPPED: Requires placeholder values >> %output_file%
echo Example: taskkill /IM notepad.exe >> %output_file%
echo. >> %output_file%
echo. >> %output_file%

echo ———————————————————————— >> %output_file%
echo [56/100] COMMAND: taskkill /F /IM [process_name] >> %output_file%
echo ———————————————————————— >> %output_file%
echo SKIPPED: Requires placeholder values >> %output_file%
echo Example: taskkill /F /IM chrome.exe >> %output_file%
echo. >> %output_file%
echo. >> %output_file%

echo [57/100] sc query
echo ———————————————————————— >> %output_file%
echo [57/100] COMMAND: sc query >> %output_file%
echo ———————————————————————— >> %output_file%
sc query >> %output_file% 2>&1
echo. >> %output_file%
echo. >> %output_file%

echo ———————————————————————— >> %output_file%
echo [58/100] COMMAND: sc query [service_name] >> %output_file%
echo ———————————————————————— >> %output_file%
echo SKIPPED: Requires placeholder values >> %output_file%
echo Example: sc query wuauserv >> %output_file%
echo. >> %output_file%
echo. >> %output_file%

echo ———————————————————————— >> %output_file%
echo [59/100] COMMAND: sc start [service_name] >> %output_file%
echo ———————————————————————— >> %output_file%
echo SKIPPED: Requires placeholder values >> %output_file%
echo Example: sc start wuauserv >> %output_file%
echo. >> %output_file%
echo. >> %output_file%

echo ———————————————————————— >> %output_file%
echo [60/100] COMMAND: sc stop [service_name] >> %output_file%
echo ———————————————————————— >> %output_file%
echo SKIPPED: Requires placeholder values >> %output_file%
echo Example: sc stop wuauserv >> %output_file%
echo. >> %output_file%
echo. >> %output_file%

echo ———————————————————————— >> %output_file%
echo [61/100] COMMAND: sc config [service_name] start= [mode] >> %output_file%
echo ———————————————————————— >> %output_file%
echo SKIPPED: Requires placeholder values >> %output_file%
echo Example: sc config wuauserv start= disabled >> %output_file%
echo. >> %output_file%
echo. >> %output_file%

echo [62/100] net start
echo ———————————————————————— >> %output_file%
echo [62/100] COMMAND: net start >> %output_file%
echo ———————————————————————— >> %output_file%
net start >> %output_file% 2>&1
echo. >> %output_file%
echo. >> %output_file%

echo ———————————————————————— >> %output_file%
echo [63/100] COMMAND: net start [service_name] >> %output_file%
echo ———————————————————————— >> %output_file%
echo SKIPPED: Requires placeholder values >> %output_file%
echo Example: net start “Windows Update” >> %output_file%
echo. >> %output_file%
echo. >> %output_file%

echo ———————————————————————— >> %output_file%
echo [64/100] COMMAND: net stop [service_name] >> %output_file%
echo ———————————————————————— >> %output_file%
echo SKIPPED: Requires placeholder values >> %output_file%
echo Example: net stop “Windows Update” >> %output_file%
echo. >> %output_file%
echo. >> %output_file%

echo [65/100] wmic process list brief
echo ———————————————————————— >> %output_file%
echo [65/100] COMMAND: wmic process list brief >> %output_file%
echo ———————————————————————— >> %output_file%
wmic process list brief >> %output_file% 2>&1
echo. >> %output_file%
echo. >> %output_file%

REM ============================================
REM FILE AND DIRECTORY COMMANDS (66-75)
REM ============================================

echo. >> %output_file%
echo ======================================================================== >> %output_file%
echo                      FILE AND DIRECTORY COMMANDS                        >> %output_file%
echo ======================================================================== >> %output_file%
echo. >> %output_file%

echo [66/100] dir C:  
echo ———————————————————————— >> %output_file%
echo [66/100] COMMAND: dir C:\ >> %output_file%
echo ———————————————————————— >> %output_file%
dir C:\ >> %output_file% 2>&1
echo. >> %output_file%
echo. >> %output_file%

echo [67/100] dir /a C:  
echo ———————————————————————— >> %output_file%
echo [67/100] COMMAND: dir /a C:\ >> %output_file%
echo ———————————————————————— >> %output_file%
dir /a C:\ >> %output_file% 2>&1
echo. >> %output_file%
echo. >> %output_file%

echo ———————————————————————— >> %output_file%
echo [68/100] COMMAND: dir /s [directory] >> %output_file%
echo ———————————————————————— >> %output_file%
echo SKIPPED: Recursive directory listing can be extremely long >> %output_file%
echo Example: dir /s C:\Users >> %output_file%
echo. >> %output_file%
echo. >> %output_file%

echo [69/100] tree
echo ———————————————————————— >> %output_file%
echo [69/100] COMMAND: tree %CD% /F >> %output_file%
echo ———————————————————————— >> %output_file%
tree %CD% /F >> %output_file% 2>&1
echo. >> %output_file%
echo. >> %output_file%

echo ———————————————————————— >> %output_file%
echo [70/100] COMMAND: cd [directory] >> %output_file%
echo ———————————————————————— >> %output_file%
echo SKIPPED: Changes directory - requires placeholder >> %output_file%
echo Example: cd C:\Windows >> %output_file%
echo. >> %output_file%
echo. >> %output_file%

echo [71/100] mkdir test_directory
echo ———————————————————————— >> %output_file%
echo [71/100] COMMAND: mkdir test_directory >> %output_file%
echo ———————————————————————— >> %output_file%
mkdir %TEMP%\cmd_test_dir >> %output_file% 2>&1
echo Test directory created in %TEMP%\cmd_test_dir >> %output_file%
echo. >> %output_file%
echo. >> %output_file%

echo ———————————————————————— >> %output_file%
echo [72/100] COMMAND: rmdir [directory] >> %output_file%
echo ———————————————————————— >> %output_file%
echo SKIPPED: Requires placeholder values >> %output_file%
echo Example: rmdir test_directory >> %output_file%
echo. >> %output_file%
echo. >> %output_file%

echo ———————————————————————— >> %output_file%
echo [73/100] COMMAND: copy [source] [destination] >> %output_file%
echo ———————————————————————— >> %output_file%
echo SKIPPED: Requires placeholder values >> %output_file%
echo Example: copy file.txt C:\backup\file.txt >> %output_file%
echo. >> %output_file%
echo. >> %output_file%

echo ———————————————————————— >> %output_file%
echo [74/100] COMMAND: xcopy [source] [destination] /s /e >> %output_file%
echo ———————————————————————— >> %output_file%
echo SKIPPED: Requires placeholder values >> %output_file%
echo Example: xcopy C:\folder D:\backup\ /s /e >> %output_file%
echo. >> %output_file%
echo. >> %output_file%

echo ———————————————————————— >> %output_file%
echo [75/100] COMMAND: del [file] >> %output_file%
echo ———————————————————————— >> %output_file%
echo SKIPPED: Requires placeholder values >> %output_file%
echo Example: del unwanted_file.txt >> %output_file%
echo. >> %output_file%
echo. >> %output_file%

REM ============================================
REM REGISTRY AND SYSTEM COMMANDS (76-85)
REM ============================================

echo. >> %output_file%
echo ======================================================================== >> %output_file%
echo                      REGISTRY AND SYSTEM COMMANDS                       >> %output_file%
echo ======================================================================== >> %output_file%
echo. >> %output_file%

echo ———————————————————————— >> %output_file%
echo [76/100] COMMAND: reg query [key] >> %output_file%
echo ———————————————————————— >> %output_file%
echo SKIPPED: Requires placeholder values >> %output_file%
echo Example: reg query HKLM\Software\Microsoft\Windows\CurrentVersion >> %output_file%
echo. >> %output_file%
echo. >> %output_file%

echo ———————————————————————— >> %output_file%
echo [77/100] COMMAND: reg add [key] /v [value] /d [data] >> %output_file%
echo ———————————————————————— >> %output_file%
echo SKIPPED: Requires placeholder values >> %output_file%
echo Example: reg add HKCU\Software\TestKey /v TestValue /d “TestData” >> %output_file%
echo. >> %output_file%
echo. >> %output_file%

echo ———————————————————————— >> %output_file%
echo [78/100] COMMAND: reg delete [key] >> %output_file%
echo ———————————————————————— >> %output_file%
echo SKIPPED: Requires placeholder values >> %output_file%
echo Example: reg delete HKCU\Software\TestKey /f >> %output_file%
echo. >> %output_file%
echo. >> %output_file%

echo [79/100] schtasks /query
echo ———————————————————————— >> %output_file%
echo [79/100] COMMAND: schtasks /