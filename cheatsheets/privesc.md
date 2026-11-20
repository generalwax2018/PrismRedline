# Privilege Escalation Enumeration
# Primary tools: LinPEAS / WinPEAS (PEASS-ng)

## LinPEAS (Linux)
curl -L https://github.com/peass-ng/PEASS-ng/releases/latest/download/linpeas.sh -o linpeas.sh
chmod +x linpeas.sh
./linpeas.sh | tee linpeas.out

## WinPEAS (Windows)
# Transfer winPEASx64.exe then:
winPEASx64.exe

## Manual checks (Linux)
id; sudo -l
find / -perm -4000 -type f 2>/dev/null
cat /etc/crontab; ls -la /etc/cron*
ps aux
uname -a

## Manual checks (Windows)
whoami /priv
systeminfo
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated

## References
- https://github.com/peass-ng/PEASS-ng
- https://book.hacktricks.xyz
