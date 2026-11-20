# Active Directory Enumeration
# High-level traditional flow (no exploit steps)

## Initial
nmap -p 88,135,139,389,445,464,593,636,3268,3269,3389 <DC>
nxc smb <target>
enum4linux-ng <target>

## Domain info (once credentialed)
nxc smb <DC> -u user -p pass --users
nxc smb <DC> -u user -p pass --groups
bloodhound-python -d domain.local -u user -p pass -ns <DC> -c all

## Useful references
- https://github.com/swisskyrepo/InternalAllTheThings
- https://github.com/Integration-IT/Active-Directory-Exploitation-Cheat-Sheet
- https://book.hacktricks.xyz/windows/active-directory-methodology

## Notes
Stay in phase. Enumeration before any lateral movement attempts.
Record every command and result for the attack chain section of the report.
