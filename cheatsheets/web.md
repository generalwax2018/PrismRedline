# Web Enumeration
## Directory / file discovery
gobuster dir -u http://target -w /usr/share/wordlists/dirb/common.txt
ffuf -u http://target/FUZZ -w /usr/share/seclists/Discovery/Web-Content/common.txt

## Nikto
nikto -h http://target

## Notes
Only relevant paths that lead to a foothold need to be documented in the report.
