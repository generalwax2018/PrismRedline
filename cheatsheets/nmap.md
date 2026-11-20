# Nmap Quick Reference
# Sources: community cheatsheets (pkieszek, jasonniebauer, cheat/cheatsheets)

## Host Discovery
nmap -sn 192.168.1.0/24                  # ping scan only
nmap -sn -PR 192.168.1.0/24              # ARP scan (local)
nmap -PS22,80,443 -sn 10.0.0.0/24        # TCP SYN ping
nmap -Pn 10.0.0.5                        # skip discovery, assume up

## Port Scanning
nmap -sS -T4 10.0.0.5                    # SYN scan
nmap -sT 10.0.0.5                        # connect scan
nmap -sU --top-ports 20 10.0.0.5         # UDP top ports
nmap -p- -T4 10.0.0.5                    # all TCP ports
nmap -F 10.0.0.5                         # fast (100 common)

## Service / OS
nmap -sV -sC 10.0.0.5                    # version + default scripts
nmap -A 10.0.0.5                         # aggressive (version, OS, scripts, traceroute)
nmap -O 10.0.0.5                         # OS detection

## Output
nmap -oN scan.txt -oX scan.xml 10.0.0.5

## Useful flags
-n          # no DNS
--open      # only open ports
--reason    # why the state was chosen
--min-rate 50
