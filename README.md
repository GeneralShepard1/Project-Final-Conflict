# Service Vulnerabilities & Network Security Findings

Ovaj dokument predstavlja pregled pronađenih servisnih i mrežnih ranjivosti tokom skeniranja sistema. Za svaku ranjivost naveden je način otkrivanja, dokaz i preporučene mjere mitigacije.

---

## 1) FTP (21) – Plain text login / Anonymous login

Naziv ranjivosti: FTP koristi nekriptovanu autentifikaciju (Plain-text credentials) + moguć Anonymous login  

Host: <IP>  
Port/Servis: 21 / FTP  

Kako je otkriveno:

```bash
sudo nmap -sV -p21 <IP>
sudo nmap --script ftp-anon,ftp-syst,ftp-banner -p21 <IP>
```

Rezultat (dokaz):

```
21/tcp open  ftp vsftpd 3.0.3
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
```

FTP servis je otvoren i omogućava anonymous pristup.

Preporuka:
- Onemogućiti FTP ako nije potreban
- Koristiti SFTP ili FTPS
- Zabraniti anonymous login
- Uvesti jake lozinke i firewall pravila

Rizik: **HIGH**

---

## 2) SSH (22) – Brute force / slabi algoritmi

Naziv ranjivosti: SSH omogućava brute-force i/ili koristi nesigurne algoritme  

Host: <IP>  
Port/Servis: 22 / SSH  

Kako je otkriveno:

```bash
sudo nmap -sV -p22 <IP>
sudo nmap --script ssh2-enum-algos,ssh-hostkey -p22 <IP>
ssh -v user@<IP>
```

Rezultat (dokaz):

SSH servis aktivan.

Slabi algoritmi primjer:
```
aes128-cbc
hmac-sha1
```

Dobri algoritmi primjer:
```
curve25519-sha256
ssh-ed25519
```

Preporuka:
- Koristiti SSH ključeve
- Isključiti password login
- Onemogućiti PermitRootLogin
- Uključiti fail2ban
- Forsirati SSHv2 i moderne algoritme

Rizik: **MEDIUM/HIGH**

---

## 3) Telnet (23) – Plain text komunikacija

Naziv ranjivosti: Telnet koristi nekriptovanu komunikaciju (sniffing moguć)

Host: <IP>  
Port/Servis: 23 / Telnet  

Kako je otkriveno:

```bash
sudo nmap -sV -p23 <IP>
```

Rezultat (dokaz):
Port 23 otvoren, komunikacija ide u plain textu.

Preporuka:
- Onemogućiti Telnet
- Koristiti SSH

Rizik: **HIGH**

---

## 4) HTTP (80) – Nešifrovana komunikacija + info disclosure

Naziv ranjivosti: HTTP bez enkripcije + curenje informacija kroz headers i metode

Host: <IP>  
Port/Servis: 80 / HTTP  

Kako je otkriveno:

```bash
sudo nmap -sV -p80 <IP>
sudo nmap --script http-title,http-headers,http-methods,http-enum,http-robots.txt -p80 <IP>
sudo nmap --script http-trace -p80 <IP>
```

Rezultat (dokaz):

```
Server: Apache/2.4.18 (Ubuntu)
X-Powered-By: PHP/7.0.33
```

Headers otkrivaju tehnologije i verzije.

Preporuka:
- Forsirati HTTPS (redirect 80 → 443)
- Isključiti TRACE i nepotrebne metode
- Update web server
- Sakriti server banner

Rizik: **MEDIUM/HIGH**

---

## 5) HTTPS (443) – Slabi TLS protokoli / cipheri

Naziv ranjivosti: Slaba TLS konfiguracija ili zastarjeli protokoli

Host: <IP>  
Port/Servis: 443 / HTTPS  

Kako je otkriveno:

```bash
sudo nmap -sV -p443 <IP>
sudo nmap --script ssl-cert,ssl-enum-ciphers -p443 <IP>
```

Rezultat (dokaz):
HTTPS aktivan, ali mogući stari TLS protokoli ili slabi cipheri.

Preporuka:
- Onemogućiti SSLv3, TLS1.0 i TLS1.1
- Koristiti TLS1.2 ili TLS1.3
- Validan certifikat

Rizik: **MEDIUM**

---

## 6) SMB (445) – EternalBlue / SMBv1

Naziv ranjivosti: SMB izložen prema mreži (MS17-010 rizik)

Host: <IP>  
Port/Servis: 445 / SMB  

Kako je otkriveno:

```bash
sudo nmap -sV -p445 <IP>
sudo nmap --script smb-os-discovery,smb-security-mode -p445 <IP>
sudo nmap --script smb-vuln* -p445 <IP>
sudo nmap --script smb-protocols -p445 <IP>
```

Rezultat (dokaz):
Ako SMBv1 postoji → moguć EternalBlue napad.

Preporuka:
- Onemogućiti SMBv1
- Patch Windows
- Blokirati port 445 firewallom

Rizik: **HIGH**

---

## 7) NetBIOS (139) – Legacy exposure

Naziv ranjivosti: NetBIOS port izložen

Host: <IP>  
Port/Servis: 139 / NetBIOS  

Kako je otkriveno:

```bash
sudo nmap -sV -p139 <IP>
```

Preporuka:
- Onemogućiti NetBIOS over TCP/IP
- Koristiti SMBv2/v3
- Firewall ograničenja

Rizik: **MEDIUM**

---

## 8) RDP (3389) – Remote access rizik

Naziv ranjivosti: RDP izložen + moguća slaba enkripcija

Host: <IP>  
Port/Servis: 3389 / RDP  

Kako je otkriveno:

```bash
sudo nmap -sV -p3389 <IP>
sudo nmap --script rdp-enum-encryption -p3389 <IP>
```

Preporuka:
- Ograničiti pristup firewallom
- Uključiti NLA
- Patch sistem

Rizik: **HIGH**

---

## 9) MySQL (3306) – Otvoren prema mreži

Naziv ranjivosti: MySQL servis izložen

Host: <IP>  
Port/Servis: 3306 / MySQL  

Kako je otkriveno:

```bash
sudo nmap -sV -p3306 <IP>
sudo nmap --script mysql-info -p3306 <IP>
```

Preporuka:
- Jaka autentikacija
- Bind na localhost
- Firewall blokada

Rizik: **HIGH**

---

## 10) PostgreSQL (5432) – Otvoren prema mreži

Naziv ranjivosti: PostgreSQL izložen mreži

Host: <IP>  
Port/Servis: 5432 / PostgreSQL  

Kako je otkriveno:

```bash
sudo nmap -sV -p5432 <IP>
sudo nmap --script pgsql-info -p5432 <IP>
```

Preporuka:
- Firewall ograničenja
- Bind localhost ako nije potreban remote pristup

Rizik: **MEDIUM/HIGH**

---

## 11) DNS Spoofing rizik (lokalni DNS = gateway)

Naziv ranjivosti: DNS spoofing moguć zbog lokalnog DNS servera

Kako je otkriveno:

```bash
cat /etc/resolv.conf
```

Ako DNS pokazuje gateway IP → lokalni DNS.

Preporuka:
- Koristiti pouzdan DNS (1.1.1.1 / 8.8.8.8)
- DNSSEC gdje moguće

Rizik: **MEDIUM**

---

## 12) ARP Spoofing / MITM

Naziv ranjivosti: Dinamična ARP tabela omogućava MITM napad

Kako je otkriveno:

```bash
ip neigh show
```

Ako zapis nije PERMANENT → dinamičan unos.

Preporuka:
- Statički ARP zapis za gateway
- ARP inspection na switchu

Rizik: **MEDIUM/HIGH**

---

## 13) DHCP Spoofing

Naziv ranjivosti: DHCP spoofing moguć

Kako je otkriveno:

```bash
cat /var/lib/dhcp/dhclient.leases
```

Ako nema DHCP server identifier → slabija kontrola.

Preporuka:
- DHCP snooping
- Prihvatati DHCP samo od legit servera

Rizik: **MEDIUM**

---

## 14) Promiscuous Mode / Sniffing

Naziv ranjivosti: Interface u promiscuous modu

Kako je otkriveno:

```bash
ip link show eth0
ip -details link show eth0 | grep -i promisc
```

Ako postoji PROMISC → moguće snimanje mrežnog saobraćaja.

Preporuka:

```bash
sudo ip link set eth0 promisc off
```

Rizik: **MEDIUM**

---

## 15) Firewall loša konfiguracija

Naziv ranjivosti: Firewall nije konfigurisan (ACCEPT policy)

Kako je otkriveno:

```bash
sudo iptables -L -n
```

Ako su policy ACCEPT → nema zaštite.

Preporuka:
- Default DROP
- Dozvoliti samo potrebne portove

Rizik: **HIGH**

---

## Zaključak

Tokom provjere mrežne sigurnosti izvršeno je otkrivanje hostova u subnetu, skeniranje portova i identifikacija servisa pomoću Nmap alata. Analizirani su sigurnosni rizici na osnovu otvorenih portova i konfiguracija servisa. Uočene su potencijalne ranjivosti poput izloženih servisa (SMB, RDP, FTP), nekriptovane komunikacije (HTTP, Telnet, FTP), te mogućih mrežnih napada (ARP, DNS i DHCP spoofing). Preporučene mjere uključuju patch management, isključivanje nepotrebnih servisa, firewall restrikcije, koriš
