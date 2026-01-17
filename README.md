1) FTP (21) – Plain text login / Anonymous login

Naziv ranjivosti: FTP koristi nekriptovanu autentifikaciju (Plain-text credentials) + moguć Anonymous login
Host: <IP>
Port/Servis: 21/FTP
Kako je otkriveno (komanda):

sudo nmap -sV -p21 <IP>
sudo nmap --script ftp-anon -p21 <IP>

Rezultat (dokaz):
FTP servis je otvoren i radi na portu 21
Ako ftp-anon pokaže da je login moguć → Anonymous pristup je omogućen
Preporuka:
Onemogućiti FTP ako nije potreban
Umjesto FTP koristiti SFTP/FTPS
Zabraniti anonymous login, uvesti jake lozinke i firewall pravila
Rizik: HIGH


2) SSH (22) – Brute force / SSHv1 / slabe postavke
Naziv ranjivosti: SSH omogućava brute-force i/ili koristi nesigurne algoritme / SSHv1
Host: <IP>
Port/Servis: 22/SSH
Kako je otkriveno:
sudo nmap -sV -p22 <IP>
sudo nmap --script ssh2-enum-algos -p22 <IP>
ssh -v user@<IP>
Rezultat (dokaz):
SSH servis aktivan na portu 22
Ako se vidi star protokol / slabi algoritmi → povećan rizik
Preporuka:
Koristiti SSH ključeve (isključiti password login)
Uključiti fail2ban
Zabraniti PermitRootLogin yes
Forsirati SSHv2 i moderne algoritme
Rizik: MEDIUM/HIGH

3) Telnet (23) – Plain text (kritično)

Naziv ranjivosti: Telnet koristi nekriptovanu komunikaciju (sniffing moguć)
Host: <IP>
Port/Servis: 23/Telnet
Kako je otkriveno:
sudo nmap -sV -p23 <IP>
Rezultat (dokaz):
Telnet port 23 otvoren
Preporuka:
Onemogućiti Telnet servis
Koristiti SSH
Rizik: HIGH

4) HTTP (80) – Nešifrovana komunikacija + info disclosure
Naziv ranjivosti: HTTP saobraćaj nije enkriptovan (MITM/sniffing) + moguće curenje informacija (headers/methods)
Host: <IP>
Port/Servis: 80/HTTP
Kako je otkriveno:
sudo nmap -sV -p80 <IP>
sudo nmap --script http-title,http-headers,http-methods,http-enum,http-robots.txt -p80 <IP>
sudo nmap --script http-trace -p80 <IP>
Rezultat (dokaz):
HTTP otvoren bez TLS enkripcije
Headers/methods mogu otkriti tehnologije i verzije (pomaže napadaču)
Preporuka:
Forsirati HTTPS (443) i preusmjeriti 80 → 443
Isključiti nepotrebne metode (TRACE)
Update web server i sakriti banner
Rizik: MEDIUM/HIGH

5) HTTPS (443) – Slabi TLS protokoli/cipheri, cert problemi
Naziv ranjivosti: Slaba TLS konfiguracija / zastarjeli protokoli / slab certifikat
Host: <IP>
Port/Servis: 443/HTTPS
Kako je otkriveno:
sudo nmap -sV -p443 <IP>
sudo nmap --script ssl-cert,ssl-enum-ciphers -p443 <IP>
Rezultat (dokaz):
HTTPS aktivan
Ako se vide stari protokoli (TLS1.0/SSLv3) ili slabi cipheri → ranjivo
Preporuka:
Onemogućiti SSLv3/TLS1.0/TLS1.1
Ostavi TLS1.2+ / TLS1.3
Koristiti validan certifikat
Rizik: MEDIUM

6) SMB (445) – EternalBlue / SMBv1 / SMB Ghost / share enumeracija
Rranjivosti: SMB izložen prema mreži (visok rizik – MS17-010 / SMBv1)
Host: <IP>
Port/Servis: 445/SMB
Kako je otkriveno:
sudo nmap -sV -p445 <IP>
sudo nmap --script smb-os-discovery,smb-security-mode -p445 <IP>
sudo nmap --script smb-vuln* -p445 <IP>
sudo nmap --script smb-protocols -p445 <IP>
Rezultat (dokaz):
Port 445 otvoren
Ako smb-protocols pokaže SMBv1 → moguć EternalBlue rizik
smb-vuln* može prijaviti ranjivost MS17-010 ili slične
Preporuka:
Onemogućiti SMBv1
Patch Windows (MS updates)
Blokirati 445 na firewallu ako nije potrebno
Rizik: HIGH

7) NetBIOS (139) – SMB/legacy exposure
Naziv ranjivosti: NetBIOS port 139 izložen (legacy SMB surface)
Host: <IP>
Port/Servis: 139/NetBIOS
Kako je otkriveno:
sudo nmap -sV -p139 <IP>
Rezultat (dokaz):
Port 139 otvoren
Preporuka:
Onemogućiti NetBIOS over TCP/IP ako nije potreban
Osloniti se na modern SMBv2/v3 i firewall
Rizik: MEDIUM

8) RDP (3389) – BlueKeep / slaba enkripcija
Naziv ranjivosti: RDP izložen (remote access surface) + moguće slabe postavke
Host: <IP>
Port/Servis: 3389/RDP
Kako je otkriveno:
sudo nmap -sV -p3389 <IP>
sudo nmap --script rdp-enum-encryption -p3389 <IP>
Rezultat (dokaz):
RDP otvoren
Ako enkripcija nije jaka → povećan rizik MITM i brute force
Preporuka:
Ograničiti pristup firewallom (samo admin IP)
Uključiti NLA (Network Level Authentication)
Patch sistem
Rizik: HIGH

9) MySQL (3306) – otvoren prema mreži / bez auth
Naziv ranjivosti: MySQL servis izložen (moguće slabe lozinke i remote pristup)
Host: <IP>
Port/Servis: 3306/MySQL
Kako je otkriveno:
sudo nmap -sV -p3306 <IP>
sudo nmap --script mysql-info -p3306 <IP>
Rezultat (dokaz):
MySQL port otvoren (povećana attack surface)
Preporuka:
Postaviti jake lozinke
Bind samo na localhost ako ne treba remote
Firewall block 3306 eksterno
Rizik: HIGH

10) PostgreSQL (5432) – otvoren prema mreži
Naziv ranjivosti: PostgreSQL otvoren na mreži (moguć brute force / misconfig)
Host: <IP>
Port/Servis: 5432/PostgreSQL
Kako je otkriveno:
sudo nmap -sV -p5432 <IP>
sudo nmap --script pgsql-info -p5432 <IP>
Rezultat (dokaz):
5432 port otvoren
Preporuka:
Firewall + autentikacija
Bind localhost ako nije potreban remote
Rizik: MEDIUM/HIGH

11) DNS Spoofing rizik (lokalni DNS = gateway)
Naziv ranjivosti: DNS Spoofing moguć zbog korištenja lokalnog DNS servera (gateway)
Host: Kali
Kako je otkriveno:
cat /etc/resolv.conf
Rezultat (dokaz):
Ako DNS pokazuje gateway IP (npr 172.27.160.1) → lokalni DNS
Preporuka:
Postaviti pouzdan DNS (npr 1.1.1.1 / 8.8.8.8)
Koristiti DNSSEC gdje moguće
Rizik: MEDIUM

12) ARP Spoofing / MITM (dinamična ARP tabela)
Naziv ranjivosti: ARP spoofing/Man-in-the-middle moguć zbog dinamičnih ARP unosa
Host: Kali
Kako je otkriveno:
ip neigh show
Rezultat (dokaz):
Ako gateway nije PERMANENT nego STALE/REACHABLE → dinamičan zapis
Preporuka:
Postaviti statički ARP zapis za gateway
Switch security (ARP inspection)
Rizik: MEDIUM/HIGH

13) DHCP Spoofing (lažni DHCP server)
Naziv ranjivosti: DHCP spoofing moguć (napadač može slati lažne DHCP postavke)
Host: Kali
Kako je otkriveno:
cat /var/lib/dhcp/dhclient.leases
Rezultat (dokaz):
Ako nema option dhcp-server-identifier ili je prazno → DHCP nije jasno kontrolisan
Preporuka:
DHCP snooping (na switchu)
Prihvataj DHCP samo od legit servera
Rizik: MEDIUM

14) Promiscuous Mode / Sniffing rizik
Naziv ranjivosti: Moguć sniffing ako je interface u promiscuous modu
Host: Kali
Kako je otkriveno:
ip link show eth0
ip -details link show eth0 | grep -i promisc
Rezultat (dokaz):
Ako piše PROMISC → uključeno
Preporuka:
Isključiti promiscuous:
sudo ip link set eth0 promisc off
Rizik: MEDIUM

15) Firewall loša konfiguracija (sve otvoreno)

Naziv ranjivosti: Nema firewall zaštite (INPUT/FORWARD ACCEPT)
Host: Kali
Kako je otkriveno:
sudo iptables -L -n
Rezultat (dokaz):
Ako su policy ACCEPT → nema zaštite
Preporuka:
Postaviti default DROP + dozvoliti samo potrebno
Rizik: HIGH

Zaključak:
Tokom provjere mrežne sigurnosti izvršeno je otkrivanje hostova u subnetu, skeniranje portova i identifikacija servisa pomoću Nmap alata. Analizirani su sigurnosni rizici na osnovu otvorenih portova i konfiguracija servisa. Uočene su potencijalne ranjivosti poput izloženih servisa (SMB/RDP/FTP), nekriptovane komunikacije (HTTP/Telnet/FTP), te mogućih mrežnih napada (ARP/DNS/DHCP spoofing). Preporučene su mjere hardeninga: patch management, isključivanje nepotrebnih servisa, firewall restrikcije, moderni protokoli (HTTPS/SSH keys), te segmentacija i kontrola pristupa.
