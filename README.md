# IDK IF IT'S WORKING ?!
# ScannXR — Advanced Python Network Scanner

Scannxr is a powerful, modular, and high‑performance local network discovery & port‑scanning toolkit, designed for both beginners and cybersecurity professionals. It supports ARP discovery, SYN stealth scans, TCP connect scans, banner grabbing, MAC vendor lookup, OS fingerprinting, multi-threaded scanning, and HTML/JSON export.


---

🚀 Features

🔥 1. Network Discovery

ARP‑based host detection (fastest, LAN only)

ICMP/UDP/TCP fallback for devices that block ARP

Auto‑mode selects the best method depending on privileges


⚡ 2. Advanced Port Scanning

Stealth SYN scan (requires root)

TCP connect scan (works everywhere)

Highly parallel — multi‑thread support

Custom port ranges: 80,443,22,8000-8100


📡 3. Fingerprinting & Metadata

Banner grabbing (HTTP, SSH, FTP, SMTP, custom protocols)

OS guess based on TTL

MAC vendor lookup (via local OUI file)


📄 4. Reporting

Export results to JSON

Export beautiful HTML reports

Optional minimal Flask web dashboard


🧩 5. Modular Architecture

Clean, extensible structure

Easy to add new scan modules



---

📦 Installation

Requirements

Python 3.8+

Optional dependencies:

pip install scapy
pip install flask


---

🖥️ Usage

Basic Scan

python3 scannxr.py -n 192.168.1.0/24

Scan Top Ports

python3 scannxr.py -n 192.168.1.0/24 -p 22,80,443

Full 1‑65535 Port Scan

python3 scannxr.py -n 192.168.1.0/24 -p 1-65535

Stealth SYN Scan (root required)

sudo python3 scannxr.py -n 192.168.1.0/24 --mode syn

Export Reports

python3 scannxr.py -n 192.168.1.0/24 --json result.json --html report.html

Launch Web UI

python3 scannxr.py -n 192.168.1.0/24 --flask


---

⚙️ CLI Options

usage: scannxr.py [-h] --network NETWORK [--ports PORTS]
                  [--mode {auto,syn,connect}] [--threads THREADS]
                  [--port-threads PORT_THREADS] [--no-arp]
                  [--oui OUI] [--json JSON] [--html HTML]
                  [--flask]

Argument	Description

-n, --network	Target network (CIDR)
-p, --ports	Ports or port ranges
--mode	auto / syn / connect
--threads	Discovery threads
--port-threads	Port scan threads
--no-arp	Disable ARP discovery
--oui	MAC vendor database file
--json	Save JSON results
--html	Save HTML report
--flask	Launch Flask UI



---

📊 Example JSON Output

{
  "host": "192.168.1.10",
  "mac": "84:3A:4B:2C:10:A1",
  "vendor": "Samsung Electronics",
  "os_guess": "Linux/Android",
  "open_ports": [
    { "port": 22, "service": "ssh", "banner": "OpenSSH 8.9" },
    { "port": 80, "service": "http", "banner": "Apache 2.4" }
  ]
}


---

🔐 Legal Warning

Use Scannxr only on networks you own or are authorized to test.
Unauthorized scanning is illegal.


---


⭐ Credits

Developed by FIOZXR (GitHub: @fiozxr)


---

🙌 Support

If you like this project, consider giving a ⭐ on GitHub!
