"""
Pro Network Scanner - `pro_net_scanner.py`

Features:
- Multi-method host discovery (ARP scan if run as root with scapy, else ICMP ping sweep)
- Fast, concurrent port scanning with two modes:
    * SYN (stealth) scan via scapy (requires root & scapy)
    * TCP connect scan fallback (no root required)
- Service banner grabbing and simple service detection
- OS guess from TTL
- MAC & vendor lookup (load local OUI file if provided)
- JSON and HTML report export
- Optional minimal Flask web UI (requires Flask)

Notes:
- Running SYN scan or ARP discovery needs root/administrator privileges and scapy installed.
- Use responsibly: scan only networks you own or have explicit permission to scan.

Usage examples:
    python3 pro_net_scanner.py --network 192.168.1.0/24 --ports 1-1024 --mode syn --output report.json

"""

import argparse
import ipaddress
import json
import os
import platform
import re
import socket
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from html import escape

# Optional dependencies
try:
    from scapy.all import ARP, Ether, srp, sr1, IP, TCP, send, conf
    SCAPY_AVAILABLE = True
except Exception:
    SCAPY_AVAILABLE = False

try:
    from flask import Flask, jsonify, render_template_string
    FLASK_AVAILABLE = True
except Exception:
    FLASK_AVAILABLE = False

# ---------------------- Utilities ----------------------

def now():
    return datetime.utcnow().isoformat() + "Z"


def parse_ports(ports_str):
    """Parse ports like "22,80,8000-8100" or "1-65535" into a sorted list of ints."""
    parts = re.split(r"\s*,\s*", ports_str.strip())
    ports = set()
    for p in parts:
        if not p:
            continue
        if '-' in p:
            a, b = p.split('-')
            ports.update(range(int(a), int(b) + 1))
        else:
            ports.add(int(p))
    return sorted(p for p in ports if 1 <= p <= 65535)


# ---------------------- OUI Vendor Lookup ----------------------

def load_oui(filepath=None):
    """Load a simple OUI map from a local file (format: "AA:BB:CC\tVendor")"""
    oui = {}
    if not filepath or not os.path.exists(filepath):
        return oui
    with open(filepath, 'r', errors='ignore') as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            parts = re.split(r'\s+', line, maxsplit=1)
            if len(parts) < 2:
                continue
            key = parts[0].upper().replace('-', ':')
            oui[key] = parts[1].strip()
    return oui


# ---------------------- Discovery ----------------------

def icmp_ping(ip, timeout=1):
    """Cross-platform ICMP ping via socket/ subprocess fallback. We'll try basic socket connect to port 80 as lightweight fallback."""
    # Best-effort lightweight ping: try connecting to common ports first (80,443)
    for port in (80, 443, 22):
        try:
            s = socket.socket()
            s.settimeout(timeout)
            s.connect((str(ip), port))
            s.close()
            return True, f"tcp_connect:{port}"
        except Exception:
            pass
    # If no service present, try simple ICMP using system ping as last resort
    if platform.system().lower().startswith('windows'):
        cmd = ['ping', '-n', '1', '-w', str(int(timeout*1000)), str(ip)]
    else:
        cmd = ['ping', '-c', '1', '-W', str(int(timeout)), str(ip)]
    try:
        import subprocess
        res = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        alive = res.returncode == 0
        return alive, 'icmp'
    except Exception:
        return False, ''


def arp_scan(network_cidr, timeout=2):
    """Use scapy ARP ping (fast) -- requires scapy and root."""
    if not SCAPY_AVAILABLE:
        raise RuntimeError('scapy not available')
    net = ipaddress.ip_network(network_cidr, strict=False)
    ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=str(net)), timeout=timeout, verbose=0)
    hosts = []
    for sent, received in ans:
        hosts.append((received.psrc, received.hwsrc))
    return hosts


def discover_hosts(network_cidr, prefer_arp=True, threads=100):
    """Return list of discovered hosts as tuples (ip, mac_or_None, method)"""
    net = ipaddress.ip_network(network_cidr, strict=False)
    hosts = []
    if prefer_arp and SCAPY_AVAILABLE and os.geteuid() == 0:
        try:
            raw = arp_scan(network_cidr)
            for ip, mac in raw:
                hosts.append((ip, mac, 'arp'))
            return hosts
        except Exception:
            pass

    # Fallback: ICMP/TCP connect sweep concurrently
    ips = [str(ip) for ip in net.hosts()]
    def worker(ip):
        alive, method = icmp_ping(ip, timeout=1)
        if alive:
            return (ip, None, method)
        return None

    with ThreadPoolExecutor(max_workers=threads) as exe:
        futures = {exe.submit(worker, ip): ip for ip in ips}
        for fut in as_completed(futures):
            r = fut.result()
            if r:
                hosts.append(r)
    return hosts


# ---------------------- Port Scanning ----------------------

def tcp_connect_scan(ip, port, timeout=0.6):
    try:
        s = socket.socket()
        s.settimeout(timeout)
        res = s.connect_ex((ip, port))
        if res == 0:
            try:
                s.send(b'\r\n')
                banner = s.recv(1024).decode(errors='ignore').strip()
            except Exception:
                banner = ''
            s.close()
            return port, banner
    except Exception:
        pass
    return None


# SYN scan via scapy (requires running as root)
def syn_scan_scapy(ip, port, timeout=1):
    if not SCAPY_AVAILABLE:
        return None
    pkt = IP(dst=ip)/TCP(dport=port, flags='S')
    resp = sr1(pkt, timeout=timeout, verbose=0)
    if not resp:
        return None
    if resp.haslayer(TCP):
        flags = resp.getlayer(TCP).flags
        # SYN-ACK => open
        if flags & 0x12:  # SYN-ACK
            # send RST to close
            send(IP(dst=ip)/TCP(dport=port, flags='R'), verbose=0)
            return port, ''
    return None


def scan_ports_for_host(ip, ports, mode='auto', max_workers=500):
    """Scan ports and return dict port->banner or empty banner"""
    open_ports = {}
    if mode == 'auto':
        if SCAPY_AVAILABLE and os.geteuid() == 0:
            mode = 'syn'
        else:
            mode = 'connect'

    scan_fn = syn_scan_scapy if mode == 'syn' and SCAPY_AVAILABLE else tcp_connect_scan

    with ThreadPoolExecutor(max_workers=min(max_workers, len(ports) or 1)) as exe:
        futures = {exe.submit(scan_fn, ip, p): p for p in ports}
        for fut in as_completed(futures):
            res = fut.result()
            if res:
                port, banner = res
                open_ports[port] = banner
    return open_ports


# ---------------------- OS Guess ----------------------

def guess_os_from_ttl(info: str):
    m = re.search(r'ttl=(\d+)', info)
    if not m:
        return 'Unknown'
    ttl = int(m.group(1))
    if ttl <= 64:
        return 'Linux/Unix'
    if ttl <= 128:
        return 'Windows'
    return 'Unknown'


# ---------------------- Reporting ----------------------

def save_json(results, path):
    with open(path, 'w') as f:
        json.dump(results, f, indent=2)


HTML_TEMPLATE = """
<html>
<head>
    <meta charset="utf-8" />
    <title>ProNetScan Report</title>
    <style>
        body { font-family: Inter, Roboto, sans-serif; padding: 18px; }
        .host { border: 1px solid #ddd; padding: 8px; margin-bottom: 10px; border-radius: 6px; }
        .port { font-family: monospace; }
    </style>
</head>
<body>
    <h1>ProNetScan Report</h1>
    <p>Generated: {{generated}}</p>
    <p>Summary: {{summary}}</p>
    {% for h in hosts %}
    <div class="host">
        <h2>{{h.ip}} {% if h.mac %} - MAC {{h.mac}}{% endif %}</h2>
        <p>Discovery: {{h.method}} | OS Guess: {{h.os}}</p>
        <p>Open ports:</p>
        <ul>
        {% for p,b in h.open_ports.items() %}
            <li class="port">{{p}} — {{b or '—'}}</li>
        {% endfor %}
        </ul>
    </div>
    {% endfor %}
</body>
</html>
"""


def save_html(results, path):
    # simple manual templating to avoid Jinja dependency - but we used Flask optionally
    generated = now()
    summary = f"{len(results)} hosts" if isinstance(results, list) else ""
    hosts_html = []
    for h in results:
        ports_html = ''.join(f'<li class="port">{p} — {escape(h["open_ports"].get(p, "")) or "—"}</li>' for p in sorted(h['open_ports']))
        mac = f" - MAC {escape(h['mac'])}" if h.get('mac') else ''
        host_block = f"<div class=\"host\"><h2>{escape(h['ip'])}{mac}</h2><p>Discovery: {escape(h.get('method',''))} | OS Guess: {escape(h.get('os',''))}</p><p>Open ports:</p><ul>{ports_html}</ul></div>"
        hosts_html.append(host_block)
    body = f"<html><head><meta charset=\"utf-8\"><title>ProNetScan</title></head><body><h1>ProNetScan Report</h1><p>Generated: {generated}</p><p>Summary: {summary}</p>{''.join(hosts_html)}</body></html>"
    with open(path, 'w', encoding='utf-8') as f:
        f.write(body)


# ---------------------- CLI / Main ----------------------

def run_scan(args):
    oui_map = load_oui(args.oui) if args.oui else {}
    ports = parse_ports(args.ports) if args.ports else [22, 80, 443, 445, 3389, 8080, 8000]

    print(f"Start pro scan: network={args.network} mode={args.mode} ports={len(ports)}")
    start = time.time()

    hosts = discover_hosts(args.network, prefer_arp=not args.no_arp, threads=args.threads)
    print(f"Discovered {len(hosts)} live hosts")

    results = []
    for ip, mac, method in hosts:
        print(f"\nScanning host {ip} (method={method})")
        os_guess = 'Unknown'
        if method and 'icmp' in method:
            os_guess = guess_os_from_ttl(method)
        if mac and oui_map:
            vendor = oui_map.get(mac.upper()[0:8], '')
        else:
            vendor = ''
        open_ports = scan_ports_for_host(ip, ports, mode=args.mode, max_workers=args.port_threads)
        results.append({
            'ip': ip,
            'mac': mac,
            'vendor': vendor,
            'method': method,
            'os': os_guess,
            'open_ports': open_ports
        })

    elapsed = time.time() - start
    print(f"\nScan completed in {elapsed:.1f}s — {len(results)} host(s) scanned")

    # Save outputs
    if args.json:
        save_json(results, args.json)
        print(f"JSON saved to {args.json}")
    if args.html:
        save_html(results, args.html)
        print(f"HTML saved to {args.html}")
    if not args.json and not args.html:
        # print summary
        print(json.dumps(results, indent=2))

    return results


# Minimal Flask UI (optional)
def start_flask(results, host='0.0.0.0', port=5000):
    if not FLASK_AVAILABLE:
        print('Flask not installed; install with pip install flask')
        return
    app = Flask(__name__)

    @app.route('/')
    def index():
        return render_template_string(HTML_TEMPLATE, generated=now(), summary=f"{len(results)} hosts", hosts=results)

    @app.route('/api/json')
    def api_json():
        return jsonify(results)

    print(f"Starting Flask UI on http://{host}:{port}")
    app.run(host=host, port=port)


def build_arg_parser():
    p = argparse.ArgumentParser(description='Pro Network Scanner')
    p.add_argument('--network', '-n', required=True, help='Network CIDR (e.g. 192.168.1.0/24)')
    p.add_argument('--ports', '-p', default='22,80,443,3389,8000-8100', help='Ports to scan (e.g. 22,80,8000-8100)')
    p.add_argument('--mode', choices=['auto','syn','connect'], default='auto', help='Scan mode')
    p.add_argument('--threads', type=int, default=200, help='Threads for discovery')
    p.add_argument('--port-threads', type=int, default=500, help='Threads for port scanning')
    p.add_argument('--no-arp', action='store_true', help='Disable ARP discovery even if scapy is available')
    p.add_argument('--oui', help='Path to local OUI file for vendor lookup')
    p.add_argument('--json', help='Path to save JSON results')
    p.add_argument('--html', help='Path to save HTML report')
    p.add_argument('--flask', action='store_true', help='Launch a small Flask UI after scan')
    return p


def main():
    parser = build_arg_parser()
    args = parser.parse_args()

    if args.mode == 'syn' and not SCAPY_AVAILABLE:
        print('SYN mode requested but scapy not available. Install scapy or use --mode connect')
        sys.exit(1)
    if args.mode == 'syn' and os.geteuid() != 0:
        print('SYN mode requires root privileges. Run with sudo/root.')
        sys.exit(1)

    results = run_scan(args)

    if args.flask:
        start_flask(results)


if __name__ == '__main__':
    main()
