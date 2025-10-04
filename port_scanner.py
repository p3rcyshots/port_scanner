#!/usr/bin/env python3

import socket
import threading
import argparse
import sys
import ipaddress
import concurrent.futures

from rich.console import Console
from rich.markdown import Markdown

try:
    import ollama  # Official Python API for Ollama
except ImportError:
    ollama = None  # Checked later if -m is used

console = Console()

HELP_TEXT = """
# TCP Port Scanner

**Features:**
- Full or fast port scan mode (`-f`) including port 554
- Automatic local subnet scanning or specific IP (`-p`)
- Ollama model interpretation for scanned ports (`-m`)
- Verbose output (`-v`)
- Thread count control (`--threads`)

**Usage Examples:**

- Scan entire local subnet all ports:  
  `python port_scanner.py`

- Fast scan known ports including 554:  
  `python port_scanner.py -f`

- Scan specific IP fast:  
  `python port_scanner.py -p 192.168.1.20 -f`

- Scan and interpret via Ollama:  
  `python port_scanner.py -p 192.168.1.20 -m ollama_model`

Use [bold]Ctrl+C[/bold] to interrupt scanning safely.
"""

def print_rich_help():
    md = Markdown(HELP_TEXT)
    console.print(md)

# Configurable defaults
DEFAULT_THREAD_COUNT = 100
FULL_PORT_RANGE = range(1, 65536)
FAST_PORTS = [
    20, 21, 22, 23, 25, 53, 67, 68, 69, 80, 110, 123, 135, 139, 143, 
    161, 162, 443, 445, 465, 514, 515, 520, 554, 631, 993, 995, 1433, 1521, 
    1701, 1900, 3306, 3389, 5432, 5900, 8080, 8443
]
SOCKET_TIMEOUT = 0.3

def discover_local_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(('8.8.8.8', 80))
        localip = s.getsockname()[0]
        s.close()
        return localip
    except Exception:
        console.print("[bold red][ERROR][/bold red] Could not detect local IP.")
        sys.exit(1)

def get_subnet_ips(local_ip):
    try:
        import ipaddress
        net = ipaddress.IPv4Network(local_ip + '/24', strict=False)
        return [str(ip) for ip in net.hosts()]
    except Exception:
        console.print("[bold red][ERROR][/bold red] Failed subnet detection.")
        sys.exit(1)

def grab_banner(ip, port):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(0.1)
            s.connect((ip, port))
            return s.recv(1024).decode(errors='ignore').strip()
    except Exception:
        return ""

def os_fingerprint(ip):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(1.0)
            s.connect((ip, 80))
            ttl = s.getsockopt(socket.IPPROTO_IP, socket.IP_TTL)
            if ttl <= 64:
                return f"Likely Linux/Unix (TTL={ttl})"
            elif ttl <= 128:
                return f"Likely Windows (TTL={ttl})"
            else:
                return f"Unknown OS (TTL={ttl})"
    except Exception:
        return "OS fingerprinting unavailable (port 80 closed or insufficient privileges)"

def scan_port(ip, port, verbose=False):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(SOCKET_TIMEOUT)
            s.connect((ip, port))
            banner = b""
            try:
                s.settimeout(0.1)
                banner = s.recv(1024)
            except Exception:
                pass
            banner_str = banner.decode(errors='ignore').strip() if banner else ""
            if verbose:
                console.print(f"[cyan][VERBOSE][/cyan] {ip}:{port} Open - Banner: {banner_str}")
            return port, banner_str
    except Exception as e:
        if verbose:
            console.print(f"[yellow][VERBOSE][/yellow] {ip}:{port} Closed/Filtered: {repr(e)}")
        return None

def scan_host(ip, args, port_range):
    open_ports = []
    cancel_event = threading.Event()

    def worker(port):
        if cancel_event.is_set():
            return None
        res = scan_port(ip, port, args.verbose)
        if res:
            open_ports.append(res)

    with concurrent.futures.ThreadPoolExecutor(max_workers=args.threads) as executor:
        futures = {executor.submit(worker, port): port for port in port_range}
        try:
            for future in concurrent.futures.as_completed(futures):
                if cancel_event.is_set():
                    break
        except KeyboardInterrupt:
            console.print("\n[bold red][INFO][/bold red] Scan interrupted by user (Ctrl+C). Cancelling...")
            cancel_event.set()
            executor.shutdown(wait=False)
            raise

    if not open_ports:
        return None

    console.print(f"\n[bold green][INFO][/bold green] Scanning host: {ip}")
    console.print(f"[bold green][SCAN DONE][/bold green] {ip} | Open ports: {len(open_ports)}")
    for port, banner in sorted(open_ports):
        if args.verbose and banner:
            console.print(f"  [bold blue][OPEN][/bold blue] {port}: {banner}")
        else:
            console.print(f"  [bold blue][OPEN][/bold blue] {port}")

    os_note = os_fingerprint(ip)
    console.print(f"  [bold magenta][OS][/bold magenta] {os_note}")

    return {'ip': ip, 'open_ports': open_ports, 'os_fingerprint': os_note}

def explain_ports_with_ollama(model_name, all_results):
    if ollama is None:
        console.print("[bold red][ERROR][/bold red] Ollama Python package not found. Please install ollama.")
        sys.exit(1)
    try:
        prompt = "Given these open ports and banners, explain what services and risks they pose:\n"
        for host_result in all_results:
            prompt += f"\nHost: {host_result['ip']}\n"
            for port, banner in host_result['open_ports']:
                prompt += f"  Port {port}: {banner}\n"
        console.print("\n[bold green][INFO][/bold green] Sending to Ollama for detailed service/risk assessment...")
        response = ollama.generate(model=model_name, prompt=prompt)
        console.print("\n[bold cyan][OLLAMA OUTPUT][/bold cyan]\n")
        console.print(response['response'])
    except Exception as e:
        console.print(f"[bold red][ERROR][/bold red] Ollama inference failed: {e}")

def main():
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument('-p', metavar="IP", help="Scan a specific IP address instead of local subnet.")
    parser.add_argument('-m', metavar="OLLAMA_MODEL", help="Interpret found ports using specified Ollama model.")
    parser.add_argument('-v', '--verbose', action='store_true', help="Verbose output (detailed banners/errors).")
    parser.add_argument('-f', '--fast', action='store_true', help="Fast scan: only common known ports + 554.")
    parser.add_argument('--threads', type=int, default=DEFAULT_THREAD_COUNT, help="Number of concurrent threads (default: 100).")
    parser.add_argument('-h', '--help', action='store_true', help="Show this help message and exit.")
    args = parser.parse_args()

    if args.help:
        print_rich_help()
        sys.exit(0)

    port_range = FAST_PORTS if args.fast else FULL_PORT_RANGE

    try:
        to_scan = []
        if args.p:
            to_scan = [args.p]
        else:
            local_ip = discover_local_ip()
            to_scan = get_subnet_ips(local_ip)

        all_results = []
        for ip in to_scan:
            result = scan_host(ip, args, port_range)
            if result:
                all_results.append(result)

        if args.m and all_results:
            explain_ports_with_ollama(args.m, all_results)

    except KeyboardInterrupt:
        console.print("\n[bold red][INFO][/bold red] Scan interrupted by user (Ctrl+C). Exiting cleanly.")
        sys.exit(0)
    except Exception as exc:
        console.print(f"[bold red][ERROR][/bold red] {exc}")
        sys.exit(1)

def print_rich_help():
    md = Markdown(HELP_TEXT)
    console.print(md)

HELP_TEXT = """
# TCP Port Scanner

Created by: Prashant Saxena  
https://github.com/p3rcyshots

**Features:**
- Full or fast port scan mode (`-f`) including port 554
- Automatic local subnet scanning or specific IP (`-p`)
- Ollama model interpretation for scanned ports (`-m`)
- Verbose output (`-v`)
- Thread count control (`--threads`)

**Usage Examples:**

- Scan entire local subnet all ports:  
  `python port_scanner.py`

- Fast scan known ports including 554:  
  `python port_scanner.py -f`

- Scan specific IP fast:  
  `python port_scanner.py -p 192.168.1.20 -f`

- Scan and interpret via Ollama:  
  `python port_scanner.py -p 192.168.1.20 -m ollama_model`

Use Ctrl+C to interrupt scanning safely.
"""


if __name__ == "__main__":
    main()
