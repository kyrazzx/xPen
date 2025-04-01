import socket
import requests
import threading
import queue
import sys
import os
from datetime import datetime
from urllib.parse import urlparse
import asyncio
import aiohttp
import subprocess
import struct
import time

try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn
    from rich.table import Table
    from rich.theme import Theme
except ImportError:
    print("ERROR : 'rich' and/or 'requests' are not installed.")
    print("Please install with: pip install rich requests aiohttp dnspython")
    sys.exit(1)

custom_theme = Theme({
    "info": "bold cyan",
    "warning": "yellow",
    "danger": "bold red",
    "success": "green",
    "primary": "bold dark_red",
    "secondary": "magenta",
    "accent": "red",
    "neutral": "white",
    "dim": "#a9a9a9",
    "bold": "bold",
    "italic": "italic",
    "red": "red",
    "green": "green",
    "yellow": "yellow",
    "blue": "blue",
    "magenta": "magenta",
    "cyan": "cyan",
    "dark_red": "#800000",
})

console = Console(theme=custom_theme)
NUMBER_OF_SCAN_THREADS = 100
DEFAULT_TIMEOUT = 1
IP_INFO_API = "https://ipinfo.io/{ip}/json"

def display_banner():
    os.system('cls' if os.name == 'nt' else 'clear')
    title = "[bold red]xPen[/bold red]"
    author = "[italic red]Made by Kyra[/italic red]"
    version = "[italic red]v1.0.0[/italic red]"
    panel_content = f"{title}\n{author}\n{version}"
    console.print(Panel(panel_content, title="[primary]Welcome[/primary]", border_style="red"))
    console.print("\n[warning]WARNING:[/warning] Use this tool responsibly and legally.")
    console.print("Only scan systems for which you have explicit authorization.\n")

def get_user_input(prompt, expected_type=str, validation_func=None):
    while True:
        try:
            value = console.input(f"[primary]>[/primary] {prompt} : ")
            if not value:
                console.print("[warning]Empty input not allowed.[/warning]")
                continue
            converted_value = expected_type(value)
            if validation_func and not validation_func(converted_value):
                console.print("[warning]Invalid input.[/warning]")
                continue
            return converted_value
        except ValueError:
            console.print(f"[danger]Error: Please enter a value of type {expected_type.__name__}.[/danger]")
        except KeyboardInterrupt:
            console.print("\n[warning]User interruption. Returning to menu.[/warning]")
            return None

def save_results(module_name, results):
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"results_{module_name}_{timestamp}.txt"
    try:
        with open(filename, 'w') as f:
            f.write(f"--- {module_name} results ({timestamp}) ---\n\n")
            if isinstance(results, list):
                for result in results:
                    f.write(str(result) + "\n")
            elif isinstance(results, dict):
                for key, value in results.items():
                    f.write(f"{key}: {value}\n")
            else:
                f.write(str(results) + "\n")
        console.print(f"[success]Results saved to '{filename}'[/success]")
    except Exception as e:
        console.print(f"[danger]Error saving results to file: {e}[/danger]")

class PortScanner:
    def __init__(self, target_ip, ports_to_scan, timeout=DEFAULT_TIMEOUT, scan_type='tcp'):
        self.target_ip = target_ip
        self.ports_to_scan = ports_to_scan
        self.open_ports = []
        self.port_queue = queue.Queue()
        self.lock = threading.Lock()
        self.timeout = timeout
        self.scan_type = scan_type.lower()
        if self.scan_type not in ['tcp', 'udp']:
            self.scan_type = 'tcp'
            console.print("[warning]Invalid scan type specified, defaulting to TCP.[/warning]")

    def _validate_ip(self):
        try:
            socket.inet_aton(self.target_ip)
            return True
        except socket.error:
            console.print(f"[danger]Error: Invalid IP address: {self.target_ip}[/danger]")
            return False

    def _parse_ports(self):
        valid_ports = []
        try:
            if '-' in self.ports_to_scan:
                start, end = map(int, self.ports_to_scan.split('-'))
                if 0 < start <= end <= 65535:
                    valid_ports = list(range(start, end + 1))
                else:
                    raise ValueError("Invalid port range")
            elif ',' in self.ports_to_scan:
                valid_ports = [int(p.strip()) for p in self.ports_to_scan.split(',')]
                if not all(0 < p <= 65535 for p in valid_ports):
                    raise ValueError("Invalid port list")
            else:
                port = int(self.ports_to_scan)
                if 0 < port <= 65535:
                    valid_ports = [port]
                else:
                    raise ValueError("Invalid port")
            return valid_ports
        except ValueError as e:
            console.print(f"[danger]Error in port format ({e}): {self.ports_to_scan}[/danger]")
            console.print("[warning]Accepted formats: 80 | 21,22,80 | 1-1024[/warning]")
            return None

    def _scan_tcp_port(self, port):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(self.timeout)
                result = sock.connect_ex((self.target_ip, port))
                if result == 0:
                    with self.lock:
                        self.open_ports.append(port)
                        try:
                            sock.send(b'HEAD / HTTP/1.0\r\n\r\n')
                            banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
                            if banner:
                                console.print(f"[success]Port {port:<5} Open[/success] - Banner: [cyan]{banner.splitlines()[0] if banner else 'N/A'}[/cyan]")
                            else:
                                console.print(f"[success]Port {port:<5} Open[/success]")
                        except (socket.timeout, ConnectionResetError):
                            console.print(f"[success]Port {port:<5} Open[/success] (No banner or timeout)")
                        except Exception:
                            console.print(f"[success]Port {port:<5} Open[/success] (Banner error)")
        except socket.gaierror:
            pass
        except socket.error:
            pass
        except Exception as e:
            console.print(f"[danger]Unexpected error scanning port {port}: {e}[/danger]")

    def _scan_udp_port(self, port):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                sock.settimeout(self.timeout)
                try:
                    sock.sendto(b'Some data', (self.target_ip, port))
                    _, _ = sock.recvfrom(1024)
                    with self.lock:
                        self.open_ports.append(port)
                        console.print(f"[success]Port {port:<5} Open/Filtered (UDP response)[/success]")
                except socket.timeout:
                    console.print(f"[warning]Port {port:<5} Open|Filtered (No UDP response within timeout)[/warning]")
                except Exception as e:
                    console.print(f"[danger]Error during UDP scan on port {port}: {e}[/danger]")
        except socket.gaierror:
            pass
        except socket.error as e:
            console.print(f"[danger]Socket error during UDP scan on port {port}: {e}[/danger]")
        except Exception as e:
            console.print(f"[danger]Unexpected error scanning UDP port {port}: {e}[/danger]")


    def _worker(self):
        while not self.port_queue.empty():
            port = self.port_queue.get()
            if self.scan_type == 'tcp':
                self._scan_tcp_port(port)
            elif self.scan_type == 'udp':
                self._scan_udp_port(port)
            self.port_queue.task_done()

    def run_scan(self):
        if not self._validate_ip():
            return

        port_list = self._parse_ports()
        if not port_list:
            return

        console.print(f"\n[info]Launching {self.scan_type.upper()} port scan on {self.target_ip} ({len(port_list)} ports)...[/info]")
        start_time = datetime.now()

        for port in port_list:
            self.port_queue.put(port)

        threads = []
        for _ in range(min(NUMBER_OF_SCAN_THREADS, len(port_list))):
            thread = threading.Thread(target=self._worker, daemon=True)
            threads.append(thread)
            thread.start()

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            TextColumn("({task.completed}/{task.total})"),
            console=console,
            transient=True
        ) as progress:
            task = progress.add_task("[yellow]Scanning...", total=len(port_list))
            while not self.port_queue.empty():
                progress.update(task, completed=len(port_list) - self.port_queue.qsize())

            self.port_queue.join()
            progress.update(task, completed=len(port_list))

        end_time = datetime.now()
        duration = end_time - start_time

        console.print(f"\n[info]Scan finished in {duration.total_seconds():.2f} seconds.[/info]")

        if self.open_ports:
            table = Table(title=f"Open Ports on {self.target_ip}", show_header=True, header_style="bold magenta")
            table.add_column("Port", style="dim", width=12)
            table.add_column("Protocol", style="blue", width=10)
            table.add_column("Common Service", style="green")

            common_services = {
                21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
                80: "HTTP", 110: "POP3", 135: "RPC", 139: "NetBIOS", 143: "IMAP",
                443: "HTTPS", 445: "SMB", 993: "IMAPS", 995: "POP3S",
                1723: "PPTP", 3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL",
                5900: "VNC", 8080: "HTTP Alt", 8443: "HTTPS Alt"
            }

            for port in sorted(self.open_ports):
                service = common_services.get(port, "Unknown")
                table.add_row(str(port), self.scan_type.upper(), service)
            console.print(table)
            save_results(f"port_scan_{self.target_ip}", {"open_ports": sorted(self.open_ports), "scan_type": self.scan_type})
        else:
            console.print("[warning]No open ports found in the specified range.[/warning]")

class DirectoryBuster:
    def __init__(self, base_url, wordlist_paths, timeout=DEFAULT_TIMEOUT, user_agent='UltimatePentestTool/1.0', http_method='GET'):
        self.base_url = self._format_url(base_url)
        self.wordlist_paths = wordlist_paths if isinstance(wordlist_paths, list) else [wordlist_paths]
        self.found_paths = []
        self.timeout = timeout
        self.user_agent = user_agent
        self.http_method = http_method.upper()
        if self.http_method not in ['GET', 'HEAD']:
            self.http_method = 'GET'
            console.print("[warning]Invalid HTTP method specified, defaulting to GET.[/warning]")

    def _format_url(self, url):
        if not url.startswith(('http://', 'https://')):
            console.print("[warning]URL provided without schema (http/https), adding 'http://' by default.[/warning]")
            url = 'http://' + url
        if not url.endswith('/'):
            url += '/'
        return url

    async def _verify_path(self, session, path):
        test_url = self.base_url + path
        try:
            headers = {'User-Agent': self.user_agent}
            async with session.request(self.http_method, test_url, timeout=self.timeout, allow_redirects=True, headers=headers) as response:
                status_code = response.status
                if status_code == 200:
                    console.print(f"[success][+] Found (200): {test_url}[/success]")
                    self.found_paths.append((test_url, status_code))
                elif status_code == 403:
                    console.print(f"[warning][!] Forbidden (403): {test_url}[/warning]")
                    self.found_paths.append((test_url, status_code))
                elif status_code in [301, 302, 307, 308]:
                    location = response.headers.get('Location', '')
                    console.print(f"[info][>] Redirect ({status_code}): {test_url} -> {location}[/info]")
                    self.found_paths.append((test_url, status_code))
                elif status_code == 401:
                    console.print(f"[secondary][-] Unauthorized (401): {test_url}[/secondary]")
                    self.found_paths.append((test_url, status_code))

        except aiohttp.ClientError:
            pass
        except asyncio.TimeoutError:
            pass
        except Exception as e:
            console.print(f"[danger]Unexpected error for {test_url}: {e}[/danger]")

    async def _process_wordlist(self, session, wordlist_path, progress):
        if not os.path.exists(wordlist_path):
            console.print(f"[danger]Error: Wordlist file '{wordlist_path}' does not exist.[/danger]")
            return 0
        count = 0
        try:
            with open(wordlist_path, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    path = line.strip()
                    if path and not path.startswith('#'):
                        await self._verify_path(session, path)
                        count += 1
                        progress.advance(progress.tasks[0].id)
        except FileNotFoundError:
            console.print(f"[danger]Error: Wordlist file '{wordlist_path}' not found.[/danger]")
        except Exception as e:
            console.print(f"[danger]Error reading wordlist '{wordlist_path}': {e}[/danger]")
        return count

    async def run_bruteforce(self):
        if not self.base_url:
            console.print("[danger]Invalid base URL.[/danger]")
            return

        console.print(f"\n[info]Launching directory brute-force on {self.base_url}[/info]")
        console.print(f"[info]Using wordlists: {', '.join(self.wordlist_paths)}[/info]")
        console.print(f"[info]HTTP Method: {self.http_method}[/info]")
        start_time = datetime.now()

        total_lines = 0
        for path in self.wordlist_paths:
            try:
                with open(path, 'r', encoding='utf-8', errors='ignore') as f:
                    for _ in f:
                        total_lines += 1
            except FileNotFoundError:
                console.print(f"[danger]Warning: Wordlist file '{path}' not found.[/danger]")
            except Exception as e:
                console.print(f"[danger]Error reading wordlist '{path}': {e}[/danger]")

        async with aiohttp.ClientSession() as session:
            with Progress(
                TextColumn("[progress.description]{task.description}"),
                BarColumn(),
                TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
                TextColumn("({task.completed}/{task.total} words tested)"),
                console=console,
                transient=False
            ) as progress:
                task = progress.add_task("[yellow]Bruteforcing...", total=total_lines)
                for wordlist_path in self.wordlist_paths:
                    await self._process_wordlist(session, wordlist_path, progress)

        end_time = datetime.now()
        duration = end_time - start_time
        console.print(f"\n[info]Brute-force finished in {duration.total_seconds():.2f} seconds.[/info]")

        if self.found_paths:
            console.print("\n[bold magenta]Brute-force Results:[/bold magenta]")
            for url, status in self.found_paths:
                color = "green" if status == 200 else ("yellow" if status == 403 else ("cyan" if status in [301, 302, 307, 308] else "magenta"))
                console.print(f"  [[{color}]{status}[/{color}]] {url}")
            save_results(f"dir_brute_{urlparse(self.base_url).netloc}", self.found_paths)
        else:
            console.print("[warning]No directories or files found with the provided wordlists.[/warning]")

class DnsEnumerator:
    def __init__(self, target):
        self.target = target
        self.console = Console(theme=custom_theme)

    def enumerate_records(self, record_type):
        try:
            result = socket.getaddrinfo(self.target, None, 0, 0, 0, socket.AI_CANONNAME)
            for r in result:
                if record_type == 'A' and r[0] == socket.AF_INET:
                    return f"A Record: {r[4][0]}"
                elif record_type == 'AAAA' and r[0] == socket.AF_INET6:
                    return f"AAAA Record: {r[4][0]}"
                elif record_type == 'CNAME' and r[3]:
                    return f"CNAME Record: {r[3]}"
            return f"{record_type} Record not found."
        except socket.gaierror:
            return f"Could not resolve {self.target}"

    def get_mx_records(self):
        try:
            import dns.resolver
            answers = dns.resolver.resolve(self.target, 'MX')
            mx_records = [f"MX Record: {r.exchange} (Preference: {r.preference})" for r in answers]
            return mx_records if mx_records else "No MX records found."
        except ImportError:
            return "Error: 'dnspython' library is required for MX record lookup. Please install it with: pip install dnspython"
        except dns.resolver.NXDOMAIN:
            return f"No DNS record found for {self.target}"
        except Exception as e:
            return f"An error occurred while fetching MX records: {e}"

    def get_ns_records(self):
        try:
            import dns.resolver
            answers = dns.resolver.resolve(self.target, 'NS')
            ns_records = [f"NS Record: {r.target}" for r in answers]
            return ns_records if ns_records else "No NS records found."
        except ImportError:
            return "Error: 'dnspython' library is required for NS record lookup. Please install it with: pip install dnspython"
        except dns.resolver.NXDOMAIN:
            return f"No DNS record found for {self.target}"
        except Exception as e:
            return f"An error occurred while fetching NS records: {e}"

    def get_soa_record(self):
        try:
            import dns.resolver
            answers = dns.resolver.resolve(self.target, 'SOA')
            soa_records = [f"SOA Record: {r.mname} {r.rname} {r.serial} {r.refresh} {r.retry} {r.expire} {r.minimum}" for r in answers]
            return soa_records if soa_records else "No SOA record found."
        except ImportError:
            return "Error: 'dnspython' library is required for SOA record lookup. Please install it with: pip install dnspython"
        except dns.resolver.NXDOMAIN:
            return f"No DNS record found for {self.target}"
        except Exception as e:
            return f"An error occurred while fetching SOA record: {e}"

    def get_txt_records(self):
        try:
            import dns.resolver
            answers = dns.resolver.resolve(self.target, 'TXT')
            txt_records = [f"TXT Record: {' '.join(r.strings)}" for r in answers]
            return txt_records if txt_records else "No TXT records found."
        except ImportError:
            return "Error: 'dnspython' library is required for TXT record lookup. Please install it with: pip install dnspython"
        except dns.resolver.NXDOMAIN:
            return f"No DNS record found for {self.target}"
        except Exception as e:
            return f"An error occurred while fetching TXT records: {e}"

    def run(self):
        console.print(f"\n[primary]--- DNS Enumeration for {self.target} ---[/primary]")
        a_record = self.enumerate_records('A')
        console.print(f"[cyan]{a_record}[/cyan]")
        aaaa_record = self.enumerate_records('AAAA')
        if "not found" not in aaaa_record:
            console.print(f"[cyan]{aaaa_record}[/cyan]")
        cname_record = self.enumerate_records('CNAME')
        if "not found" not in cname_record and "Could not resolve" not in cname_record:
            console.print(f"[cyan]{cname_record}[/cyan]")
        mx_records = self.get_mx_records()
        if isinstance(mx_records, list):
            for record in mx_records:
                console.print(f"[green]{record}[/green]")
        else:
            console.print(f"[yellow]{mx_records}[/yellow]")
        ns_records = self.get_ns_records()
        if isinstance(ns_records, list):
            for record in ns_records:
                console.print(f"[blue]{record}[/blue]")
        else:
            console.print(f"[yellow]{ns_records}[/yellow]")
        soa_record = self.get_soa_record()
        if isinstance(soa_record, list):
            for record in soa_record:
                console.print(f"[magenta]{record}[/magenta]")
        else:
            console.print(f"[yellow]{soa_record}[/yellow]")
        txt_records = self.get_txt_records()
        if isinstance(txt_records, list):
            for record in txt_records:
                console.print(f"[dim]{record}[/dim]")
        else:
            console.print(f"[yellow]{txt_records}[/yellow]")
        results = {
            "A Record": a_record,
            "AAAA Record": aaaa_record,
            "CNAME Record": cname_record,
            "MX Records": mx_records,
            "NS Records": ns_records,
            "SOA Record": soa_record,
            "TXT Records": txt_records
        }
        save_results(f"dns_enum_{self.target}", results)

class SubdomainEnumerator:
    def __init__(self, target_domain, wordlist_path, timeout=DEFAULT_TIMEOUT):
        self.target_domain = target_domain
        self.wordlist_path = wordlist_path
        self.found_subdomains = set()
        self.timeout = timeout
        self.console = Console(theme=custom_theme)

    async def _check_subdomain(self, session, subdomain):
        url = f"http://{subdomain}.{self.target_domain}"
        try:
            async with session.get(url, timeout=self.timeout, allow_redirects=False) as response:
                if response.status != 404:
                    with self.console.lock:
                        if subdomain not in self.found_subdomains:
                            self.found_subdomains.add(subdomain)
                            self.console.print(f"[success]Found subdomain: [bold cyan]{url}[/bold cyan] (Status: {response.status})[/success]")
        except aiohttp.ClientError:
            pass
        except asyncio.TimeoutError:
            pass
        except Exception as e:
            pass

    async def run_enumeration(self):
        if not os.path.exists(self.wordlist_path):
            self.console.print(f"[danger]Error: Subdomain wordlist '{self.wordlist_path}' not found.[/danger]")
            return

        self.console.print(f"\n[info]Starting subdomain enumeration for {self.target_domain} using wordlist '{self.wordlist_path}'[/info]")
        start_time = datetime.now()

        try:
            with open(self.wordlist_path, 'r') as f:
                subdomains = [line.strip() for line in f if line.strip() and not line.startswith('#')]
        except Exception as e:
            self.console.print(f"[danger]Error reading subdomain wordlist: {e}[/danger]")
            return

        async with aiohttp.ClientSession() as session:
            tasks = [self._check_subdomain(session, subdomain) for subdomain in subdomains]
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                BarColumn(),
                TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
                TextColumn(f"({len(self.found_subdomains)} found / {len(subdomains)} tested)"),
                console=self.console,
                transient=True
            ) as progress:
                task = progress.add_task("[yellow]Enumerating subdomains...", total=len(tasks))
                for future in asyncio.as_completed(tasks):
                    await future
                    progress.advance(task)

        end_time = datetime.now()
        duration = end_time - start_time
        self.console.print(f"\n[info]Subdomain enumeration finished in {duration.total_seconds():.2f} seconds.[/info]")

        if self.found_subdomains:
            self.console.print("\n[bold magenta]Found Subdomains:[/bold magenta]")
            for subdomain in sorted(self.found_subdomains):
                self.console.print(f"  [green]{subdomain}.{self.target_domain}[/green]")
            save_results(f"subdomain_enum_{self.target_domain}", sorted(self.found_subdomains))
        else:
            self.console.print("[warning]No subdomains found with the provided wordlist.[/warning]")

class HttpHeaderAnalyzer:
    def __init__(self, target_url, timeout=DEFAULT_TIMEOUT, user_agent='UltimatePentestTool/1.0'):
        self.target_url = self._format_url(target_url)
        self.timeout = timeout
        self.user_agent = user_agent
        self.console = Console(theme=custom_theme)

    def _format_url(self, url):
        if not url.startswith(('http://', 'https://')):
            url = 'http://' + url
        return url

    async def analyze_headers(self):
        console.print(f"\n[info]Analyzing HTTP headers for {self.target_url}[/info]")
        try:
            headers = {'User-Agent': self.user_agent}
            async with aiohttp.ClientSession() as session:
                async with session.head(self.target_url, timeout=self.timeout, allow_redirects=True, headers=headers) as response:
                    console.print("[bold magenta]Response Headers:[/bold magenta]")
                    headers_data = {}
                    for key, value in response.headers.items():
                        console.print(f"[cyan]{key}:[/cyan] [green]{value}[/green]")
                        headers_data[key] = value
                    save_results(f"http_headers_{urlparse(self.target_url).netloc}", headers_data)
        except aiohttp.ClientError as e:
            console.print(f"[danger]Error fetching URL: {e}[/danger]")
        except asyncio.TimeoutError:
            console.print(f"[warning]Timeout occurred while fetching {self.target_url}[/warning]")
        except Exception as e:
            console.print(f"[danger]An unexpected error occurred: {e}[/danger]")

    def run(self):
        asyncio.run(self.analyze_headers())

class WhoisLookup:
    def __init__(self, target_domain):
        self.target_domain = target_domain
        self.console = Console(theme=custom_theme)

    def run(self):
        console.print(f"\n[primary]--- WHOIS Lookup for {self.target_domain} ---[/primary]")
        try:
            import whois
            w = whois.whois(self.target_domain)
            if w:
                console.print(f"[bold magenta]WHOIS Information:[/bold magenta]")
                for key, value in w.items():
                    if value:
                        console.print(f"[cyan]{key}:[/cyan] [green]{value}[/green]")
                save_results(f"whois_{self.target_domain}", w)
            else:
                console.print(f"[warning]No WHOIS information found for {self.target_domain}[/warning]")
        except ImportError:
            console.print("[danger]Error: 'whois' library is required. Please install it with: pip install python-whois[/danger]")
        except whois.exceptions.WhoisError as e:
            console.print(f"[warning]WHOIS lookup failed: {e}[/warning]")
        except Exception as e:
            console.print(f"[danger]An unexpected error occurred during WHOIS lookup: {e}[/danger]")

class ReverseIpLookup:
    def __init__(self, target_ip, timeout=10):
        self.target_ip = target_ip
        self.timeout = timeout
        self.console = Console(theme=custom_theme)

    async def run(self):
        console.print(f"\n[primary]--- Reverse IP Lookup for {self.target_ip} ---[/primary]")
        url = f"https://api.hackertarget.com/reverseiplookup/?q={self.target_ip}"
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(url, timeout=self.timeout) as response:
                    if response.status == 200:
                        data = await response.text()
                        domains = [line.strip() for line in data.splitlines() if line.strip()]
                        if domains:
                            console.print("[bold magenta]Domains found on this IP:[/bold magenta]")
                            for domain in domains:
                                console.print(f"[green]{domain}[/green]")
                            save_results(f"reverse_ip_{self.target_ip}", domains)
                        else:
                            console.print("[warning]No domains found for this IP address.[/warning]")
                    else:
                        console.print(f"[warning]Reverse IP lookup failed with status code: {response.status}[/warning]")
        except aiohttp.ClientError as e:
            console.print(f"[danger]Error during reverse IP lookup: {e}[/danger]")
        except asyncio.TimeoutError:
            console.print("[warning]Timeout during reverse IP lookup.[/warning]")
        except Exception as e:
            console.print(f"[danger]An unexpected error occurred during reverse IP lookup: {e}[/danger]")

class GeoIpLookup:
    def __init__(self, target_ip):
        self.target_ip = target_ip
        self.console = Console(theme=custom_theme)

    async def run(self):
        console.print(f"\n[primary]--- GeoIP Lookup for {self.target_ip} ---[/primary]")
        url = IP_INFO_API.format(ip=self.target_ip)
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(url) as response:
                    if response.status == 200:
                        data = await response.json()
                        console.print("[bold magenta]GeoIP Information:[/bold magenta]")
                        for key, value in data.items():
                            console.print(f"[cyan]{key}:[/cyan] [green]{value}[/green]")
                        save_results(f"geoip_{self.target_ip}", data)
                    elif response.status == 404:
                        console.print(f"[warning]Could not find GeoIP information for {self.target_ip}[/warning]")
                    else:
                        console.print(f"[warning]GeoIP lookup failed with status code: {response.status}[/warning]")
        except aiohttp.ClientError as e:
            console.print(f"[danger]Error during GeoIP lookup: {e}[/danger]")
        except asyncio.TimeoutError:
            console.print("[warning]Timeout during GeoIP lookup.[/warning]")
        except Exception as e:
            console.print(f"[danger]An unexpected error occurred during GeoIP lookup: {e}[/danger]")

class PingSweep:
    def __init__(self, network, timeout=1):
        self.network = network
        self.timeout = timeout
        self.console = Console(theme=custom_theme)
        self.live_hosts = []

    async def _ping(self, ip):
        param = '-n' if sys.platform.lower() == 'win32' else '-c'
        command = ['ping', param, '1', '-w', str(int(self.timeout * 1000)), ip]
        process = await asyncio.create_subprocess_exec(
            *command, stdout=subprocess.PIPE, stderr=subprocess.PIPE
        )
        stdout, _ = await process.communicate()
        if process.returncode == 0:
            with self.console.lock:
                self.live_hosts.append(ip)
                self.console.print(f"[success]Host is up: [bold green]{ip}[/bold green][/success]")

    async def run(self):
        console.print(f"\n[primary]--- Ping Sweep for {self.network} ---[/primary]")
        try:
            ip_parts = self.network.split('.')
            if len(ip_parts) != 4 or not all(0 <= int(part) <= 255 for part in ip_parts[:3]) or ip_parts[3] != '0/24':
                console.print("[danger]Invalid network format. Please use format like '192.168.1.0/24'.[/danger]")
                return

            base_ip = '.'.join(ip_parts[:3])
            tasks = []
            for i in range(1, 255):
                ip = f"{base_ip}.{i}"
                tasks.append(self._ping(ip))

            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                BarColumn(),
                TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
                TextColumn(f"({len(self.live_hosts)} found / {len(tasks)} tested)"),
                console=self.console,
                transient=True
            ) as progress:
                task = progress.add_task("[yellow]Scanning network...", total=len(tasks))
                for future in asyncio.as_completed(tasks):
                    await future
                    progress.advance(task)

            if self.live_hosts:
                console.print("\n[bold magenta]Live Hosts:[/bold magenta]")
                for host in sorted(self.live_hosts):
                    console.print(f"[green]{host}[/green]")
                save_results(f"ping_sweep_{self.network.replace('/', '_')}", self.live_hosts)
            else:
                console.print("[warning]No live hosts found in the specified network.[/warning]")

        except Exception as e:
            console.print(f"[danger]An error occurred during ping sweep: {e}[/danger]")

class Traceroute:
    def __init__(self, target):
        self.target = target
        self.console = Console(theme=custom_theme)

    async def run(self):
        console.print(f"\n[primary]--- Traceroute to {self.target} ---[/primary]")
        param = '-n' if sys.platform.lower() == 'win32' else ''
        command = ['traceroute', param, self.target]
        try:
            process = await asyncio.create_subprocess_exec(
                *command, stdout=subprocess.PIPE, stderr=subprocess.PIPE
            )
            stdout, stderr = await process.communicate()
            if stdout:
                console.print("[bold magenta]Traceroute Output:[/bold magenta]")
                output = stdout.decode('utf-8', errors='ignore')
                console.print(output)
                save_results(f"traceroute_{self.target.replace('.', '_')}", output.splitlines())
            elif stderr:
                error_output = stderr.decode('utf-8', errors='ignore')
                console.print(f"[warning]Traceroute encountered an issue:\n{error_output}[/warning]")
            else:
                console.print("[info]Traceroute completed without output.[/info]")
        except FileNotFoundError:
            console.print("[danger]Error: 'traceroute' command not found. Make sure it's in your system's PATH.[/danger]")
        except Exception as e:
            console.print(f"[danger]An error occurred during traceroute: {e}[/danger]")

class ReverseDnsLookup:
    def __init__(self, target_ip):
        self.target_ip = target_ip
        self.console = Console(theme=custom_theme)

    def run(self):
        console.print(f"\n[primary]--- Reverse DNS Lookup for {self.target_ip} ---[/primary]")
        try:
            hostname, _, _ = socket.gethostbyaddr(self.target_ip)
            console.print(f"[success]Hostname for {self.target_ip}: [bold green]{hostname}[/bold green][/success]")
            save_results(f"reverse_dns_{self.target_ip.replace('.', '_')}", {"ip": self.target_ip, "hostname": hostname})
        except socket.herror:
            console.print(f"[warning]No hostname found for {self.target_ip}[/warning]")
        except socket.gaierror:
            console.print(f"[danger]Invalid IP address: {self.target_ip}[/danger]")
        except Exception as e:
            console.print(f"[danger]An unexpected error occurred during reverse DNS lookup: {e}[/danger]")

class AsnLookup:
    def __init__(self, target_ip, timeout=10):
        self.target_ip = target_ip
        self.timeout = timeout
        self.console = Console(theme=custom_theme)

    async def run(self):
        console.print(f"\n[primary]--- ASN Lookup for {self.target_ip} ---[/primary]")
        url = IP_INFO_API.format(ip=self.target_ip)
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(url, timeout=self.timeout) as response:
                    if response.status == 200:
                        data = await response.json()
                        if 'asn' in data:
                            console.print(f"[success]ASN for {self.target_ip}: [bold green]{data['asn']} ({data.get('org', 'N/A')})[/bold green][/success]")
                            save_results(f"asn_lookup_{self.target_ip.replace('.', '_')}", {"ip": self.target_ip, "asn": data['asn'], "organization": data.get('org', 'N/A')})
                        else:
                            console.print(f"[warning]ASN information not found for {self.target_ip}[/warning]")
                    else:
                        console.print(f"[warning]ASN lookup failed with status code: {response.status}[/warning]")
        except aiohttp.ClientError as e:
            console.print(f"[danger]Error during ASN lookup: {e}[/danger]")
        except asyncio.TimeoutError:
            console.print("[warning]Timeout during ASN lookup.[/warning]")
        except Exception as e:
            console.print(f"[danger]An unexpected error occurred during ASN lookup: {e}[/danger]")

class TcpSynScanner:
    def __init__(self, target_ip, ports_to_scan, timeout=DEFAULT_TIMEOUT):
        self.target_ip = target_ip
        self.ports_to_scan = self._parse_ports(ports_to_scan)
        self.timeout = timeout
        self.console = Console(theme=custom_theme)
        self.open_ports = []

    def _parse_ports(self, ports_str):
        valid_ports = []
        try:
            if '-' in ports_str:
                start, end = map(int, ports_str.split('-'))
                if 0 < start <= end <= 65535:
                    valid_ports = list(range(start, end + 1))
            elif ',' in ports_str:
                valid_ports = [int(p.strip()) for p in ports_str.split(',')]
                if not all(0 < p <= 65535 for p in valid_ports):
                    raise ValueError("Invalid port list")
            else:
                port = int(ports_str)
                if 0 < port <= 65535:
                    valid_ports = [port]
            return valid_ports
        except ValueError as e:
            console.print(f"[danger]Error in port format ({e}): {ports_str}[/danger]")
            console.print("[warning]Accepted formats: 80 | 21,22,80 | 1-1024[/warning]")
            return None

    async def _scan_port(self, port):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP) as sock:
                sock.settimeout(self.timeout)
                sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
                src_port = 54321
                ip_header = struct.pack('!BBHHHBBH4s4s',
                                       0x45, 0, 40, 0, 0, 0, 0, 0, 6, 0,
                                       socket.inet_aton('0.0.0.0'), socket.inet_aton(self.target_ip))
                tcp_header = struct.pack('!HHLLBBHHH',
                                        src_port, port, 0, 0, 5 << 4, 0, 0, 0, 0)
                tcp_checksum = self._checksum(ip_header + tcp_header)
                tcp_header = struct.pack('!HHLLBBHHH',
                                        src_port, port, 0, 0, 5 << 4, 0, tcp_checksum, 0, 0)
                packet = ip_header + tcp_header
                sock.sendto(packet, (self.target_ip, port))
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as connect_sock:
                    connect_sock.settimeout(self.timeout)
                    result = connect_sock.connect_ex((self.target_ip, port))
                    if result == 0:
                        with self.console.lock:
                            if port not in self.open_ports:
                                self.open_ports.append(port)
                                self.console.print(f"[success]Port {port:<5} Open (SYN Scan)[/success]")

        except socket.gaierror:
            pass
        except socket.error as e:
            if e.errno not in [1, 13]:
                self.console.print(f"[danger]Error scanning port {port}: {e}[/danger]")
        except Exception as e:
            self.console.print(f"[danger]Unexpected error scanning port {port}: {e}[/danger]")

    def _checksum(self, data):
        s = 0
        n = len(data) % 2
        for i in range(0, len(data)-n, 2):
            s += ord(data[i]) + (ord(data[i+1]) << 8)
        if n:
            s += ord(data[len(data)-1])
        while (s >> 16):
            s = (s & 0xFFFF) + (s >> 16)
        s = ~s & 0xffff
        return s

    async def run_scan(self):
        console.print("[warning]TCP SYN Scan requires root privileges on most systems.[/warning]")
        if self.ports_to_scan is None:
            return

        console.print(f"\n[info]Launching TCP SYN port scan on {self.target_ip} ({len(self.ports_to_scan)} ports)...[/info]")
        start_time = datetime.now()
        tasks = [self._scan_port(port) for port in self.ports_to_scan]

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            TextColumn(f"({len(self.open_ports)} found / {len(self.ports_to_scan)} tested)"),
            console=self.console,
            transient=True
        ) as progress:
            task = progress.add_task("[yellow]Scanning...", total=len(tasks))
            for future in asyncio.as_completed(tasks):
                await future
                progress.advance(task)

        end_time = datetime.now()
        duration = end_time - start_time
        console.print(f"\n[info]Scan finished in {duration.total_seconds():.2f} seconds.[/info]")

        if self.open_ports:
            console.print("\n[bold magenta]Open Ports (SYN Scan):[/bold magenta]")
            for port in sorted(self.open_ports):
                console.print(f"[green]{port}[/green]")
            save_results(f"syn_scan_{self.target_ip}", sorted(self.open_ports))
        else:
            console.print("[warning]No open ports found (SYN Scan).[/warning]")

class ServiceVersionDetection:
    def __init__(self, target_ip, ports_to_scan, timeout=5):
        self.target_ip = target_ip
        self.ports_to_scan = self._parse_ports(ports_to_scan)
        self.timeout = timeout
        self.console = Console(theme=custom_theme)
        self.service_info = {}

    def _parse_ports(self, ports_str):
        valid_ports = []
        try:
            if '-' in ports_str:
                start, end = map(int, ports_str.split('-'))
                if 0 < start <= end <= 65535:
                    valid_ports = list(range(start, end + 1))
            elif ',' in ports_str:
                valid_ports = [int(p.strip()) for p in ports_str.split(',')]
                if not all(0 < p <= 65535 for p in valid_ports):
                    raise ValueError("Invalid port list")
            else:
                port = int(ports_str)
                if 0 < port <= 65535:
                    valid_ports = [port]
            return valid_ports
        except ValueError as e:
            console.print(f"[danger]Error in port format ({e}): {ports_str}[/danger]")
            console.print("[warning]Accepted formats: 80 | 21,22,80 | 1-1024[/warning]")
            return None

    def _get_service_banner(self, ip, port):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(self.timeout)
                sock.connect((ip, port))
                sock.send(b'HEAD / HTTP/1.0\r\n\r\n')
                banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
                return banner.splitlines()[0] if banner else "No banner"
        except (socket.timeout, ConnectionRefusedError):
            return "No response"
        except Exception:
            return "Error"

    async def run_scan(self):
        if self.ports_to_scan is None:
            return

        console.print(f"\n[info]Attempting service version detection on {self.target_ip} ({len(self.ports_to_scan)} ports)...[/info]")
        start_time = datetime.now()

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            TextColumn("({task.completed}/{task.total})"),
            console=self.console,
            transient=True
        ) as progress:
            task = progress.add_task("[yellow]Detecting...", total=len(self.ports_to_scan))
            for port in self.ports_to_scan:
                banner = self._get_service_banner(self.target_ip, port)
                if banner and banner != "No response" and banner != "Error":
                    self.service_info[port] = banner
                    console.print(f"[info]Port {port:<5}: [bold cyan]{banner}[/bold cyan][/info]")
                progress.advance(task)

        end_time = datetime.now()
        duration = end_time - start_time
        console.print(f"\n[info]Service version detection finished in {duration.total_seconds():.2f} seconds.[/info]")

        if self.service_info:
            save_results(f"service_version_{self.target_ip}", self.service_info)
        else:
            console.print("[warning]No service information could be obtained.[/warning]")

class RobotsTxtScanner:
    def __init__(self, base_url, timeout=DEFAULT_TIMEOUT, user_agent='UltimatePentestTool/1.0'):
        self.base_url = self._format_url(base_url)
        self.timeout = timeout
        self.user_agent = user_agent
        self.console = Console(theme=custom_theme)

    def _format_url(self, url):
        if not url.startswith(('http://', 'https://')):
            url = 'http://' + url
        return url.rstrip('/')

    async def run(self):
        console.print(f"\n[primary]--- robots.txt Scanner for {self.base_url} ---[/primary]")
        url = f"{self.base_url}/robots.txt"
        try:
            headers = {'User-Agent': self.user_agent}
            async with aiohttp.ClientSession() as session:
                async with session.get(url, timeout=self.timeout, allow_redirects=True, headers=headers) as response:
                    if response.status == 200:
                        content = await response.text()
                        console.print("[bold magenta]robots.txt Content:[/bold magenta]")
                        console.print(f"[green]{content}[/green]")
                        save_results(f"robots_txt_{urlparse(self.base_url).netloc}", {"content": content})
                    else:
                        console.print(f"[info]robots.txt not found or access denied (Status: {response.status}).[/info]")
        except aiohttp.ClientError as e:
            console.print(f"[danger]Error fetching URL: {e}[/danger]")
        except asyncio.TimeoutError:
            console.print(f"[warning]Timeout occurred while fetching {url}[/warning]")
        except Exception as e:
            console.print(f"[danger]An unexpected error occurred: {e}[/danger]")

class SitemapXmlScanner:
    def __init__(self, base_url, timeout=DEFAULT_TIMEOUT, user_agent='UltimatePentestTool/1.0'):
        self.base_url = self._format_url(base_url)
        self.timeout = timeout
        self.user_agent = user_agent
        self.console = Console(theme=custom_theme)

    def _format_url(self, url):
        if not url.startswith(('http://', 'https://')):
            url = 'http://' + url
        return url.rstrip('/')

    async def run(self):
        console.print(f"\n[primary]--- sitemap.xml Scanner for {self.base_url} ---[/primary]")
        url = f"{self.base_url}/sitemap.xml"
        try:
            headers = {'User-Agent': self.user_agent}
            async with aiohttp.ClientSession() as session:
                async with session.get(url, timeout=self.timeout, allow_redirects=True, headers=headers) as response:
                    if response.status == 200:
                        content = await response.text()
                        console.print("[bold magenta]sitemap.xml Content:[/bold magenta]")
                        console.print(f"[green]{content}[/green]")
                        save_results(f"sitemap_xml_{urlparse(self.base_url).netloc}", {"content": content})
                    else:
                        console.print(f"[info]sitemap.xml not found or access denied (Status: {response.status}).[/info]")
        except aiohttp.ClientError as e:
            console.print(f"[danger]Error fetching URL: {e}[/danger]")
        except asyncio.TimeoutError:
            console.print(f"[warning]Timeout occurred while fetching {url}[/warning]")
        except Exception as e:
            console.print(f"[danger]An unexpected error occurred: {e}[/danger]")

class LinkExtractor:
    def __init__(self, target_url, timeout=DEFAULT_TIMEOUT, user_agent='UltimatePentestTool/1.0'):
        self.target_url = self._format_url(target_url)
        self.timeout = timeout
        self.user_agent = user_agent
        self.console = Console(theme=custom_theme)
        self.extracted_links = set()

    def _format_url(self, url):
        if not url.startswith(('http://', 'https://')):
            url = 'http://' + url
        return url.rstrip('/')

    async def run(self):
        console.print(f"\n[primary]--- Link Extractor for {self.target_url} ---[/primary]")
        try:
            headers = {'User-Agent': self.user_agent}
            async with aiohttp.ClientSession() as session:
                async with session.get(self.target_url, timeout=self.timeout, allow_redirects=True, headers=headers) as response:
                    if response.status == 200:
                        html_content = await response.text()
                        from bs4 import BeautifulSoup
                        soup = BeautifulSoup(html_content, 'html.parser')
                        for link in soup.find_all('a', href=True):
                            href = link['href']
                            if href.startswith('http') or href.startswith('/'):
                                self.extracted_links.add(href)
                        console.print("[bold magenta]Extracted Links:[/bold magenta]")
                        for link in sorted(self.extracted_links):
                            console.print(f"[green]{link}[/green]")
                        save_results(f"links_{urlparse(self.target_url).netloc}", sorted(list(self.extracted_links)))
                    else:
                        console.print(f"[warning]Could not retrieve content from {self.target_url} (Status: {response.status}).[/warning]")
        except aiohttp.ClientError as e:
            console.print(f"[danger]Error fetching URL: {e}[/danger]")
        except asyncio.TimeoutError:
            console.print(f"[warning]Timeout occurred while fetching {self.target_url}[/warning]")
        except ImportError:
            console.print("[danger]Error: 'beautifulsoup4' library is required. Please install it with: pip install beautifulsoup4[/danger]")
        except Exception as e:
            console.print(f"[danger]An unexpected error occurred: {e}[/danger]")

class CmsDetector:
    def __init__(self, target_url, timeout=DEFAULT_TIMEOUT, user_agent='UltimatePentestTool/1.0'):
        self.target_url = self._format_url(target_url)
        self.timeout = timeout
        self.user_agent = user_agent
        self.console = Console(theme=custom_theme)
        self.cms_signatures = {
            "WordPress": ["wp-content", "wp-includes"],
            "Joomla": ["administrator/index.php", "components/"],
            "Drupal": ["modules/system/system.module", "themes/bartik/style.css"],
            "Magento": ["skin/frontend/", "js/lib/prototype/prototype.js"],
            "Shopify": [".myshopify.com"],
            "Wix": ["wix.com"],
            "Squarespace": ["squarespace.com"],
        }

    def _format_url(self, url):
        if not url.startswith(('http://', 'https://')):
            url = 'http://' + url
        return url.rstrip('/')

    async def check_signature(self, session, url, signature):
        try:
            async with session.get(url, timeout=self.timeout, allow_redirects=False) as response:
                return response.status == 200
        except aiohttp.ClientError:
            return False
        except asyncio.TimeoutError:
            return False
        except Exception:
            return False

    async def run(self):
        console.print(f"\n[primary]--- CMS Detection for {self.target_url} ---[/primary]")
        detected_cms = "Unknown"
        try:
            headers = {'User-Agent': self.user_agent}
            async with aiohttp.ClientSession() as session:
                for cms, signatures in self.cms_signatures.items():
                    for sig in signatures:
                        test_url = f"{self.target_url}/{sig}"
                        if await self.check_signature(session, test_url, sig):
                            detected_cms = cms
                            break
                    if detected_cms != "Unknown":
                        break
            console.print(f"[success]Detected CMS: [bold green]{detected_cms}[/bold green][/success]")
            save_results(f"cms_detection_{urlparse(self.target_url).netloc}", {"cms": detected_cms})

        except Exception as e:
            console.print(f"[danger]An error occurred during CMS detection: {e}[/danger]")

class CloudflareDetector:
    def __init__(self, target_url, timeout=DEFAULT_TIMEOUT, user_agent='UltimatePentestTool/1.0'):
        self.target_url = self._format_url(target_url)
        self.timeout = timeout
        self.user_agent = user_agent
        self.console = Console(theme=custom_theme)

    def _format_url(self, url):
        if not url.startswith(('http://', 'https://')):
            url = 'http://' + url
        return url

    async def run(self):
        console.print(f"\n[primary]--- Cloudflare Detection for {self.target_url} ---[/primary]")
        try:
            headers = {'User-Agent': self.user_agent}
            async with aiohttp.ClientSession() as session:
                async with session.get(self.target_url, timeout=self.timeout, allow_redirects=True, headers=headers) as response:
                    if 'server' in response.headers and 'cloudflare' in response.headers['server'].lower():
                        console.print("[success]Cloudflare detected![/success]")
                        save_results(f"cloudflare_detection_{urlparse(self.target_url).netloc}", {"status": "detected"})
                    else:
                        console.print("[info]Cloudflare not detected.[/info]")
                        save_results(f"cloudflare_detection_{urlparse(self.target_url).netloc}", {"status": "not detected"})
        except aiohttp.ClientError as e:
            console.print(f"[danger]Error fetching URL: {e}[/danger]")
        except asyncio.TimeoutError:
            console.print(f"[warning]Timeout occurred while fetching {self.target_url}[/warning]")
        except Exception as e:
            console.print(f"[danger]An unexpected error occurred: {e}[/danger]")

class HttpMethodEnumerator:
    def __init__(self, target_url, timeout=DEFAULT_TIMEOUT, user_agent='UltimatePentestTool/1.0'):
        self.target_url = self._format_url(target_url)
        self.timeout = timeout
        self.user_agent = user_agent
        self.console = Console(theme=custom_theme)
        self.methods_to_test = ["GET", "HEAD", "POST", "PUT", "DELETE", "OPTIONS", "TRACE"]
        self.allowed_methods = []

    def _format_url(self, url):
        if not url.startswith(('http://', 'https://')):
            url = 'http://' + url
        return url

    async def test_method(self, session, method):
        try:
            headers = {'User-Agent': self.user_agent}
            async with session.request(method, self.target_url, timeout=self.timeout, allow_redirects=False, headers=headers) as response:
                if response.status not in [405, 501]:
                    with self.console.lock:
                        self.allowed_methods.append(f"{method}: {response.status}")
                        self.console.print(f"[success]Method [bold green]{method}[/bold green] allowed (Status: {response.status})[/success]")
        except aiohttp.ClientError:
            pass
        except asyncio.TimeoutError:
            pass
        except Exception:
            pass

    async def run(self):
        console.print(f"\n[primary]--- HTTP Method Enumeration for {self.target_url} ---[/primary]")
        async with aiohttp.ClientSession() as session:
            tasks = [self.test_method(session, method) for method in self.methods_to_test]
            await asyncio.gather(*tasks)

        if self.allowed_methods:
            console.print("\n[bold magenta]Allowed HTTP Methods:[/bold magenta]")
            for method_info in self.allowed_methods:
                console.print(f"[green]{method_info}[/green]")
            save_results(f"http_methods_{urlparse(self.target_url).netloc}", self.allowed_methods)
        else:
            console.print("[warning]No allowed HTTP methods (other than 405/501) found.[/warning]")

class CookieAnalyzer:
    def __init__(self, target_url, timeout=DEFAULT_TIMEOUT, user_agent='UltimatePentestTool/1.0'):
        self.target_url = self._format_url(target_url)
        self.timeout = timeout
        self.user_agent = user_agent
        self.console = Console(theme=custom_theme)

    def _format_url(self, url):
        if not url.startswith(('http://', 'https://')):
            url = 'http://' + url
        return url

    async def run(self):
        console.print(f"\n[primary]--- Cookie Analysis for {self.target_url} ---[/primary]")
        try:
            headers = {'User-Agent': self.user_agent}
            async with aiohttp.ClientSession() as session:
                async with session.get(self.target_url, timeout=self.timeout, allow_redirects=True, headers=headers) as response:
                    if response.cookies:
                        console.print("[bold magenta]Cookies Set:[/bold magenta]")
                        cookies_data = {}
                        for cookie in response.cookies.values():
                            console.print(f"[cyan]{cookie.key}:[/cyan] [green]{cookie.value}[/green]")
                            cookies_data[cookie.key] = cookie.value
                            if cookie.secure:
                                console.print(f"  [dim]Secure: Yes[/dim]")
                            if cookie.httponly:
                                console.print(f"  [dim]HttpOnly: Yes[/dim]")
                            if cookie.expires:
                                console.print(f"  [dim]Expires: {datetime.fromtimestamp(cookie.expires)}[/dim]")
                            if cookie.domain:
                                console.print(f"  [dim]Domain: {cookie.domain}[/dim]")
                            if cookie.path:
                                console.print(f"  [dim]Path: {cookie.path}[/dim]")
                            console.print("-" * 20)
                        save_results(f"cookie_analysis_{urlparse(self.target_url).netloc}", cookies_data)
                    else:
                        console.print("[info]No cookies set by this website.[/info]")
        except aiohttp.ClientError as e:
            console.print(f"[danger]Error fetching URL: {e}[/danger]")
        except asyncio.TimeoutError:
            console.print(f"[warning]Timeout occurred while fetching {self.target_url}[/warning]")
        except Exception as e:
            console.print(f"[danger]An unexpected error occurred: {e}[/danger]")

class CommonHeaderCheck:
    def __init__(self, target_url, timeout=DEFAULT_TIMEOUT, user_agent='UltimatePentestTool/1.0'):
        self.target_url = self._format_url(target_url)
        self.timeout = timeout
        self.user_agent = user_agent
        self.console = Console(theme=custom_theme)
        self.headers_to_check = {
            "Strict-Transport-Security": "Should be present to enforce HTTPS.",
            "X-Frame-Options": "Helps prevent clickjacking.",
            "X-Content-Type-Options": "Prevents MIME sniffing.",
            "Content-Security-Policy": "Controls resources the user agent is allowed to load.",
            "Referrer-Policy": "Controls how much referrer information to include.",
            "Permissions-Policy": "Controls browser features available to the document.",
        }

    def _format_url(self, url):
        if not url.startswith(('http://', 'https://')):
            url = 'http://' + url
        return url

    async def run(self):
        console.print(f"\n[primary]--- Common Security Header Check for {self.target_url} ---[/primary]")
        try:
            headers = {'User-Agent': self.user_agent}
            async with aiohttp.ClientSession() as session:
                async with session.head(self.target_url, timeout=self.timeout, allow_redirects=True, headers=headers) as response:
                    found_headers = response.headers
                    results = {}
                    for header, description in self.headers_to_check.items():
                        if header in found_headers:
                            console.print(f"[success]Header [bold green]{header}[/bold green] found: [dim]{found_headers.get(header)}[/dim][/success]")
                            results[header] = f"Found: {found_headers.get(header)}"
                        else:
                            console.print(f"[warning]Header [bold yellow]{header}[/bold yellow] not found: [dim]{description}[/dim][/warning]")
                            results[header] = f"Not Found: {description}"
                    save_results(f"header_check_{urlparse(self.target_url).netloc}", results)
        except aiohttp.ClientError as e:
            console.print(f"[danger]Error fetching URL: {e}[/danger]")
        except asyncio.TimeoutError:
            console.print(f"[warning]Timeout occurred while fetching {self.target_url}[/warning]")
        except Exception as e:
            console.print(f"[danger]An unexpected error occurred: {e}[/danger]")

class SslTlsInfo:
    def __init__(self, target_url, timeout=10):
        self.target_url = self._format_url(target_url)
        self.timeout = timeout
        self.console = Console(theme=custom_theme)

    def _format_url(self, url):
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
        return url

    async def run(self):
        console.print(f"\n[primary]--- SSL/TLS Certificate Information for {self.target_url} ---[/primary]")
        import ssl
        import certifi
        try:
            url_parsed = urlparse(self.target_url)
            hostname = url_parsed.netloc
            port = 443 if url_parsed.scheme == 'https' else 80

            context = ssl.create_default_context(cafile=certifi.where())
            with socket.create_connection((hostname, port), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    if cert:
                        console.print("[bold magenta]SSL/TLS Certificate Details:[/bold magenta]")
                        console.print(f"[cyan]Subject:[/cyan] [green]{cert.get('subject')}[/green]")
                        console.print(f"[cyan]Issuer:[/cyan] [green]{cert.get('issuer')}[/green]")
                        console.print(f"[cyan]Valid From:[/cyan] [green]{cert.get('notBefore')}[/green]")
                        console.print(f"[cyan]Valid Until:[/cyan] [green]{cert.get('notAfter')}[/green]")
                        console.print(f"[cyan]Subject Alternative Names:[/cyan] [green]{cert.get('subjectAltName')}[/green]")
                        save_results(f"ssl_info_{hostname}", cert)
                    else:
                        console.print("[warning]No SSL/TLS certificate found.[/warning]")
        except socket.gaierror:
            console.print(f"[danger]Could not resolve hostname: {hostname}[/danger]")
        except socket.timeout:
            console.print(f"[warning]Timeout occurred while connecting to {hostname}:{port}[/warning]")
        except ssl.SSLError as e:
            console.print(f"[danger]SSL/TLS error: {e}[/danger]")
        except Exception as e:
            console.print(f"[danger]An unexpected error occurred: {e}[/danger]")

class HashIdentifier:
    def __init__(self):
        self.console = Console(theme=custom_theme)

    def run(self):
        console.print("\n[primary]--- Hash Identifier ---[/primary]")
        hash_value = get_user_input("Enter the hash to identify")
        if not hash_value:
            return

        import hashlib

        hash_length = len(hash_value)

        possible_types = []
        if hash_length == 32:
            possible_types.append("MD5")
        elif hash_length == 40:
            possible_types.append("SHA1")
        elif hash_length == 64:
            possible_types.extend(["SHA256", "SHA512 (truncated)"])
        elif hash_length == 56:
            possible_types.append("SHA224")
        elif hash_length == 128:
            possible_types.append("SHA512")

        if possible_types:
            console.print("[info]Possible hash types:[/info]")
            for hash_type in possible_types:
                console.print(f"[green]- {hash_type}[/green]")
            save_results("hash_identifier", {"hash": hash_value, "possible_types": possible_types})
        else:
            console.print("[warning]Could not identify the hash type based on its length.[/warning]")

class Base64Coder:
    def __init__(self):
        self.console = Console(theme=custom_theme)

    def run(self):
        console.print("\n[primary]--- Base64 Encoder/Decoder ---[/primary]")
        choice = get_user_input("Choose an action (encode/decode)")
        if not choice:
            return

        import base64

        if choice.lower() == 'encode':
            text_to_encode = get_user_input("Enter text to encode")
            if text_to_encode is not None:
                encoded_text = base64.b64encode(text_to_encode.encode('utf-8')).decode('utf-8')
                console.print(f"[success]Encoded text: [bold green]{encoded_text}[/bold green][/success]")
                save_results("base64_coder", {"action": "encode", "original": text_to_encode, "result": encoded_text})
        elif choice.lower() == 'decode':
            text_to_decode = get_user_input("Enter Base64 string to decode")
            if text_to_decode is not None:
                try:
                    decoded_text = base64.b64decode(text_to_decode).decode('utf-8')
                    console.print(f"[success]Decoded text: [bold green]{decoded_text}[/bold green][/success]")
                    save_results("base64_coder", {"action": "decode", "original": text_to_decode, "result": decoded_text})
                except base64.binascii.Error:
                    console.print("[danger]Invalid Base64 string.[/danger]")
        else:
            console.print("[warning]Invalid choice. Please enter 'encode' or 'decode'.[/warning]")

class IpHostnameConverter:
    def __init__(self):
        self.console = Console(theme=custom_theme)

    def run(self):
        console.print("\n[primary]--- IP to Hostname Converter ---[/primary]")
        ips_str = get_user_input("Enter IP addresses separated by comma")
        if not ips_str:
            return

        ips = [ip.strip() for ip in ips_str.split(',')]
        results = {}
        for ip in ips:
            try:
                hostname, _, _ = socket.gethostbyaddr(ip)
                console.print(f"[success]IP: [bold cyan]{ip}[/bold cyan] -> Hostname: [bold green]{hostname}[/bold green][/success]")
                results[ip] = hostname
            except socket.herror:
                console.print(f"[warning]No hostname found for {ip}[/warning]")
                results[ip] = "No hostname found"
            except socket.gaierror:
                console.print(f"[danger]Invalid IP address: {ip}[/danger]")
                results[ip] = "Invalid IP address"
            except Exception as e:
                console.print(f"[danger]An unexpected error occurred for {ip}: {e}[/danger]")
                results[ip] = f"Error: {e}"
        save_results("ip_to_hostname", results)

class UrlIpConverter:
    def __init__(self):
        self.console = Console(theme=custom_theme)

    def run(self):
        console.print("\n[primary]--- URL to IP Converter ---[/primary]")
        urls_str = get_user_input("Enter URLs separated by comma")
        if not urls_str:
            return

        urls = [url.strip() for url in urls_str.split(',')]
        results = {}
        for url in urls:
            try:
                parsed_url = urlparse(url)
                hostname = parsed_url.netloc
                ip_address = socket.gethostbyname(hostname)
                console.print(f"[success]URL: [bold cyan]{url}[/bold cyan] -> IP: [bold green]{ip_address}[/bold green][/success]")
                results[url] = ip_address
            except socket.gaierror:
                console.print(f"[warning]Could not resolve hostname for {url}[/warning]")
                results[url] = "Could not resolve hostname"
            except Exception as e:
                console.print(f"[danger]An unexpected error occurred for {url}: {e}[/danger]")
                results[url] = f"Error: {e}"
        save_results("url_to_ip", results)

def display_menu():
    menu_options = {
        "1": "Port Scan",
        "2": "Directory Brute-force",
        "3": "DNS Enumeration",
        "4": "Subdomain Enumeration",
        "5": "HTTP Header Analysis",
        "6": "WHOIS Lookup",
        "7": "Reverse IP Lookup",
        "8": "GeoIP Lookup",
        "9": "Ping Sweep",
        "10": "Traceroute",
        "11": "Reverse DNS Lookup",
        "12": "ASN Lookup",
        "13": "TCP SYN Scan",
        "14": "Service Version Detection",
        "15": "robots.txt Scanner",
        "16": "sitemap.xml Scanner",
        "17": "Link Extractor",
        "18": "CMS Detection",
        "19": "Cloudflare Detection",
        "20": "HTTP Method Enumeration",
        "21": "Cookie Analysis",
        "22": "Common Security Header Check",
        "23": "SSL/TLS Certificate Information",
        "24": "Hash Identifier",
        "25": "Base64 Encoder/Decoder",
        "26": "IP to Hostname Converter",
        "27": "URL to IP Converter",
        "0": "Exit"
    }
    table = Table(title="[primary]Main Menu[/primary]", show_header=False, border_style="red")
    table.add_column("Option", style="cyan", width=5)
    table.add_column("Description", style="white")
    for key, value in menu_options.items():
        table.add_row(key, value)
    time.sleep(5)
    os.system('cls' if os.name == 'nt' else 'clear')
    console.print(table)

def main():
    display_banner()
    while True:
        display_menu()
        choice = get_user_input("[primary]>[/primary] Choose an option: ")

        if choice == '1':
            os.system('cls' if os.name == 'nt' else 'clear')
            console.print("\n[primary]--- Port Scan ---[/primary]")
            target_ip = get_user_input("Enter target IP address")
            if target_ip is None: continue
            ports_str = get_user_input("Enter port(s) to scan (e.g., 80, 1-1024, 22,80,443)")
            if ports_str is None: continue
            timeout = get_user_input("Enter timeout for port scan (seconds, default: 1)", expected_type=float, validation_func=lambda x: x > 0)
            if timeout is None: timeout = DEFAULT_TIMEOUT
            scan_type = get_user_input("Enter scan type (TCP/UDP, default: TCP)", validation_func=lambda x: x.lower() in ['tcp', 'udp'])
            if scan_type is None: scan_type = 'tcp'
            scanner = PortScanner(target_ip, ports_str, timeout=timeout, scan_type=scan_type)
            scanner.run_scan()

        elif choice == '2':
            os.system('cls' if os.name == 'nt' else 'clear')
            console.print("\n[primary]--- Directory Brute-force ---[/primary]")
            base_url = get_user_input("Enter base URL (e.g., http://example.com)")
            if base_url is None: continue
            wordlist_paths_str = get_user_input("Enter path(s) to wordlist(s) separated by comma")
            if wordlist_paths_str is None: continue
            wordlist_paths = [path.strip() for path in wordlist_paths_str.split(',')]
            user_agent = get_user_input("Enter custom User-Agent (optional)", expected_type=str)
            if user_agent is None: user_agent = 'UltimatePentestTool/1.0'
            http_method = get_user_input("Enter HTTP method (GET/HEAD, default: GET)", validation_func=lambda x: x.upper() in ['GET', 'HEAD'])
            if http_method is None: http_method = 'GET'

            buster = DirectoryBuster(base_url, wordlist_paths, user_agent=user_agent, http_method=http_method)
            asyncio.run(buster.run_bruteforce())

        elif choice == '3':
            os.system('cls' if os.name == 'nt' else 'clear')
            console.print("\n[primary]--- DNS Enumeration ---[/primary]")
            target = get_user_input("Enter target domain or IP address")
            if target is None: continue
            dns_enum = DnsEnumerator(target)
            dns_enum.run()

        elif choice == '4':
            os.system('cls' if os.name == 'nt' else 'clear')
            console.print("\n[primary]--- Subdomain Enumeration ---[/primary]")
            target_domain = get_user_input("Enter target domain (e.g., example.com)")
            if target_domain is None: continue
            wordlist_path = get_user_input("Enter path to subdomain wordlist")
            if wordlist_path is None: continue
            timeout = get_user_input("Enter timeout for subdomain enumeration (seconds, default: 1)", expected_type=float, validation_func=lambda x: x > 0)
            if timeout is None: timeout = DEFAULT_TIMEOUT

            subdomain_enum = SubdomainEnumerator(target_domain, wordlist_path, timeout=timeout)
            asyncio.run(subdomain_enum.run_enumeration())

        elif choice == '5':
            os.system('cls' if os.name == 'nt' else 'clear')
            console.print("\n[primary]--- HTTP Header Analysis ---[/primary]")
            target_url = get_user_input("Enter target URL (e.g., http://example.com)")
            if target_url is None: continue
            timeout = get_user_input("Enter timeout for HTTP request (seconds, default: 1)", expected_type=float, validation_func=lambda x: x > 0)
            if timeout is None: timeout = DEFAULT_TIMEOUT

            header_analyzer = HttpHeaderAnalyzer(target_url, timeout=timeout)
            header_analyzer.run()

        elif choice == '6':
            os.system('cls' if os.name == 'nt' else 'clear')
            console.print("\n[primary]--- WHOIS Lookup ---[/primary]")
            target_domain = get_user_input("Enter target domain to lookup (e.g., example.com)")
            if target_domain is None: continue
            whois_lookup = WhoisLookup(target_domain)
            whois_lookup.run()

        elif choice == '7':
            os.system('cls' if os.name == 'nt' else 'clear')
            console.print("\n[primary]--- Reverse IP Lookup ---[/primary]")
            target_ip = get_user_input("Enter target IP address")
            if target_ip is None: continue
            reverse_ip = ReverseIpLookup(target_ip)
            asyncio.run(reverse_ip.run())

        elif choice == '8':
            os.system('cls' if os.name == 'nt' else 'clear')
            console.print("\n[primary]--- GeoIP Lookup ---[/primary]")
            target_ip = get_user_input("Enter target IP address")
            if target_ip is None: continue
            geoip = GeoIpLookup(target_ip)
            asyncio.run(geoip.run())

        elif choice == '9':
            os.system('cls' if os.name == 'nt' else 'clear')
            console.print("\n[primary]--- Ping Sweep ---[/primary]")
            network = get_user_input("Enter network to sweep (e.g., 192.168.1.0/24)")
            if network is None: continue
            timeout = get_user_input("Enter timeout per ping (seconds, default: 1)", expected_type=float, validation_func=lambda x: x > 0)
            if timeout is None: timeout = DEFAULT_TIMEOUT
            ping_sweep = PingSweep(network, timeout=timeout)
            asyncio.run(ping_sweep.run())

        elif choice == '10':
            os.system('cls' if os.name == 'nt' else 'clear')
            console.print("\n[primary]--- Traceroute ---[/primary]")
            target = get_user_input("Enter target IP address or domain")
            if target is None: continue
            traceroute = Traceroute(target)
            asyncio.run(traceroute.run())

        elif choice == '11':
            os.system('cls' if os.name == 'nt' else 'clear')
            console.print("\n[primary]--- Reverse DNS Lookup ---[/primary]")
            target_ip = get_user_input("Enter target IP address")
            if target_ip is None: continue
            reverse_dns = ReverseDnsLookup(target_ip)
            reverse_dns.run()

        elif choice == '12':
            os.system('cls' if os.name == 'nt' else 'clear')
            console.print("\n[primary]--- ASN Lookup ---[/primary]")
            target_ip = get_user_input("Enter target IP address")
            if target_ip is None: continue
            asn_lookup = AsnLookup(target_ip)
            asyncio.run(asn_lookup.run())

        elif choice == '13':
            os.system('cls' if os.name == 'nt' else 'clear')
            console.print("\n[primary]--- TCP SYN Scan ---[/primary]")
            target_ip = get_user_input("Enter target IP address")
            if target_ip is None: continue
            ports_str = get_user_input("Enter port(s) to scan (e.g., 80, 1-1024)")
            if ports_str is None: continue
            timeout = get_user_input("Enter timeout for scan (seconds, default: 1)", expected_type=float, validation_func=lambda x: x > 0)
            if timeout is None: timeout = DEFAULT_TIMEOUT
            syn_scanner = TcpSynScanner(target_ip, ports_str, timeout=timeout)
            asyncio.run(syn_scanner.run_scan())

        elif choice == '14':
            os.system('cls' if os.name == 'nt' else 'clear')
            console.print("\n[primary]--- Service Version Detection ---[/primary]")
            target_ip = get_user_input("Enter target IP address")
            if target_ip is None: continue
            ports_str = get_user_input("Enter port(s) to check (e.g., 80, 1-100)")
            if ports_str is None: continue
            timeout = get_user_input("Enter timeout per port (seconds, default: 5)", expected_type=float, validation_func=lambda x: x > 0)
            if timeout is None: timeout = 5
            version_detector = ServiceVersionDetection(target_ip, ports_str, timeout=timeout)
            asyncio.run(version_detector.run_scan())

        elif choice == '15':
            os.system('cls' if os.name == 'nt' else 'clear')
            console.print("\n[primary]--- robots.txt Scanner ---[/primary]")
            base_url = get_user_input("Enter base URL (e.g., http://example.com)")
            if base_url is None: continue
            robots_scanner = RobotsTxtScanner(base_url)
            asyncio.run(robots_scanner.run())

        elif choice == '16':
            os.system('cls' if os.name == 'nt' else 'clear')
            console.print("\n[primary]--- sitemap.xml Scanner ---[/primary]")
            base_url = get_user_input("Enter base URL (e.g., http://example.com)")
            if base_url is None: continue
            sitemap_scanner = SitemapXmlScanner(base_url)
            asyncio.run(sitemap_scanner.run())

        elif choice == '17':
            os.system('cls' if os.name == 'nt' else 'clear')
            console.print("\n[primary]--- Link Extractor ---[/primary]")
            target_url = get_user_input("Enter target URL to extract links from")
            if target_url is None: continue
            link_extractor = LinkExtractor(target_url)
            asyncio.run(link_extractor.run())

        elif choice == '18':
            os.system('cls' if os.name == 'nt' else 'clear')
            console.print("\n[primary]--- CMS Detection ---[/primary]")
            target_url = get_user_input("Enter target URL")
            if target_url is None: continue
            cms_detector = CmsDetector(target_url)
            asyncio.run(cms_detector.run())

        elif choice == '19':
            os.system('cls' if os.name == 'nt' else 'clear')
            console.print("\n[primary]--- Cloudflare Detection ---[/primary]")
            target_url = get_user_input("Enter target URL")
            if target_url is None: continue
            cloudflare_detector = CloudflareDetector(target_url)
            asyncio.run(cloudflare_detector.run())

        elif choice == '20':
            os.system('cls' if os.name == 'nt' else 'clear')
            console.print("\n[primary]--- HTTP Method Enumeration ---[/primary]")
            target_url = get_user_input("Enter target URL")
            if target_url is None: continue
            method_enumerator = HttpMethodEnumerator(target_url)
            asyncio.run(method_enumerator.run())

        elif choice == '21':
            os.system('cls' if os.name == 'nt' else 'clear')
            console.print("\n[primary]--- Cookie Analysis ---[/primary]")
            target_url = get_user_input("Enter target URL")
            if target_url is None: continue
            cookie_analyzer = CookieAnalyzer(target_url)
            asyncio.run(cookie_analyzer.run())

        elif choice == '22':
            os.system('cls' if os.name == 'nt' else 'clear')
            console.print("\n[primary]--- Common Security Header Check ---[/primary]")
            target_url = get_user_input("Enter target URL")
            if target_url is None: continue
            header_checker = CommonHeaderCheck(target_url)
            asyncio.run(header_checker.run())

        elif choice == '23':
            os.system('cls' if os.name == 'nt' else 'clear')
            console.print("\n[primary]--- SSL/TLS Certificate Information ---[/primary]")
            target_url = get_user_input("Enter target URL (e.g., https://example.com)")
            if target_url is None: continue
            ssl_info = SslTlsInfo(target_url)
            asyncio.run(ssl_info.run())

        elif choice == '24':
            os.system('cls' if os.name == 'nt' else 'clear')
            hash_identifier = HashIdentifier()
            hash_identifier.run()

        elif choice == '25':
            os.system('cls' if os.name == 'nt' else 'clear')
            base64_coder = Base64Coder()
            base64_coder.run()

        elif choice == '26':
            os.system('cls' if os.name == 'nt' else 'clear')
            ip_converter = IpHostnameConverter()
            ip_converter.run()

        elif choice == '27':
            os.system('cls' if os.name == 'nt' else 'clear')
            url_converter = UrlIpConverter()
            url_converter.run()

        elif choice == '0':
            console.print("[primary]Exiting...[/primary]")
            break
        else:
            console.print("[danger]Invalid option. Please try again.[/danger]")

        console.print("\n" + "="*30 + "\n")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        console.print("\n\n[warning]Interruption detected. Closing the tool.[/warning]")
        sys.exit(0)
