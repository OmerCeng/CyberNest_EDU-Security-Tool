import socket
import threading
import time
from datetime import datetime
import sys

# ANSI color codes
RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
BLUE = "\033[94m"
MAGENTA = "\033[95m"
CYAN = "\033[96m"
WHITE = "\033[97m"
RESET = "\033[0m"
BOLD = "\033[1m"

# Common service ports mapping
COMMON_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 135: "RPC", 139: "NetBIOS", 143: "IMAP",
    443: "HTTPS", 993: "IMAPS", 995: "POP3S", 1433: "MSSQL", 1521: "Oracle",
    3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL", 5900: "VNC", 6379: "Redis",
    8080: "HTTP-Proxy", 8443: "HTTPS-Alt", 9200: "Elasticsearch", 27017: "MongoDB"
}

class AdvancedPortScanner:
    def __init__(self, target, timeout=1, threads=50):
        self.target = target
        self.timeout = timeout
        self.threads = threads
        self.open_ports = []
        self.total_ports = 0
        self.scanned_ports = 0
        self.lock = threading.Lock()
        self.start_time = None
        
    def scan_port(self, port):
        """Single port scan with service detection"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            result = sock.connect_ex((self.target, port))
            
            if result == 0:
                service = COMMON_PORTS.get(port, "Unknown")
                with self.lock:
                    self.open_ports.append((port, service))
            
            sock.close()
            
        except socket.error:
            pass
        finally:
            with self.lock:
                self.scanned_ports += 1
                
    def progress_display(self):
        """Minimal progress display"""
        while self.scanned_ports < self.total_ports:
            elapsed = time.time() - self.start_time
            progress = (self.scanned_ports / self.total_ports) * 100
            
            # Clean progress line
            sys.stdout.write(f"\r{CYAN}Scanning... {progress:.1f}% ({self.scanned_ports}/{self.total_ports}) - Found: {len(self.open_ports)} open ports{RESET}")
            sys.stdout.flush()
            time.sleep(0.1)
    
    def port_scan(self, start_port=1, end_port=1024, scan_type="fast"):
        """Advanced port scanning with threading"""
        
        # Determine port range based on scan type
        if scan_type == "quick":
            common_ports = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 993, 995, 1433, 3306, 3389, 5432, 8080]
            ports_to_scan = [p for p in common_ports if start_port <= p <= end_port]
        else:
            ports_to_scan = list(range(start_port, end_port + 1))
        
        self.total_ports = len(ports_to_scan)
        self.start_time = time.time()
        
        print(f"\n{BOLD}{BLUE}🎯 Target: {WHITE}{self.target}{RESET}")
        print(f"{BOLD}{BLUE}📊 Ports to scan: {WHITE}{self.total_ports}{RESET}")
        print(f"{BOLD}{BLUE}🧵 Threads: {WHITE}{self.threads}{RESET}")
        print(f"{BOLD}{BLUE}⏱️  Timeout: {WHITE}{self.timeout}s{RESET}")
        print(f"{WHITE}{'='*60}{RESET}\n")
        
        # Start progress monitor
        progress_thread = threading.Thread(target=self.progress_display, daemon=True)
        progress_thread.start()
        
        # Create and start threads
        threads = []
        port_index = 0
        
        def worker():
            nonlocal port_index
            while port_index < len(ports_to_scan):
                if port_index >= len(ports_to_scan):
                    break
                current_port = ports_to_scan[port_index]
                port_index += 1
                self.scan_port(current_port)
        
        # Start worker threads
        for _ in range(min(self.threads, len(ports_to_scan))):
            thread = threading.Thread(target=worker)
            thread.daemon = True
            thread.start()
            threads.append(thread)
        
        # Wait for all threads to complete
        for thread in threads:
            thread.join()
        
        # Final results
        elapsed = time.time() - self.start_time
        print(f"\r{GREEN}✅ Scan completed! - {elapsed:.1f}s - Found: {len(self.open_ports)} open ports{RESET}")
        
        return self.open_ports
    
    def display_results(self, open_ports):
        """Display scan results in nmap-like format"""
        if not open_ports:
            print(f"\n{RED}❌ No open ports found.{RESET}")
            return
        
        print(f"\n{GREEN}🎯 OPEN PORTS DISCOVERED:{RESET}")
        print(f"{WHITE}{'='*60}{RESET}")
        print(f"{BOLD}{BLUE}{'PORT':<8} {'STATE':<10} {'SERVICE':<15}{RESET}")
        print(f"{WHITE}{'-'*35}{RESET}")
        
        for port, service in sorted(open_ports):
            print(f"{YELLOW}{port:<8} {GREEN}{'open':<10} {CYAN}{service:<15}{RESET}")
        
        print(f"\n{BOLD}{GREEN}📊 Summary: {len(open_ports)} open ports found{RESET}")
        
        # Security recommendations
        if open_ports:
            print(f"\n{BOLD}{MAGENTA}🛡️  Security Notes:{RESET}")
            for port, service in sorted(open_ports):
                if port in [21, 23, 135, 139]:
                    print(f"   {RED}⚠️  Port {port} ({service}) - Consider disabling if not needed{RESET}")
                elif port in [22, 3389]:
                    print(f"   {YELLOW}⚠️  Port {port} ({service}) - Ensure strong authentication{RESET}")
                elif port in [80, 443]:
                    print(f"   {BLUE}ℹ️  Port {port} ({service}) - Web server detected{RESET}")
        
        print(f"{WHITE}{'='*60}{RESET}")


def run():
    print(f"""{CYAN}
🔍 Advanced Port Scanner
{'='*60}
Professional port scanning with service detection and threading
{RESET}""")
    
    while True:
        print(f"\n{BOLD}{GREEN}===== Advanced Port Scanner ====={RESET}")
        print(f"{BLUE}1.{RESET} {WHITE}Quick Scan (Common Ports){RESET}")
        print(f"{BLUE}2.{RESET} {WHITE}Fast Scan (1-1024){RESET}")
        print(f"{BLUE}3.{RESET} {WHITE}Custom Port Range{RESET}")
        print(f"{BLUE}4.{RESET} {WHITE}Comprehensive Scan (1-65535){RESET}")
        print(f"{BLUE}0.{RESET} {RED}Return to Menu{RESET}")
        
        choice = input(f"\n{BOLD}{WHITE}Select scan type: {RESET}")
        
        if choice == '0':
            break
            
        target = input(f"{YELLOW}Enter target IP/hostname: {RESET}").strip()
        if not target:
            print(f"{RED}❌ Target cannot be empty!{RESET}")
            continue
            
        # Validate target format
        if not target.replace('.', '').replace('-', '').replace(':', '').replace('/', '').replace('_', '').isalnum():
            print(f"{RED}❌ Invalid target format!{RESET}")
            continue
        
        try:
            # Advanced scanner settings
            timeout = 1
            threads = 50
            
            if choice == '1':
                # Quick scan - only common ports
                scanner = AdvancedPortScanner(target, timeout=timeout, threads=threads)
                open_ports = scanner.port_scan(1, 65535, scan_type="quick")
                scanner.display_results(open_ports)
                
            elif choice == '2':
                # Fast scan - 1-1024
                scanner = AdvancedPortScanner(target, timeout=timeout, threads=threads)
                open_ports = scanner.port_scan(1, 1024, scan_type="fast")
                scanner.display_results(open_ports)
                
            elif choice == '3':
                # Custom range
                port_range = input(f"{YELLOW}Enter port range (e.g. 80-443) or single port: {RESET}").strip()
                
                try:
                    if '-' in port_range:
                        start_port, end_port = map(int, port_range.split('-'))
                    else:
                        start_port = end_port = int(port_range)
                        
                    if start_port < 1 or end_port > 65535 or start_port > end_port:
                        print(f"{RED}❌ Port range must be 1-65535 and start <= end{RESET}")
                        continue
                        
                    scanner = AdvancedPortScanner(target, timeout=timeout, threads=threads)
                    open_ports = scanner.port_scan(start_port, end_port, scan_type="custom")
                    scanner.display_results(open_ports)
                    
                except ValueError:
                    print(f"{RED}❌ Invalid port format! Use 'start-end' or single port{RESET}")
                    continue
                    
            elif choice == '4':
                # Comprehensive scan
                print(f"{RED}⚠️  This will scan all 65535 ports (may take several minutes)!{RESET}")
                confirm = input(f"{YELLOW}Continue? (y/N): {RESET}").strip().lower()
                
                if confirm == 'y':
                    scanner = AdvancedPortScanner(target, timeout=0.5, threads=100)
                    open_ports = scanner.port_scan(1, 65535, scan_type="comprehensive")
                    scanner.display_results(open_ports)
                else:
                    continue
                    
            else:
                print(f"{RED}❌ Invalid selection!{RESET}")
                continue
                
        except KeyboardInterrupt:
            print(f"\n{YELLOW}⚠️  Scan interrupted by user{RESET}")
        except socket.gaierror:
            print(f"{RED}❌ Could not resolve target: {target}{RESET}")
        except Exception as e:
            print(f"{RED}❌ Error occurred: {e}{RESET}")
            
        input(f"\n{BOLD}{CYAN}Press Enter to continue...{RESET}")

if __name__ == "__main__":
    run()



