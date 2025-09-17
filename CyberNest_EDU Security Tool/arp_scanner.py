"""
ARP Network Scanner - Network Discovery Tool

This tool performs network device discovery using standard protocols:
- ARP (Address Resolution Protocol) table analysis
- ICMP ping scanning for device discovery
- Hostname resolution and MAC address vendor identification

Author: CyberNest_EDU Security Tool Suite
"""

import subprocess
import re
import socket
import platform
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

def get_local_ip():
    """Get local IP address"""
    try:
        # Find local IP by connecting to Google DNS
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
        return local_ip
    except:
        return "192.168.1.1"

def get_network_range(ip):
    """Calculate network range from IP address"""
    ip_parts = ip.split('.')
    network = f"{ip_parts[0]}.{ip_parts[1]}.{ip_parts[2]}"
    return network

def ping_host(ip):
    """Ping a specific IP address"""
    try:
        # Ping command based on operating system
        if platform.system().lower() == "windows":
            cmd = ["ping", "-n", "1", "-w", "1000", ip]
        else:
            cmd = ["ping", "-c", "1", "-W", "1", ip]
        
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=2)
        return ip if result.returncode == 0 else None
    except:
        return None

def get_arp_table():
    """Get ARP table"""
    arp_entries = {}
    try:
        if platform.system().lower() == "windows":
            result = subprocess.run(["arp", "-a"], capture_output=True, text=True)
        else:
            result = subprocess.run(["arp", "-a"], capture_output=True, text=True)
        
        if result.returncode == 0:
            lines = result.stdout.split('\n')
            for line in lines:
                # Extract IP and MAC addresses
                if platform.system().lower() == "windows":
                    # Windows format: 192.168.1.1    00-11-22-33-44-55     dynamic
                    match = re.search(r'(\d+\.\d+\.\d+\.\d+)\s+([0-9a-fA-F-]{17})', line)
                else:
                    # Linux/Mac format: 192.168.1.1 at 00:11:22:33:44:55 [ether] on eth0
                    match = re.search(r'(\d+\.\d+\.\d+\.\d+).*?([0-9a-fA-F:]{17})', line)
                
                if match:
                    ip = match.group(1)
                    mac = match.group(2)
                    # Convert MAC address to standard format
                    if '-' in mac:
                        mac = mac.replace('-', ':')
                    arp_entries[ip] = mac.upper()
    except:
        pass
    
    return arp_entries

def get_hostname(ip):
    """Get hostname from IP address"""
    try:
        hostname = socket.gethostbyaddr(ip)[0]
        return hostname
    except:
        return "Unknown"

def get_vendor_info(mac):
    """Get vendor information from MAC address (simple dictionary)"""
    mac_vendors = {
        "00:50:56": "VMware",
        "08:00:27": "VirtualBox",
        "52:54:00": "QEMU",
        "00:0C:29": "VMware",
        "00:1C:42": "Parallels",
        "00:03:FF": "Microsoft",
        "00:15:5D": "Microsoft Hyper-V",
        "DC:A6:32": "Raspberry Pi",
        "B8:27:EB": "Raspberry Pi",
        "E4:5F:01": "Raspberry Pi",
        "00:16:3E": "Xen",
        "00:1A:4A": "Apple",
        "00:1B:63": "Apple",
        "00:1C:B3": "Apple",
        "00:1D:4F": "Apple",
        "00:1E:C2": "Apple",
        "00:1F:F3": "Apple",
        "00:21:E9": "Apple",
        "00:22:41": "Apple",
        "00:23:12": "Apple",
        "00:23:DF": "Apple",
        "00:24:36": "Apple",
        "00:25:00": "Apple",
        "00:25:4B": "Apple",
        "00:25:BC": "Apple",
        "00:26:08": "Apple",
        "00:26:4A": "Apple",
        "00:26:B0": "Apple",
        "00:26:BB": "Apple",
        "04:0C:CE": "Apple",
        "04:15:52": "Apple",
        "04:1E:64": "Apple",
        "04:26:65": "Apple",
        "04:54:53": "Apple",
        "04:69:F8": "Apple",
        "04:DB:56": "Apple",
        "04:E5:36": "Apple",
        "04:F1:3E": "Apple",
        "04:F7:E4": "Apple",
        "08:74:02": "Apple",
        "0C:30:21": "Apple",
        "0C:3E:9F": "Apple",
        "0C:4D:E9": "Apple",
        "0C:74:C2": "Apple",
        "10:40:F3": "Apple",
        "10:9A:DD": "Apple",
        "10:DD:B1": "Apple",
        "14:10:9F": "Apple",
        "14:7D:DA": "Apple",
        "14:BD:61": "Apple",
        "18:65:90": "Apple",
        "18:AF:61": "Apple",
        "1C:1A:C0": "Apple",
        "1C:AB:A7": "Apple",
        "20:76:93": "Apple",
        "20:A2:E4": "Apple",
        "24:A0:74": "Apple",
        "24:AB:34": "Apple",
        "28:37:37": "Apple",
        "28:6A:BA": "Apple",
        "28:CF:DA": "Apple",
        "28:CF:E9": "Apple",
        "28:E0:2C": "Apple",
        "28:E7:CF": "Apple",
        "2C:1F:23": "Apple",
        "2C:36:F8": "Apple",
        "2C:54:91": "Apple",
        "2C:BE:08": "Apple",
        "2C:F0:A2": "Apple",
        "2C:F0:EE": "Apple",
        "30:05:5C": "Apple",
        "30:90:AB": "Apple",
        "34:15:9E": "Apple",
        "34:36:3B": "Apple",
        "34:A3:95": "Apple",
        "34:C0:59": "Apple",
        "38:B5:4D": "Apple",
        "3C:07:54": "Apple",
        "3C:15:C2": "Apple",
        "40:33:1A": "Apple",
        "40:6C:8F": "Apple",
        "40:A6:D9": "Apple",
        "40:B3:95": "Apple",
        "40:CB:C0": "Apple",
        "44:00:10": "Apple",
        "44:4C:0C": "Apple",
        "44:D8:84": "Apple",
        "44:FB:42": "Apple",
        "48:43:7C": "Apple",
        "48:74:6E": "Apple",
        "48:A1:95": "Apple",
        "48:BF:6B": "Apple",
        "4C:32:75": "Apple",
        "4C:7C:5F": "Apple",
        "4C:8D:79": "Apple",
        "4C:B1:99": "Apple",
        "50:ED:3C": "Apple",
        "54:26:96": "Apple",
        "54:72:4F": "Apple",
        "54:AE:27": "Apple",
        "54:E4:3A": "Apple",
        "58:23:8C": "Apple",
        "58:55:CA": "Apple",
        "5C:59:48": "Apple",
        "5C:95:AE": "Apple",
        "5C:F9:38": "Apple",
        "60:03:08": "Apple",
        "60:33:4B": "Apple",
        "60:69:44": "Apple",
        "60:C5:47": "Apple",
        "60:F4:45": "Apple",
        "60:FA:CD": "Apple",
        "60:FB:42": "Apple",
        "64:20:0C": "Apple",
        "64:76:BA": "Apple",
        "64:A3:CB": "Apple",
        "64:B0:A6": "Apple",
        "64:CC:2E": "Apple",
        "68:96:7B": "Apple",
        "68:AB:1E": "Apple",
        "68:D9:3C": "Apple",
        "6C:40:08": "Apple",
        "6C:94:66": "Apple",
        "70:11:24": "Apple",
        "70:48:0F": "Apple",
        "70:56:81": "Apple",
        "70:73:CB": "Apple",
        "70:CD:60": "Apple",
        "74:E2:F5": "Apple",
        "78:31:C1": "Apple",
        "78:4F:43": "Apple",
        "78:CA:39": "Apple",
        "7C:6D:62": "Apple",
        "7C:C3:A1": "Apple",
        "7C:C7:09": "Apple",
        "7C:D1:C3": "Apple",
        "80:92:9F": "Apple",
        "80:E6:50": "Apple",
        "84:29:99": "Apple",
        "84:38:35": "Apple",
        "84:85:06": "Apple",
        "84:FC:FE": "Apple",
        "88:1F:A1": "Apple",
        "88:53:2E": "Apple",
        "88:63:DF": "Apple",
        "88:66:A5": "Apple",
        "88:C6:63": "Apple",
        "8C:2D:AA": "Apple",
        "8C:58:77": "Apple",
        "8C:7C:92": "Apple",
        "8C:85:90": "Apple",
        "8C:8E:F2": "Apple",
        "90:27:E4": "Apple",
        "90:72:40": "Apple",
        "90:B0:ED": "Apple",
        "90:B2:1F": "Apple",
        "94:E6:F7": "Apple",
        "98:01:A7": "Apple",
        "98:B8:E3": "Apple",
        "9C:20:7B": "Apple",
        "9C:29:3F": "Apple",
        "9C:04:EB": "Apple",
        "9C:F3:87": "Apple",
        "A0:99:9B": "Apple",
        "A0:CE:C8": "Apple",
        "A4:5E:60": "Apple",
        "A4:83:E7": "Apple",
        "A4:B1:97": "Apple",
        "A4:C3:61": "Apple",
        "A8:20:66": "Apple",
        "A8:51:AB": "Apple",
        "A8:66:7F": "Apple",
        "A8:96:75": "Apple",
        "A8:BB:CF": "Apple",
        "AC:29:3A": "Apple",
        "AC:3C:0B": "Apple",
        "AC:61:EA": "Apple",
        "AC:87:A3": "Apple",
        "AC:BC:32": "Apple",
        "B0:19:C6": "Apple",
        "B0:34:95": "Apple",
        "B0:65:BD": "Apple",
        "B4:18:D1": "Apple",
        "B4:F0:AB": "Apple",
        "B4:F6:1C": "Apple",
        "B8:09:8A": "Apple",
        "B8:17:C2": "Apple",
        "B8:53:AC": "Apple",
        "B8:78:26": "Apple",
        "B8:C7:5D": "Apple",
        "B8:E8:56": "Apple",
        "B8:F6:B1": "Apple",
        "BC:52:B7": "Apple",
        "BC:67:1C": "Apple",
        "BC:6C:21": "Apple",
        "BC:92:6B": "Apple",
        "BC:EC:5D": "Apple",
        "C0:84:7A": "Apple",
        "C4:2C:03": "Apple",
        "C4:B3:01": "Apple",
        "C8:1E:E7": "Apple",
        "C8:2A:14": "Apple",
        "C8:33:4B": "Apple",
        "C8:69:CD": "Apple",
        "C8:89:F3": "Apple",
        "CC:08:8D": "Apple",
        "CC:25:EF": "Apple",
        "CC:29:F5": "Apple",
        "D0:23:DB": "Apple",
        "D0:33:11": "Apple",
        "D0:A6:37": "Apple",
        "D4:61:9D": "Apple",
        "D4:85:64": "Apple",
        "D4:9A:20": "Apple",
        "D8:30:62": "Apple",
        "D8:96:95": "Apple",
        "D8:A2:5E": "Apple",
        "D8:BB:2C": "Apple",
        "DC:2B:2A": "Apple",
        "DC:2B:61": "Apple",
        "DC:37:45": "Apple",
        "DC:56:E7": "Apple",
        "DC:86:D8": "Apple",
        "DC:9B:9C": "Apple",
        "E0:AC:CB": "Apple",
        "E0:B9:BA": "Apple",
        "E0:C9:7A": "Apple",
        "E0:F5:C6": "Apple",
        "E0:F8:47": "Apple",
        "E4:8B:7F": "Apple",
        "E4:C6:3D": "Apple",
        "E4:CE:8F": "Apple",
        "E8:04:0B": "Apple",
        "E8:2A:EA": "Apple",
        "E8:80:2E": "Apple",
        "EC:35:86": "Apple",
        "EC:89:F5": "Apple",
        "F0:18:98": "Apple",
        "F0:D1:A9": "Apple",
        "F0:DB:E2": "Apple",
        "F0:DC:E2": "Apple",
        "F4:0F:24": "Apple",
        "F4:31:C3": "Apple",
        "F4:37:B7": "Apple",
        "F4:5C:89": "Apple",
        "F4:F1:5A": "Apple",
        "F8:1E:DF": "Apple",
        "F8:27:93": "Apple",
        "F8:2F:A8": "Apple",
        "F8:4F:AD": "Apple",
        "F8:D0:27": "Apple",
        "FC:25:3F": "Apple",
        "FC:E9:98": "Apple",
        "00:1B:44": "Samsung",
        "00:12:FB": "Samsung",
        "00:15:99": "Samsung",
        "00:16:32": "Samsung",
        "00:17:C9": "Samsung",
        "00:1A:8A": "Samsung",
        "00:1D:25": "Samsung",
        "00:1E:7D": "Samsung",
        "00:1F:CC": "Samsung",
        "00:21:19": "Samsung",
        "00:23:39": "Samsung",
        "00:D0:59": "Samsung",
        "08:EC:A9": "Samsung",
        "0C:14:20": "Samsung",
        "0C:71:5D": "Samsung",
        "0C:89:10": "Samsung",
        "10:1D:C0": "Samsung",
        "14:49:E0": "Samsung",
        "18:3A:2D": "Samsung",
        "18:3D:A2": "Samsung",
        "1C:62:B8": "Samsung",
        "20:64:32": "Samsung",
        "20:A1:7E": "Samsung",
        "24:4B:03": "Samsung",
        "28:BA:B5": "Samsung",
        "2C:8A:72": "Samsung",
        "30:07:4D": "Samsung",
        "30:19:66": "Samsung",
        "34:23:87": "Samsung",
        "34:AA:8B": "Samsung",
        "38:AA:3C": "Samsung",
        "3C:5A:B4": "Samsung",
        "40:0E:85": "Samsung",
        "40:4D:8E": "Samsung",
        "44:4E:6D": "Samsung",
        "44:5D:A6": "Samsung",
        "48:5A:3F": "Samsung",
        "4C:3C:16": "Samsung",
        "4C:66:41": "Samsung",
        "50:32:37": "Samsung",
        "50:CC:F8": "Samsung",
        "54:88:0E": "Samsung",
        "5C:0A:5B": "Samsung",
        "5C:51:88": "Samsung",
        "60:6B:BD": "Samsung",
        "68:EB:C5": "Samsung",
        "6C:2F:2C": "Samsung",
        "6C:F3:73": "Samsung",
        "70:F9:27": "Samsung",
        "74:45:CE": "Samsung",
        "78:1F:DB": "Samsung",
        "78:59:5E": "Samsung",
        "7C:1C:4E": "Samsung",
        "7C:61:66": "Samsung",
        "80:57:19": "Samsung",
        "84:38:38": "Samsung",
        "84:A4:66": "Samsung",
        "88:32:9B": "Samsung",
        "8C:77:12": "Samsung",
        "8C:C8:CD": "Samsung",
        "90:18:7C": "Samsung",
        "94:35:0A": "Samsung",
        "98:22:EF": "Samsung",
        "9C:02:98": "Samsung",
        "9C:3A:AF": "Samsung",
        "A0:0B:BA": "Samsung",
        "A0:21:B7": "Samsung",
        "A4:EB:D3": "Samsung",
        "A8:F2:74": "Samsung",
        "AC:36:13": "Samsung",
        "AC:5A:14": "Samsung",
        "B4:62:93": "Samsung",
        "B4:EF:39": "Samsung",
        "B8:5E:7B": "Samsung",
        "BC:14:85": "Samsung",
        "BC:20:A4": "Samsung",
        "BC:85:56": "Samsung",
        "C0:BD:D1": "Samsung",
        "C4:57:6E": "Samsung",
        "C8:19:F7": "Samsung",
        "C8:3E:99": "Samsung",
        "C8:A8:23": "Samsung",
        "CC:07:AB": "Samsung",
        "CC:C7:60": "Samsung",
        "D0:22:BE": "Samsung",
        "D0:87:E2": "Samsung",
        "D4:87:D8": "Samsung",
        "D4:E8:B2": "Samsung",
        "D8:31:CF": "Samsung",
        "DC:71:96": "Samsung",
        "E0:91:F5": "Samsung",
        "E4:40:E2": "Samsung",
        "E8:50:8B": "Samsung",
        "EC:1F:72": "Samsung",
        "EC:9B:F3": "Samsung",
        "F0:25:B7": "Samsung",
        "F0:6E:0B": "Samsung",
        "F0:E7:7E": "Samsung",
        "F4:09:D8": "Samsung",
        "F4:7B:5E": "Samsung",
        "F8:04:2E": "Samsung",
        "F8:A9:D0": "Samsung",
        "FC:A1:3E": "Samsung",
        "FC:C2:DE": "Samsung"
    }
    
    mac_prefix = mac[:8]
    return mac_vendors.get(mac_prefix, "Unknown")

def scan_network_advanced():
    """Advanced network scanning"""
    print("\n🔍 Starting Network Scan...")
    
    # Find local IP and network range
    local_ip = get_local_ip()
    network = get_network_range(local_ip)
    
    print(f"📍 Local IP: {local_ip}")
    print(f"🌐 Network Range: {network}.1-254")
    print("⏳ Scanning devices...\n")
    
    # First find active IPs with ping
    active_ips = []
    with ThreadPoolExecutor(max_workers=50) as executor:
        futures = []
        for i in range(1, 255):
            ip = f"{network}.{i}"
            futures.append(executor.submit(ping_host, ip))
        
        for future in as_completed(futures):
            result = future.result()
            if result:
                active_ips.append(result)
    
    # Get ARP table
    arp_table = get_arp_table()
    
    # Combine results and display
    devices = []
    for ip in active_ips:
        hostname = get_hostname(ip)
        mac = arp_table.get(ip, "Unknown")
        vendor = get_vendor_info(mac) if mac != "Unknown" else "Unknown"
        
        devices.append({
            'ip': ip,
            'mac': mac,
            'hostname': hostname,
            'vendor': vendor
        })
    
    # Sort results by IP address
    devices.sort(key=lambda x: tuple(map(int, x['ip'].split('.'))))
    
    return devices, len(active_ips)

def display_results(devices, total_found):
    """Format and display results"""
    print("=" * 80)
    print(f"📊 SCAN RESULTS - {total_found} ACTIVE DEVICES FOUND")
    print("=" * 80)
    
    if not devices:
        print("❌ No active devices found!")
        return
    
    # Table header
    print(f"{'IP ADDRESS':<15} {'MAC ADDRESS':<18} {'HOSTNAME':<25} {'VENDOR':<20}")
    print("-" * 80)
    
    for device in devices:
        ip = device['ip']
        mac = device['mac'] if device['mac'] != "Unknown" else "N/A"
        hostname = device['hostname'] if len(device['hostname']) <= 24 else device['hostname'][:21] + "..."
        vendor = device['vendor'] if len(device['vendor']) <= 19 else device['vendor'][:16] + "..."
        
        print(f"{ip:<15} {mac:<18} {hostname:<25} {vendor:<20}")
    
    print("-" * 80)
    print(f"✅ Total {total_found} devices scanned")

def quick_arp_scan():
    """Quick ARP table scanning"""
    print("\n🚀 Quick ARP Scan...")
    print("📋 Devices in ARP table:\n")
    
    arp_table = get_arp_table()
    
    if not arp_table:
        print("❌ No devices found in ARP table!")
        return
    
    devices = []
    for ip, mac in arp_table.items():
        hostname = get_hostname(ip)
        vendor = get_vendor_info(mac)
        devices.append({
            'ip': ip,
            'mac': mac,
            'hostname': hostname,
            'vendor': vendor
        })
    
    # Sort by IP address
    devices.sort(key=lambda x: tuple(map(int, x['ip'].split('.'))))
    
    display_results(devices, len(devices))

def run():
    """Main function"""
    while True:
        print("""
    ==== ARP Network Scanner ====
    1. Quick ARP Scan (Current ARP Table)
    2. Advanced Network Scan (Ping + ARP)
    3. Show Local Network Information
    0. Return to Main Menu
    """)
        
        choice = input("Select an option: ").strip()
        
        if choice == '1':
            quick_arp_scan()
            input("\n📱 Press Enter to continue...")
            
        elif choice == '2':
            devices, total = scan_network_advanced()
            display_results(devices, total)
            input("\n📱 Press Enter to continue...")
            
        elif choice == '3':
            local_ip = get_local_ip()
            network = get_network_range(local_ip)
            print(f"""
    📍 Local Network Information:
    ├── Local IP: {local_ip}
    ├── Network Range: {network}.0/24
    ├── Gateway: {network}.1 (probably)
    ├── Scan Range: {network}.1 - {network}.254
    └── Operating System: {platform.system()}
    """)
            input("\n📱 Press Enter to continue...")
            
        elif choice == '0':
            break
            
        else:
            print("❌ Invalid selection! Please choose between 0-3.")
            input("\n📱 Press Enter to continue...")

def run_cli(network_range):
    """CLI version for command line usage"""
    try:
        print(f"[+] Network range: {network_range}")
        print(f"[+] Scan started at: {time.strftime('%Y-%m-%d %H:%M:%S')}")
        print("-" * 50)
        
        # Parse network range
        if '/' in network_range:
            # CIDR notation like 192.168.1.0/24
            base_ip = network_range.split('/')[0]
            network = '.'.join(base_ip.split('.')[:-1])
        else:
            # Assume it's a base network like 192.168.1.0
            network = '.'.join(network_range.split('.')[:-1])
        
        print(f"[+] Scanning network: {network}.0/24")
        print(f"[+] IP range: {network}.1 - {network}.254")
        
        # Perform ping scan
        alive_hosts = []
        with ThreadPoolExecutor(max_workers=50) as executor:
            future_to_ip = {executor.submit(ping_host, f"{network}.{i}"): i 
                          for i in range(1, 255)}
            
            for future in as_completed(future_to_ip):
                result = future.result()
                if result:
                    alive_hosts.append(result)
        
        if alive_hosts:
            print(f"\n[+] Found {len(alive_hosts)} active host(s):")
            
            # Get ARP table for MAC addresses
            arp_table = get_arp_table()
            
            for host in sorted(alive_hosts, key=lambda x: int(x.split('.')[-1])):
                try:
                    hostname = socket.gethostbyaddr(host)[0]
                except:
                    hostname = "Unknown"
                
                mac = "Unknown"
                vendor = "Unknown"
                
                # Look for MAC in ARP table
                for arp_entry in arp_table:
                    if arp_entry['ip'] == host:
                        mac = arp_entry['mac']
                        vendor = get_vendor_info(mac)
                        break
                
                print(f"  {host:<15} {mac:<18} {hostname:<20} {vendor}")
        else:
            print(f"\n[-] No active hosts found in range {network}.0/24")
            
    except Exception as e:
        print(f"[-] Error: {e}")
        import sys
        sys.exit(1)

if __name__ == "__main__":
    run()
