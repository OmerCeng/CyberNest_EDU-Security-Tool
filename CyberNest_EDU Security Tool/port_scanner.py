import socket
from datetime import datetime

def port_scan(target, start_port=1, end_port=1024):
    print(f"\nTarget: {target}")
    print(f"Scan started at: {datetime.now()}")
    print(f"Port range: {start_port}-{end_port}\n")

    try:
        for port in range(start_port, end_port + 1):
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            socket.setdefaulttimeout(0.5)
            result = sock.connect_ex((target, port))
            if result == 0:
                print(f"[+] Port {port} is open")
            sock.close()
    except KeyboardInterrupt:
        print("\nExiting scan...")
    except socket.gaierror:
        print("Could not resolve target address.")
    except socket.error:
        print("Could not connect to target.")

    print(f"\nScan completed at: {datetime.now()}")


def run():
    print(f"""
    🔍 Port Scanner Tool
    {'='*50}
    Enter target IP address and port range to scan for open ports.
    """)
    
    while True:
        target = input("\nEnter target IP address (or type 'exit' to return): ")
        if target.lower() == 'exit':
            return
            
        if not target.replace('.', '').replace('-', '').replace(':', '').replace('/', '').isalnum():
            print("❌ Please enter a valid IP address or hostname.")
            continue
            
        port_range = input("Enter port range (e.g. 20-80) or single port (e.g. 80): ")
        if port_range.lower() == 'exit':
            return
            
        try:
            if '-' in port_range:
                start_port, end_port = map(int, port_range.split('-'))
            else:
                start_port = end_port = int(port_range)
                
            if start_port < 1 or end_port > 65535 or start_port > end_port:
                print("❌ Port range must be between 1-65535 and start port must be <= end port.")
                continue
                
            port_scan(target, start_port, end_port)
            
        except ValueError:
            print("❌ Invalid port range. Please enter in 'start-end' format or single port number.")
        except Exception as e:
            print(f"❌ An error occurred: {e}")
            
        print("\n" + "="*50)



