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
    while True:
        target = input("Enter target IP address (or type 'exit' to return): ")
        if target.lower() == 'exit':
            return
        port_range = input("Enter port range (e.g. 20-80) (or type 'exit' to return): ")
        if port_range.lower() == 'exit':
            return
        try:
            start_port, end_port = map(int, port_range.split('-'))
            port_scan(target, start_port, end_port)
        except ValueError:
            print("Invalid port range. Please enter in 'start-end' format.")
        except Exception as e:
            print(f"An error occurred: {e}")



