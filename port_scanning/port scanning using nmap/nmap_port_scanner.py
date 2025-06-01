import nmap, sys, argparse
from datetime import datetime

def parse_arguments():
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(description="Nmap Port Scanner")
    parser.add_argument("target", help="Target IP or hostname to scan")
    parser.add_argument("--ports", default="1-1000", help="Port range to scan (default: 1-1000)")
    parser.add_argument("--dns", default="8.8.8.8,8.8.4.4", help="DNS servers (default: Google DNS)")
    return parser.parse_args()

def print_header(message):
    """Print a formatted header."""
    print("\n" + "=" * 30 + f" {message} " + "=" * 30)

def print_subheader(message):
    """Print a formatted subheader."""
    print("-" * 30 + f" {message} " + "-" * 30)

def main():
    # Parse command-line arguments
    args = parse_arguments()
    target = args.target
    port_range = args.ports
    dns_servers = args.dns

    try:
        # Initialize Nmap PortScanner
        nm = nmap.PortScanner()
        
        print_header("Starting Nmap Scan")
        print(f"[*] Scanning target: {target}")
        print(f"[*] Port range: {port_range}")
        print(f"[*] DNS servers: {dns_servers}")

        # Perform scan with specified arguments
        nm.scan(target, arguments=f"-O --dns-servers {dns_servers} -sV -p {port_range}")

        # Print scan statistics
        scan_stats = nm.scanstats()
        print(f"[*] Scan completed at: {scan_stats['timestr']}")
        print(f"[*] Elapsed time: {scan_stats['elapsed']}s")
        print(f"[*] Hosts - Up: {scan_stats['uphosts']}, Down: {scan_stats['downhosts']}, Total: {scan_stats['totalhosts']}")
        print(f"[*] Equivalent command: {nm.command_line()}")

        # Iterate through discovered hosts
        for host in nm.all_hosts():
            print_header(f"Host: {host}")
            
            # Retrieve host information
            hostname = nm[host].hostname() or "Unknown"
            ipv4 = nm[host].get("addresses", {}).get("ipv4", "N/A")
            mac = nm[host].get("addresses", {}).get("mac", "N/A")
            vendor = nm[host].get("vendor", "Unknown")
            os_match = nm[host].get("osmatch", [{}])[0].get("name", "Unknown")

            # Print host information
            print(f"Hostname: {hostname}")
            print(f"IPv4: {ipv4}")
            print(f"MAC Address: {mac}")
            print(f"Vendor: {vendor}")
            print(f"OS: {os_match}")

            # Retrieve and display open TCP ports
            open_tcp_ports = nm[host].all_tcp()
            if open_tcp_ports:
                print_subheader("Open TCP Ports")
                for port in open_tcp_ports:
                    port_details = nm[host].tcp(port)
                    print(f"TCP Port: {port}")
                    print(f"  State: {port_details.get('state', 'N/A')}")
                    print(f"  Reason: {port_details.get('reason', 'N/A')}")
                    print(f"  Service: {port_details.get('name', 'N/A')}")
                    print(f"  Product: {port_details.get('product', 'N/A')}")
                    print(f"  Version: {port_details.get('version', 'N/A')}")
                    print(f"  Extra Info: {port_details.get('extrainfo', 'N/A')}")
                    print(f"  CPE: {port_details.get('cpe', 'N/A')}")
                    print("-" * 50)

            # Retrieve and display open UDP ports
            open_udp_ports = nm[host].all_udp()
            if open_udp_ports:
                print_subheader("Open UDP Ports")
                print(f"UDP Ports: {', '.join(map(str, open_udp_ports))}")

    except nmap.PortScannerError as e:
        print(f"[!] Nmap error: {e}")
        sys.exit(1)
    except Exception as e:
        print(f"[!] Unexpected error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()