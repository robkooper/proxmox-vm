#!/usr/bin/env python3
"""
Ping Subnet Utility

Scans a subnet, pings all IP addresses, and outputs a CSV with:
- IP address
- Hostname (from reverse DNS lookup, if available)
- Status (ACTIVE or DEAD)
"""

import argparse
import csv
import ipaddress
import os
import socket
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, Optional, Tuple

try:
    import dns.resolver
    import dns.reversename
    DNS_AVAILABLE = True
except ImportError:
    DNS_AVAILABLE = False

try:
    from proxmox_utils import ProxmoxConfig
    PROXMOX_UTILS_AVAILABLE = True
except ImportError:
    PROXMOX_UTILS_AVAILABLE = False


def ping_host(ip: str, timeout: int = 1) -> bool:
    """
    Ping a single IP address
    
    Args:
        ip: IP address to ping
        timeout: Timeout in seconds
    
    Returns:
        True if host responds, False otherwise
    """
    # Use ping command appropriate for the OS
    if sys.platform.startswith('win'):
        # Windows ping: -n 1 (one packet), -w timeout in milliseconds
        cmd = ['ping', '-n', '1', '-w', str(timeout * 1000), ip]
    elif sys.platform == 'darwin':
        # macOS ping: -c 1 (one packet), -W timeout in milliseconds
        cmd = ['ping', '-c', '1', '-W', str(timeout * 1000), ip]
    else:
        # Linux ping: -c 1 (one packet), -W timeout in seconds
        cmd = ['ping', '-c', '1', '-W', str(timeout), ip]
    
    try:
        result = subprocess.run(
            cmd,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=timeout + 1
        )
        return result.returncode == 0
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return False


def reverse_dns_lookup(ip: str, timeout: int = 2, dns_server: str = '141.142.2.2') -> Optional[str]:
    """
    Perform reverse DNS lookup to get hostname using specified DNS server
    
    Args:
        ip: IP address to look up
        timeout: Timeout in seconds
        dns_server: DNS server to use for lookup (default: 141.142.2.2)
    
    Returns:
        Hostname if found, None otherwise
    """
    # Try using dnspython with specified DNS server first
    if DNS_AVAILABLE:
        try:
            # Create reverse DNS name (e.g., 1.2.3.4 -> 4.3.2.1.in-addr.arpa)
            reverse_name = dns.reversename.from_address(ip)
            
            # Create resolver with custom DNS server
            resolver = dns.resolver.Resolver()
            resolver.nameservers = [dns_server]
            resolver.timeout = timeout
            resolver.lifetime = timeout
            
            # Query for PTR record
            answer = resolver.resolve(reverse_name, 'PTR')
            if answer:
                # Get first PTR record and remove trailing dot
                hostname = str(answer[0]).rstrip('.')
                return hostname
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.Timeout, Exception):
            # Fall through to socket-based lookup if dnspython fails
            pass
    
    # Fallback to system DNS if dnspython not available or fails
    try:
        socket.setdefaulttimeout(timeout)
        hostname, _, _ = socket.gethostbyaddr(ip)
        return hostname
    except (socket.herror, socket.gaierror, socket.timeout, OSError):
        return None


def check_ip(ip: str, ping_timeout: int = 1, dns_timeout: int = 2, dns_server: str = '141.142.2.2') -> Tuple[str, Optional[str], str]:
    """
    Check a single IP address: ping it and get hostname
    
    Args:
        ip: IP address to check
        ping_timeout: Ping timeout in seconds
        dns_timeout: DNS lookup timeout in seconds
        dns_server: DNS server to use for reverse lookup
    
    Returns:
        Tuple of (ip, hostname, status)
    """
    ip_str = str(ip)
    
    # Ping the host
    is_active = ping_host(ip_str, ping_timeout)
    status = "ACTIVE" if is_active else "DEAD"
    
    # Get hostname (only if active, or always try?)
    # Let's try DNS lookup for all IPs, but it's more likely to work for active ones
    hostname = reverse_dns_lookup(ip_str, dns_timeout, dns_server)
    
    # If IP ends in .1 and no hostname found, use "gateway"
    if not hostname and ip_str.endswith('.1'):
        hostname = 'gateway'
    
    return (ip_str, hostname, status)


def scan_subnet(
    subnet_cidr: str,
    output_file: str,
    max_workers: int = 10,
    ping_timeout: int = 1,
    dns_timeout: int = 2,
    dns_server: str = '141.142.2.2'
):
    """
    Scan a subnet, ping all IPs, and write results to CSV
    
    Args:
        subnet_cidr: Subnet in CIDR notation (e.g., '192.168.1.0/24')
        output_file: Output CSV file path
        max_workers: Maximum number of concurrent ping operations
        ping_timeout: Ping timeout in seconds
        dns_timeout: DNS lookup timeout in seconds
        dns_server: DNS server to use for reverse DNS lookups
    """
    try:
        network = ipaddress.ip_network(subnet_cidr, strict=False)
    except ValueError as e:
        print(f"Error: Invalid subnet CIDR '{subnet_cidr}': {e}", file=sys.stderr)
        sys.exit(1)
    
    # Get all host IPs (excludes network and broadcast addresses)
    all_ips = list(network.hosts())
    total_ips = len(all_ips)
    
    print(f"Scanning subnet {subnet_cidr} ({total_ips} IP addresses)...")
    print(f"Using {max_workers} concurrent workers")
    print(f"Ping timeout: {ping_timeout}s, DNS timeout: {dns_timeout}s")
    print(f"DNS server: {dns_server}")
    if not DNS_AVAILABLE:
        print("Warning: dnspython not available, using system DNS (install with: pip install dnspython)")
    print()
    
    results = []
    completed = 0
    
    # Use ThreadPoolExecutor for parallel pinging
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        # Submit all ping tasks
        future_to_ip = {
            executor.submit(check_ip, str(ip), ping_timeout, dns_timeout, dns_server): ip
            for ip in all_ips
        }
        
        # Process results as they complete
        for future in as_completed(future_to_ip):
            try:
                ip, hostname, status = future.result()
                results.append({
                    'ip': ip,
                    'hostname': hostname or '',
                    'status': status
                })
                completed += 1
                
                # Progress indicator
                if completed % 10 == 0 or completed == total_ips:
                    print(f"Progress: {completed}/{total_ips} ({completed * 100 // total_ips}%)", end='\r')
            except Exception as e:
                ip = future_to_ip[future]
                print(f"\nError checking {ip}: {e}", file=sys.stderr)
                results.append({
                    'ip': str(ip),
                    'hostname': '',
                    'status': 'ERROR'
                })
                completed += 1
    
    print()  # New line after progress
    
    # Sort results by IP address
    results.sort(key=lambda x: ipaddress.ip_address(x['ip']))
    
    # Write to CSV
    print(f"Writing results to {output_file}...")
    with open(output_file, 'w', newline='') as csvfile:
        fieldnames = ['ip', 'hostname', 'status']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        
        writer.writeheader()
        for result in results:
            writer.writerow(result)
    
    # Print summary
    active_count = sum(1 for r in results if r['status'] == 'ACTIVE')
    dead_count = sum(1 for r in results if r['status'] == 'DEAD')
    hostname_count = sum(1 for r in results if r['hostname'])
    
    print(f"\nScan complete!")
    print(f"Total IPs: {total_ips}")
    print(f"ACTIVE: {active_count}")
    print(f"DEAD: {dead_count}")
    print(f"With hostname: {hostname_count}")
    print(f"Results saved to: {output_file}")


def get_dns_server_from_config(config_file: str = 'proxmox.ini') -> Optional[str]:
    """
    Get DNS server from proxmox.ini configuration
    
    Args:
        config_file: Path to configuration file
    
    Returns:
        First DNS server from config, or None if not available
    """
    if not PROXMOX_UTILS_AVAILABLE:
        return None
    
    try:
        if not os.path.exists(config_file):
            return None
        
        config = ProxmoxConfig(config_file)
        if not config.has_netbox_config():
            return None
        
        dns_servers = config.get_netbox_dns_servers()
        if dns_servers and len(dns_servers) > 0:
            return dns_servers[0]  # Return first DNS server
    except Exception:
        # Silently fail - will use default
        pass
    
    return None


def main():
    parser = argparse.ArgumentParser(
        description='Scan a subnet, ping all IPs, and output CSV with IP, hostname, and status',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s 192.168.1.0/24
  %(prog)s 10.0.0.0/24 -o results.csv
  %(prog)s 172.16.0.0/16 -w 100 -t 2
        """
    )
    
    parser.add_argument(
        'subnet',
        help='Subnet in CIDR notation (e.g., 192.168.1.0/24)'
    )
    
    parser.add_argument(
        '--config',
        default='proxmox.ini',
        help='Path to configuration file (default: proxmox.ini)'
    )
    
    parser.add_argument(
        '-o', '--output',
        default='subnet-scan.csv',
        help='Output CSV file (default: subnet-scan.csv)'
    )
    
    parser.add_argument(
        '-w', '--workers',
        type=int,
        default=10,
        help='Maximum number of concurrent ping operations (default: 10)'
    )
    
    parser.add_argument(
        '-t', '--timeout',
        type=int,
        default=1,
        help='Ping timeout in seconds (default: 1)'
    )
    
    parser.add_argument(
        '--dns-timeout',
        type=int,
        default=2,
        help='DNS lookup timeout in seconds (default: 2)'
    )
    
    parser.add_argument(
        '--dns-server',
        default=None,
        help='DNS server to use for reverse DNS lookups (default: from proxmox.ini or 141.142.2.2)'
    )
    
    args = parser.parse_args()
    
    # Determine DNS server: command line arg > config file > default
    dns_server = args.dns_server
    if not dns_server:
        dns_server = get_dns_server_from_config(args.config)
    if not dns_server:
        dns_server = '141.142.2.2'  # Final fallback
    
    scan_subnet(
        args.subnet,
        args.output,
        max_workers=args.workers,
        ping_timeout=args.timeout,
        dns_timeout=args.dns_timeout,
        dns_server=dns_server
    )


if __name__ == '__main__':
    main()
