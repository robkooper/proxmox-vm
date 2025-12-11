#!/usr/bin/env python3
"""
Proxmox Firewall Management Script

Add or delete firewall rules for VMs by hostname:port with optional IP address restriction.
"""

import argparse
import re
import sys
from typing import Optional
from proxmox_utils import (
    ProxmoxConfig,
    connect_proxmox,
    find_vm_by_name,
    find_vm_by_id,
    add_firewall_rule,
    delete_firewall_rule,
    get_firewall_rules,
    print_error,
    print_success,
    print_info,
    ProxmoxError,
    ProxmoxConnectionError
)


def parse_hostname_port(hostname_port: str) -> tuple:
    """
    Parse hostname:port string
    
    Args:
        hostname_port: String in format "hostname:port" or just "hostname"
    
    Returns:
        Tuple of (hostname, port) where port can be None
    """
    if ':' not in hostname_port:
        return (hostname_port, None)
    
    parts = hostname_port.rsplit(':', 1)
    if len(parts) != 2:
        raise ValueError(f"Invalid format: {hostname_port}. Expected 'hostname:port'")
    
    hostname = parts[0]
    try:
        port = int(parts[1])
        if port < 1 or port > 65535:
            raise ValueError(f"Port must be between 1 and 65535, got {port}")
    except ValueError as e:
        raise ValueError(f"Invalid port number: {parts[1]}") from e
    
    return (hostname, port)


def validate_ip_address(ip: str) -> bool:
    """
    Validate IP address format
    
    Args:
        ip: IP address string
    
    Returns:
        True if valid, False otherwise
    """
    try:
        import ipaddress
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False


def determine_protocol(port: Optional[int]) -> str:
    """
    Determine protocol based on port number (defaults to tcp)
    
    Args:
        port: Port number
    
    Returns:
        Protocol string ('tcp', 'udp', or 'icmp')
    """
    if port is None:
        return 'icmp'
    # Common UDP ports
    udp_ports = {53, 67, 68, 123, 161, 162, 514, 520, 1900, 5353}
    if port in udp_ports:
        return 'udp'
    return 'tcp'


def add_rule(proxmox, hostname: str, port: Optional[int], source_ip: Optional[str] = None):
    """
    Add a firewall rule to a VM
    
    Args:
        proxmox: ProxmoxAPI instance
        hostname: VM hostname
        port: Port number (None for ICMP)
        source_ip: Optional source IP address restriction
    """
    # Find VM by hostname
    vm = find_vm_by_name(proxmox, hostname)
    if not vm:
        print_error(f"VM '{hostname}' not found")
        sys.exit(1)
    
    vmid = vm['vmid']
    node = vm['node']
    
    protocol = determine_protocol(port)
    
    if port is None:
        comment = f"ICMP from {source_ip}" if source_ip else "ICMP"
    else:
        comment = f"Port {port} from {source_ip}" if source_ip else f"Port {port}"
    
    print_info(f"Adding firewall rule to VM {vmid} ({hostname}) on node {node}")
    print_info(f"  Rule: {protocol.upper()} port {port if port else 'ICMP'} {'from ' + source_ip if source_ip else '(all sources)'}")
    
    if add_firewall_rule(proxmox, node, vmid, port, protocol, source_ip, comment):
        print_success("Firewall rule added successfully")
    else:
        print_error("Failed to add firewall rule")
        sys.exit(1)


def delete_rule(proxmox, hostname: str, port: Optional[int], source_ip: Optional[str] = None):
    """
    Delete a firewall rule from a VM
    
    Args:
        proxmox: ProxmoxAPI instance
        hostname: VM hostname
        port: Port number (None for ICMP)
        source_ip: Optional source IP address (only delete rule matching this IP)
    """
    # Find VM by hostname
    vm = find_vm_by_name(proxmox, hostname)
    if not vm:
        print_error(f"VM '{hostname}' not found")
        sys.exit(1)
    
    vmid = vm['vmid']
    node = vm['node']
    
    protocol = determine_protocol(port)
    
    print_info(f"Deleting firewall rule from VM {vmid} ({hostname}) on node {node}")
    if source_ip:
        print_info(f"  Rule: {protocol.upper()} port {port if port else 'ICMP'} from {source_ip}")
    else:
        print_info(f"  Rule: {protocol.upper()} port {port if port else 'ICMP'} (all sources)")
    
    if delete_firewall_rule(proxmox, node, vmid, port, protocol, source_ip):
        print_success("Firewall rule deleted successfully")
    else:
        print_error("Failed to delete firewall rule (rule may not exist)")
        sys.exit(1)


def list_rules(proxmox, hostname: str):
    """
    List all firewall rules for a VM
    
    Args:
        proxmox: ProxmoxAPI instance
        hostname: VM hostname
    """
    # Find VM by hostname
    vm = find_vm_by_name(proxmox, hostname)
    if not vm:
        print_error(f"VM '{hostname}' not found")
        sys.exit(1)
    
    vmid = vm['vmid']
    node = vm['node']
    
    print_info(f"Firewall rules for VM {vmid} ({hostname}) on node {node}:")
    print()
    
    rules = get_firewall_rules(proxmox, node, vmid)
    
    if not rules:
        print_info("No firewall rules found")
        return
    
    # Print header
    print(f"{'Pos':<6} {'Action':<8} {'Direction':<10} {'Protocol':<8} {'Port':<8} {'Source':<20} {'Comment':<30}")
    print("=" * 100)
    
    for rule in rules:
        pos = rule.get('pos', 'N/A')
        action = rule.get('action', 'N/A')
        direction = rule.get('dir', 'N/A')
        protocol = rule.get('proto', 'N/A')
        port = rule.get('dport', 'N/A')
        source = rule.get('source', 'N/A')
        comment = rule.get('comment', '')
        
        print(f"{pos:<6} {action:<8} {direction:<10} {protocol:<8} {port:<8} {source:<20} {comment:<30}")


def main():
    parser = argparse.ArgumentParser(
        description='Manage firewall rules for Proxmox VMs',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  # Add rule for port 8080 on webserver (all sources)
  %(prog)s add webserver:8080
  
  # Add rule for port 3306 on dbserver from specific IP
  %(prog)s add dbserver:3306 --ip 192.168.1.100
  
  # Delete rule for port 8080 on webserver (all sources)
  %(prog)s delete webserver:8080
  
  # Delete rule for port 3306 on dbserver from specific IP only
  %(prog)s delete dbserver:3306 --ip 192.168.1.100
  
  # List all firewall rules for a VM
  %(prog)s list webserver
        '''
    )
    
    parser.add_argument('action', choices=['add', 'delete', 'list'],
                       help='Action to perform: add, delete, or list firewall rules')
    parser.add_argument('hostname_port',
                       help='VM hostname:port (e.g., webserver:80) or just hostname for list action')
    parser.add_argument('--ip', '--source-ip', dest='source_ip',
                       help='Source IP address restriction (optional)')
    parser.add_argument('--config', default='proxmox.ini',
                       help='Path to configuration file (default: proxmox.ini)')
    
    args = parser.parse_args()
    
    # Validate IP address if provided
    if args.source_ip and not validate_ip_address(args.source_ip):
        print_error(f"Invalid IP address: {args.source_ip}")
        sys.exit(1)
    
    # Load configuration
    try:
        config = ProxmoxConfig(args.config)
    except Exception as e:
        print_error(f"Failed to load configuration: {e}")
        print_info("Copy proxmox.ini.example to proxmox.ini and configure it")
        sys.exit(1)
    
    # Connect to Proxmox
    try:
        proxmox = connect_proxmox(config)
    except ProxmoxConnectionError as e:
        print_error(str(e))
        sys.exit(1)
    print_success("Connected to Proxmox")
    
    # Parse hostname:port
    if args.action == 'list':
        hostname = args.hostname_port
        port = None
    else:
        try:
            hostname, port = parse_hostname_port(args.hostname_port)
        except ValueError as e:
            print_error(str(e))
            sys.exit(1)
    
    # Perform action
    try:
        if args.action == 'add':
            add_rule(proxmox, hostname, port, args.source_ip)
        elif args.action == 'delete':
            delete_rule(proxmox, hostname, port, args.source_ip)
        elif args.action == 'list':
            list_rules(proxmox, hostname)
    except KeyboardInterrupt:
        print("\n\nOperation cancelled by user")
        sys.exit(1)
    except Exception as e:
        print_error(f"Unexpected error: {e}")
        sys.exit(1)


if __name__ == '__main__':
    main()

