"""Firewall management commands"""

import argparse
import sys

from proxmox.proxmox_utils import (
    ProxmoxConfig,
    connect_proxmox,
    find_vm_by_name,
    find_vm_by_id,
    add_firewall_rule,
    delete_firewall_rule,
    get_firewall_rules,
    logger,
    ProxmoxConnectionError
)


def find_vm(proxmox, vm_identifier: str):
    """
    Find VM by name or ID
    
    Args:
        proxmox: ProxmoxAPI instance
        vm_identifier: VM name or ID (as string)
    
    Returns:
        VM info dict with 'vmid', 'name', 'node', 'status' or None if not found
    """
    # Try to parse as integer (VM ID)
    try:
        vmid = int(vm_identifier)
        return find_vm_by_id(proxmox, vmid)
    except ValueError:
        # Not an integer, treat as hostname
        return find_vm_by_name(proxmox, vm_identifier)


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


def determine_protocol(port) -> str:
    """
    Determine protocol based on port number (defaults to tcp)
    
    Args:
        port: Port number (can be None for ICMP)
    
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


def setup_create_parser(parser):
    """Setup argument parser for firewall create command"""
    parser.add_argument('vm',
                        help='VM name or ID (e.g., webserver or 100)')
    parser.add_argument('port', type=int, nargs='?',
                        help='Port number (optional, omit for ICMP)')
    parser.add_argument('--ip', '--source-ip', dest='source_ip',
                        help='Source IP address restriction (optional)')


def setup_delete_parser(parser):
    """Setup argument parser for firewall delete command"""
    parser.add_argument('vm',
                        help='VM name or ID (e.g., webserver or 100)')
    parser.add_argument('port', type=int, nargs='?',
                        help='Port number (optional, omit for ICMP)')
    parser.add_argument('--ip', '--source-ip', dest='source_ip',
                        help='Source IP address (only delete rule matching this IP)')


def setup_list_parser(parser):
    """Setup argument parser for firewall list command"""
    parser.add_argument('vm',
                        help='VM name or ID (e.g., webserver or 100)')


def handle_create(args):
    """Handle firewall create command"""
    # Validate IP address if provided
    if args.source_ip and not validate_ip_address(args.source_ip):
        logger.error(f"Invalid IP address: {args.source_ip}")
        sys.exit(1)
    
    # Validate port if provided
    port = args.port
    if port is not None and (port < 1 or port > 65535):
        logger.error(f"Port must be between 1 and 65535, got {port}")
        sys.exit(1)
    
    # Load configuration
    try:
        config = ProxmoxConfig(args.config)
    except Exception as e:
        logger.error(f"Failed to load configuration: {e}")
        logger.info("→ Copy proxmox.ini.example to proxmox.ini and configure it")
        sys.exit(1)
    
    # Connect to Proxmox
    try:
        proxmox = connect_proxmox(config)
    except ProxmoxConnectionError as e:
        logger.error(str(e))
        sys.exit(1)
    logger.info("✓ Connected to Proxmox")
    
    # Find VM by name or ID
    vm = find_vm(proxmox, args.vm)
    if not vm:
        logger.error(f"VM '{args.vm}' not found")
        sys.exit(1)
    
    vmid = vm['vmid']
    vm_name = vm['name']
    node = vm['node']
    
    protocol = determine_protocol(port)
    
    if port is None:
        comment = f"ICMP from {args.source_ip}" if args.source_ip else "ICMP"
    else:
        comment = f"Port {port} from {args.source_ip}" if args.source_ip else f"Port {port}"
    
    logger.info(f"→ Adding firewall rule to VM {vmid} ({vm_name}) on node {node}")
    logger.info(f"→   Rule: {protocol.upper()} port {port if port else 'ICMP'} {'from ' + args.source_ip if args.source_ip else '(all sources)'}")
    
    if add_firewall_rule(proxmox, node, vmid, port, protocol, args.source_ip, comment):
        logger.info("✓ Firewall rule added successfully")
    else:
        logger.error("Failed to add firewall rule")
        sys.exit(1)


def handle_delete(args):
    """Handle firewall delete command"""
    # Validate IP address if provided
    if args.source_ip and not validate_ip_address(args.source_ip):
        logger.error(f"Invalid IP address: {args.source_ip}")
        sys.exit(1)
    
    # Validate port if provided
    port = args.port
    if port is not None and (port < 1 or port > 65535):
        logger.error(f"Port must be between 1 and 65535, got {port}")
        sys.exit(1)
    
    # Load configuration
    try:
        config = ProxmoxConfig(args.config)
    except Exception as e:
        logger.error(f"Failed to load configuration: {e}")
        logger.info("→ Copy proxmox.ini.example to proxmox.ini and configure it")
        sys.exit(1)
    
    # Connect to Proxmox
    try:
        proxmox = connect_proxmox(config)
    except ProxmoxConnectionError as e:
        logger.error(str(e))
        sys.exit(1)
    logger.info("✓ Connected to Proxmox")
    
    # Find VM by name or ID
    vm = find_vm(proxmox, args.vm)
    if not vm:
        logger.error(f"VM '{args.vm}' not found")
        sys.exit(1)
    
    vmid = vm['vmid']
    vm_name = vm['name']
    node = vm['node']
    
    protocol = determine_protocol(port)
    
    logger.info(f"→ Deleting firewall rule from VM {vmid} ({vm_name}) on node {node}")
    if args.source_ip:
        logger.info(f"→   Rule: {protocol.upper()} port {port if port else 'ICMP'} from {args.source_ip}")
    else:
        logger.info(f"→   Rule: {protocol.upper()} port {port if port else 'ICMP'} (all sources)")
    
    if delete_firewall_rule(proxmox, node, vmid, port, protocol, args.source_ip):
        logger.info("✓ Firewall rule deleted successfully")
    else:
        logger.error("Failed to delete firewall rule (rule may not exist)")
        sys.exit(1)


def handle_list(args):
    """Handle firewall list command"""
    # Load configuration
    try:
        config = ProxmoxConfig(args.config)
    except Exception as e:
        logger.error(f"Failed to load configuration: {e}")
        logger.info("→ Copy proxmox.ini.example to proxmox.ini and configure it")
        sys.exit(1)
    
    # Connect to Proxmox
    try:
        proxmox = connect_proxmox(config)
    except ProxmoxConnectionError as e:
        logger.error(str(e))
        sys.exit(1)
    logger.info("✓ Connected to Proxmox")
    
    # Find VM by name or ID
    vm = find_vm(proxmox, args.vm)
    if not vm:
        logger.error(f"VM '{args.vm}' not found")
        sys.exit(1)
    
    vmid = vm['vmid']
    vm_name = vm['name']
    node = vm['node']
    
    # Get all firewall rules
    rules = get_firewall_rules(proxmox, node, vmid)
    
    if not rules:
        print(f"\nNo firewall rules found for VM {vmid} ({vm_name})")
        return
    
    # Print header
    print("\n" + "=" * 80)
    print(f"Firewall Rules for VM {vmid} ({vm_name}) on node {node}:")
    print("=" * 80)
    print(f"{'Action':<8} {'Type':<6} {'Protocol':<10} {'Port':<10} {'Source IP':<20} {'Comment':<30}")
    print("-" * 80)
    
    # Sort by position if available
    rules_sorted = sorted(rules, key=lambda x: x.get('pos', 0))
    
    # Print each rule
    for rule in rules_sorted:
        action = rule.get('action', 'N/A')
        rule_type = rule.get('type', 'N/A')
        protocol = rule.get('proto', 'N/A')
        port = rule.get('dport', 'N/A')
        source_ip = rule.get('source', 'any')
        comment = rule.get('comment', '')
        enabled = rule.get('enable', 1)
        
        # Show disabled rules with a marker
        if not enabled:
            action = f"{action} (DISABLED)"
        
        print(f"{action:<8} {rule_type:<6} {protocol:<10} {port:<10} {source_ip:<20} {comment:<30}")
    
    print("=" * 80)
    print(f"\nTotal: {len(rules)} rule(s)")
