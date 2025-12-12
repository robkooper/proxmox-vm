#!/usr/bin/env python3
"""
Delete DNS record from NetBox

Usage:
    delete-dns.py -n <hostname>
    delete-dns.py -i <ip_address>

Examples:
    delete-dns.py -n myserver
    delete-dns.py -i 192.168.1.100

The script will delete the IP address record from NetBox.
If domain is configured in proxmox.ini, FQDN (hostname.domain) will be used for hostname lookup.
"""

import argparse
import sys
from proxmox_utils import (
    ProxmoxConfig,
    logger
)
from netbox_utils import (
    connect_netbox,
    delete_ip_address_in_netbox,
    delete_ip_address_by_hostname_in_netbox,
    NetboxConnectionError,
    NetboxDependencyError
)


def main():
    parser = argparse.ArgumentParser(
        description='Delete DNS record from NetBox by hostname or IP address',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  # Delete by hostname
  %(prog)s -n myserver
  
  # Delete by IP address
  %(prog)s -i 192.168.1.100
  
Note: If domain is configured in proxmox.ini, FQDN (hostname.domain) will be used for hostname lookup.
        '''
    )
    
    parser.add_argument('--config', default='proxmox.ini',
                        help='Path to configuration file (default: proxmox.ini)')
    parser.add_argument('-n', '--name', dest='hostname',
                        help='Hostname to delete')
    parser.add_argument('-i', '--ip', dest='ip_address',
                        help='IP address to delete')
    
    args = parser.parse_args()
    
    # Validate arguments
    if not args.hostname and not args.ip_address:
        logger.error("Must specify either --name (-n) or --ip (-i)")
        parser.print_help()
        sys.exit(1)
    
    if args.hostname and args.ip_address:
        logger.error("Cannot specify both --name and --ip")
        sys.exit(1)
    
    # Load configuration
    try:
        config = ProxmoxConfig(args.config)
    except FileNotFoundError:
        logger.error("Configuration file 'proxmox.ini' not found")
        sys.exit(1)
    except Exception as e:
        logger.error(f"Error loading configuration: {e}")
        sys.exit(1)
    
    # Check NetBox configuration
    if not config.has_netbox_config():
        logger.error("NetBox configuration not found in proxmox.ini")
        sys.exit(1)
    
    netbox_url = config.get_netbox_url()
    netbox_token = config.get_netbox_token()
    netbox_domain = config.get_netbox_domain()
    
    if not netbox_url or not netbox_token:
        logger.error("NetBox URL and token must be configured in proxmox.ini")
        logger.error("Set [netbox] url and token in proxmox.ini")
        sys.exit(1)
    
    # Connect to NetBox
    try:
        nb = connect_netbox(netbox_url, netbox_token)
    except NetboxDependencyError as e:
        logger.error(str(e))
        sys.exit(1)
    except NetboxConnectionError as e:
        logger.error(str(e))
        sys.exit(1)
    
    logger.info("✓ Connected to NetBox")
    
    # Delete IP address from IPAM
    success = False
    if args.hostname:
        hostname = args.hostname.strip()
        if not hostname:
            logger.error("Hostname cannot be empty")
            sys.exit(1)
        
        # Show what DNS name will be used
        if netbox_domain:
            dns_name = f"{hostname}.{netbox_domain}"
            logger.info(f"→ Deleting DNS record for FQDN: {dns_name}")
        else:
            dns_name = hostname
            logger.info(f"→ Deleting DNS record for hostname: {dns_name} (no domain configured)")
        
        success = delete_ip_address_by_hostname_in_netbox(nb, hostname, netbox_domain)
    elif args.ip_address:
        ip_address = args.ip_address.strip()
        if not ip_address:
            logger.error("IP address cannot be empty")
            sys.exit(1)
        
        logger.info(f"→ Deleting DNS record for IP: {ip_address}")
        success = delete_ip_address_in_netbox(nb, ip_address)
    
    if success:
        sys.exit(0)
    else:
        sys.exit(1)


if __name__ == '__main__':
    main()
