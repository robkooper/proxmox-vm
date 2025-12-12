#!/usr/bin/env python3
"""
Delete DNS record from NetBox

Usage:
    delete-dns.py <ip_address>

Example:
    delete-dns.py 192.168.1.100

The script will delete the IP address record from NetBox.
"""

import sys
from proxmox_utils import (
    ProxmoxConfig,
    logger
)
from netbox_utils import (
    connect_netbox,
    delete_ip_address_in_netbox,
    NetboxConnectionError,
    NetboxDependencyError
)


def main():
    if len(sys.argv) != 2:
        logger.error("Usage: delete-dns.py <ip_address>")
        logger.error("Example: delete-dns.py 192.168.1.100")
        sys.exit(1)
    
    ip_address = sys.argv[1].strip()
    
    if not ip_address:
        logger.error("IP address cannot be empty")
        sys.exit(1)
    
    # Load configuration
    try:
        config = ProxmoxConfig('proxmox.ini')
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
    if delete_ip_address_in_netbox(nb, ip_address):
        sys.exit(0)
    else:
        sys.exit(1)


if __name__ == '__main__':
    main()
