#!/usr/bin/env python3
"""
Create DNS record in NetBox

Usage:
    create-dns.py <hostname> <ip_address>

Example:
    create-dns.py myserver 192.168.1.100

The script will create/update an IP address in NetBox IPAM:
- If domain is configured in proxmox.ini: uses FQDN (hostname.domain)
- If domain is not configured: uses just the hostname
"""

import sys
from typing import Optional
from proxmox_utils import (
    ProxmoxConfig,
    logger
)
from netbox_utils import (
    connect_netbox,
    get_tenant_id,
    create_ip_address_for_hostname_in_netbox,
    NetboxError,
    NetboxConnectionError,
    NetboxDependencyError
)


def main():
    if len(sys.argv) != 3:
        logger.error("Usage: create-dns.py <hostname> <ip_address>")
        logger.error("Example: create-dns.py myserver 192.168.1.100")
        logger.error("Note: If domain is configured in proxmox.ini, FQDN (hostname.domain) will be used")
        sys.exit(1)
    
    hostname = sys.argv[1].strip()
    ip_address = sys.argv[2].strip()
    
    if not hostname:
        logger.error("Hostname cannot be empty")
        sys.exit(1)
    
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
    netbox_domain = config.get_netbox_domain()
    netbox_tenant_slug = config.get_netbox_tenant()
    netbox_subnet = config.get_netbox_subnet()
    
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
    
    # Get tenant ID if tenant slug is configured
    tenant_id = None
    if netbox_tenant_slug:
        tenant_id = get_tenant_id(nb, netbox_tenant_slug)
        if tenant_id is None:
            logger.error(f"Failed to find tenant '{netbox_tenant_slug}' in NetBox")
            sys.exit(1)
        logger.info(f"→ Using tenant: {netbox_tenant_slug} (ID: {tenant_id})")
    
    # Show what DNS name will be used
    if netbox_domain:
        dns_name = f"{hostname}.{netbox_domain}"
        logger.info(f"→ Setting IP {ip_address} for FQDN: {dns_name}")
    else:
        dns_name = hostname
        logger.info(f"→ Setting IP {ip_address} for hostname: {dns_name} (no domain configured)")
    
    # Set IP address
    if create_ip_address_for_hostname_in_netbox(nb, hostname, ip_address, netbox_domain, tenant_id, netbox_subnet):
        sys.exit(0)
    else:
        sys.exit(1)


if __name__ == '__main__':
    main()
