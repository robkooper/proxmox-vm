"""DNS management commands"""

import argparse
import ipaddress
import sys

from proxmox.proxmox_utils import (
    ProxmoxConfig,
    logger
)
from proxmox.netbox_utils import (
    connect_netbox,
    get_tenant_id,
    create_ip_address_for_hostname_in_netbox,
    delete_ip_address_in_netbox,
    delete_ip_address_by_hostname_in_netbox,
    NetboxError,
    NetboxConnectionError,
    NetboxDependencyError
)


def setup_create_parser(parser):
    """Setup argument parser for DNS create command"""
    parser.add_argument('hostname',
                        help='Hostname for the DNS record')
    parser.add_argument('ip_address',
                        help='IP address for the DNS record')


def setup_delete_parser(parser):
    """Setup argument parser for DNS delete command"""
    parser.add_argument('identifier',
                        help='Hostname or IP address to delete')


def handle_create(args):
    """Handle DNS create command"""
    hostname = args.hostname.strip()
    ip_address = args.ip_address.strip()
    
    if not hostname:
        logger.error("Hostname cannot be empty")
        sys.exit(1)
    
    if not ip_address:
        logger.error("IP address cannot be empty")
        sys.exit(1)
    
    # Load configuration
    try:
        config = ProxmoxConfig(args.config)
    except FileNotFoundError as e:
        logger.error(str(e))
        sys.exit(1)
    except Exception as e:
        logger.error(f"Error loading configuration: {e}")
        sys.exit(1)
    
    # Check NetBox configuration
    if not config.has_netbox_config():
        logger.error("NetBox configuration not found in configuration file")
        logger.error(f"Set [netbox] section in {config.config_file}")
        sys.exit(1)
    
    netbox_url = config.get_netbox_url()
    netbox_token = config.get_netbox_token()
    netbox_domain = config.get_netbox_domain()
    netbox_tenant_slug = config.get_netbox_tenant()
    netbox_subnet = config.get_netbox_subnet()
    
    if not netbox_url or not netbox_token:
        logger.error("NetBox URL and token must be configured")
        logger.error(f"Set [netbox] url and token in {config.config_file}")
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


def is_ip_address(identifier: str) -> bool:
    """
    Check if the identifier is an IP address
    
    Args:
        identifier: String to check
    
    Returns:
        True if it's a valid IP address, False otherwise
    """
    try:
        ipaddress.ip_address(identifier)
        return True
    except ValueError:
        return False


def handle_delete(args):
    """Handle DNS delete command"""
    identifier = args.identifier.strip()
    
    if not identifier:
        logger.error("Identifier cannot be empty")
        sys.exit(1)
    
    # Load configuration
    try:
        config = ProxmoxConfig(args.config)
    except FileNotFoundError as e:
        logger.error(str(e))
        sys.exit(1)
    except Exception as e:
        logger.error(f"Error loading configuration: {e}")
        sys.exit(1)
    
    # Check NetBox configuration
    if not config.has_netbox_config():
        logger.error("NetBox configuration not found in configuration file")
        logger.error(f"Set [netbox] section in {config.config_file}")
        sys.exit(1)
    
    netbox_url = config.get_netbox_url()
    netbox_token = config.get_netbox_token()
    netbox_domain = config.get_netbox_domain()
    
    if not netbox_url or not netbox_token:
        logger.error("NetBox URL and token must be configured")
        logger.error(f"Set [netbox] url and token in {config.config_file}")
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
    
    # Determine if identifier is IP address or hostname
    success = False
    if is_ip_address(identifier):
        # It's an IP address
        logger.info(f"→ Deleting DNS record for IP: {identifier}")
        success = delete_ip_address_in_netbox(nb, identifier)
    else:
        # It's a hostname
        hostname = identifier
        # Show what DNS name will be used
        if netbox_domain:
            dns_name = f"{hostname}.{netbox_domain}"
            logger.info(f"→ Deleting DNS record for FQDN: {dns_name}")
        else:
            dns_name = hostname
            logger.info(f"→ Deleting DNS record for hostname: {dns_name} (no domain configured)")
        
        success = delete_ip_address_by_hostname_in_netbox(nb, hostname, netbox_domain)
    
    if success:
        sys.exit(0)
    else:
        sys.exit(1)
