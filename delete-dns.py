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
import ipaddress
from proxmox_utils import (
    ProxmoxConfig,
    connect_netbox,
    print_error,
    print_success,
    print_info,
    NetboxConnectionError,
    NetboxDependencyError
)


def delete_ip_address(nb, ip_address: str) -> bool:
    """
    Delete IP address from NetBox
    
    Args:
        nb: NetBox API instance
        ip_address: IP address to delete (can be with or without CIDR)
    
    Returns:
        True if successful, False otherwise
    """
    
    # Validate IP address
    try:
        ip_obj = ipaddress.ip_address(ip_address.split('/')[0])
    except ValueError:
        print_error(f"Invalid IP address: {ip_address}")
        return False
    
    # Extract IP without CIDR for lookup
    ip_without_cidr = str(ip_obj)
    
    # Try to find the IP address in NetBox
    # Try multiple variations: with CIDR, without CIDR, with /32
    ip_variations = [ip_address]
    if '/' not in ip_address:
        ip_variations.append(f"{ip_address}/32")
    else:
        # Also try without CIDR
        ip_variations.append(ip_without_cidr)
        ip_variations.append(f"{ip_without_cidr}/32")
    
    ip_found = None
    for ip_var in ip_variations:
        try:
            ip_addresses = nb.ipam.ip_addresses.filter(address=ip_var)
            ip_list = list(ip_addresses)
            if ip_list:
                ip_found = ip_list[0]
                break
        except Exception:
            continue
    
    # If not found with exact match, try partial match
    if not ip_found:
        try:
            # Try searching by IP address (partial match)
            all_ips = nb.ipam.ip_addresses.filter(address__icontains=ip_without_cidr)
            for ip_obj in all_ips:
                ip_str = str(ip_obj.address).split('/')[0]
                if ip_str == ip_without_cidr:
                    ip_found = ip_obj
                    break
        except Exception as e:
            print_error(f"Error searching for IP address: {e}")
            return False
    
    if not ip_found:
        print_error(f"IP address {ip_address} not found in NetBox")
        return False
    
    # Get DNS name if available for confirmation message
    dns_name = getattr(ip_found, 'dns_name', None) or ''
    ip_with_cidr = str(ip_found.address)
    
    # Delete the IP address
    try:
        ip_found.delete()
        if dns_name:
            print_success(f"Deleted IP address {ip_with_cidr} (DNS name: {dns_name}) from NetBox")
        else:
            print_success(f"Deleted IP address {ip_with_cidr} from NetBox")
        return True
    except Exception as e:
        error_str = str(e)
        if '403' in error_str or 'permission' in error_str.lower() or 'forbidden' in error_str.lower():
            print_error(f"Insufficient permissions to delete IP address in NetBox")
            print_error(f"Please verify token permissions in NetBox")
            return False
        else:
            print_error(f"Failed to delete IP address: {e}")
            return False


def main():
    if len(sys.argv) != 2:
        print_error("Usage: delete-dns.py <ip_address>")
        print_error("Example: delete-dns.py 192.168.1.100")
        sys.exit(1)
    
    ip_address = sys.argv[1].strip()
    
    if not ip_address:
        print_error("IP address cannot be empty")
        sys.exit(1)
    
    # Load configuration
    try:
        config = ProxmoxConfig('proxmox.ini')
    except FileNotFoundError:
        print_error("Configuration file 'proxmox.ini' not found")
        sys.exit(1)
    except Exception as e:
        print_error(f"Error loading configuration: {e}")
        sys.exit(1)
    
    # Check NetBox configuration
    if not config.has_netbox_config():
        print_error("NetBox configuration not found in proxmox.ini")
        sys.exit(1)
    
    netbox_url = config.get_netbox_url()
    netbox_token = config.get_netbox_token()
    
    if not netbox_url or not netbox_token:
        print_error("NetBox URL and token must be configured in proxmox.ini")
        print_error("Set [netbox] url and token in proxmox.ini")
        sys.exit(1)
    
    # Connect to NetBox
    try:
        nb = connect_netbox(netbox_url, netbox_token)
    except NetboxDependencyError as e:
        print_error(str(e))
        sys.exit(1)
    except NetboxConnectionError as e:
        print_error(str(e))
        sys.exit(1)
    
    print_success("Connected to NetBox")
    
    # Delete IP address
    if delete_ip_address(nb, ip_address):
        sys.exit(0)
    else:
        sys.exit(1)


if __name__ == '__main__':
    main()
