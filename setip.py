#!/usr/bin/env python3
"""
Set IP address for a hostname in NetBox

Usage:
    setip.py <hostname> <ip_address>

Example:
    setip.py myserver 192.168.1.100

The script will create/update an IP address in NetBox:
- If domain is configured in proxmox.ini: uses FQDN (hostname.domain)
- If domain is not configured: uses just the hostname
"""

import sys
import ipaddress
from typing import Optional
from proxmox_utils import (
    ProxmoxConfig,
    connect_netbox,
    print_error,
    print_success,
    print_info,
    find_prefix_for_subnet,
    NetboxError,
    NetboxConnectionError,
    NetboxDependencyError
)


def get_tenant_id(nb, tenant_slug: Optional[str] = None):
    """
    Get tenant ID from NetBox by slug
    
    Args:
        nb: NetBox API instance
        tenant_slug: Tenant slug (e.g., 'sd_netbox')
    
    Returns:
        Tenant ID or None if not found
    """
    if not tenant_slug:
        return None
    
    try:
        tenants = nb.tenancy.tenants.filter(slug=tenant_slug)
        tenant_list = list(tenants)
        if tenant_list:
            return tenant_list[0].id
        else:
            print_error(f"Tenant '{tenant_slug}' not found in NetBox")
            return None
    except Exception as e:
        print_error(f"Error looking up tenant '{tenant_slug}': {e}")
        return None


def set_ip_address(nb, hostname: str, ip_address: str, domain: Optional[str] = None, tenant_id: Optional[int] = None, subnet_cidr: Optional[str] = None):
    """
    Set IP address for a hostname in NetBox
    
    Args:
        nb: NetBox API instance
        hostname: Hostname to set IP for
        ip_address: IP address to set
        domain: Optional domain name (if provided, creates FQDN: hostname.domain)
        tenant_id: Optional tenant ID
    
    Returns:
        True if successful, False otherwise
    """
    
    # Use FQDN (hostname.domain) if domain is provided, otherwise use just hostname
    if domain:
        full_hostname = f"{hostname}.{domain}"
    else:
        full_hostname = hostname
    
    # Validate IP address
    try:
        ip_obj = ipaddress.ip_address(ip_address)
    except ValueError:
        print_error(f"Invalid IP address: {ip_address}")
        return False
    
    # Find existing IP address for this hostname (using FQDN)
    try:
        existing_ips = nb.ipam.ip_addresses.filter(dns_name=full_hostname)
        existing_list = list(existing_ips)
        
        # Also check without domain (in case old records exist)
        existing_ips_short = nb.ipam.ip_addresses.filter(dns_name=hostname)
        existing_list.extend(list(existing_ips_short))
    except Exception as e:
        print_error(f"Error querying NetBox for existing IPs: {e}")
        return False
    
    # Find the prefix/subnet for this IP to get CIDR notation
    ip_with_cidr = ip_address
    prefix_obj = None
    
    # First, try to use the subnet from config to find the prefix
    if subnet_cidr:
        prefix_obj = find_prefix_for_subnet(nb, subnet_cidr)
        if prefix_obj:
            try:
                prefix_net = ipaddress.ip_network(prefix_obj.prefix, strict=False)
                if ip_obj in prefix_net:
                    ip_with_cidr = f"{ip_address}/{prefix_net.prefixlen}"
                    print_info(f"Using prefix from config: {prefix_obj.prefix}")
                else:
                    print_error(f"IP {ip_address} is not in the configured subnet {subnet_cidr}")
                    return False
            except Exception as e:
                print_error(f"Error processing prefix {prefix_obj.prefix}: {e}")
                return False
        else:
            print_error(f"Subnet {subnet_cidr} from config not found in NetBox")
            return False
    
    # If no subnet from config, try to find prefix automatically
    if not prefix_obj:
        try:
            # Get all prefixes and find which one contains this IP
            prefixes = nb.ipam.prefixes.all()
            for prefix in prefixes:
                try:
                    prefix_net = ipaddress.ip_network(prefix.prefix, strict=False)
                    if ip_obj in prefix_net:
                        ip_with_cidr = f"{ip_address}/{prefix_net.prefixlen}"
                        prefix_obj = prefix
                        break
                except Exception:
                    continue
            
            # If no prefix found, default to /32
            if '/' not in ip_with_cidr:
                ip_with_cidr = f"{ip_address}/32"
        except Exception as e:
            print_info(f"Could not determine subnet for IP, using /32: {e}")
            ip_with_cidr = f"{ip_address}/32"
    
    # Check if the IP already exists with a different hostname (before updating)
    try:
        # Try multiple CIDR variations to find existing IP
        ip_variations = [ip_with_cidr]
        if '/' in ip_with_cidr:
            # Also try without CIDR and with /32
            ip_variations.append(ip_address)
            ip_variations.append(f"{ip_address}/32")
        
        ip_conflict = False
        for ip_var in ip_variations:
            try:
                ip_check = nb.ipam.ip_addresses.filter(address=ip_var)
                ip_check_list = list(ip_check)
                if ip_check_list:
                    for existing_ip_obj in ip_check_list:
                        existing_dns = getattr(existing_ip_obj, 'dns_name', None) or ''
                        # If IP exists with different FQDN, it's a conflict
                        if existing_dns and existing_dns != full_hostname and existing_dns != hostname:
                            print_error(f"IP address {ip_address} already exists with different DNS name: {existing_dns}")
                            print_error(f"Cannot assign same IP to {full_hostname}")
                            return False
                        # If IP exists with same hostname/FQDN, we'll update it below
            except Exception:
                continue
    except Exception:
        pass  # Continue if check fails
    
    # If IP record exists for this hostname, update it
    if existing_list:
        try:
            # If multiple IPs exist for this hostname, update the first one and remove others
            ip_obj_to_update = existing_list[0]
            current_ip = str(ip_obj_to_update.address).split('/')[0]
            
            # If the IP is already correct, just verify and return
            if current_ip == ip_address:
                if domain:
                    print_success(f"IP address for {full_hostname} (FQDN) is already set to {ip_with_cidr}")
                else:
                    print_success(f"IP address for {full_hostname} is already set to {ip_with_cidr}")
                return True
            
            # Update the IP address
            ip_obj_to_update.address = ip_with_cidr
            ip_obj_to_update.dns_name = full_hostname
            if tenant_id:
                ip_obj_to_update.tenant = tenant_id
            # Associate with prefix if we found one
            if prefix_obj:
                ip_obj_to_update.prefix = prefix_obj.id
            ip_obj_to_update.save()
            
            # Remove any other IP records for this hostname (if multiple exist)
            if len(existing_list) > 1:
                for other_ip in existing_list[1:]:
                    try:
                        other_ip.delete()
                        print_info(f"Removed duplicate IP record: {other_ip.address}")
                    except Exception:
                        pass  # Continue if deletion fails
            
            if domain:
                print_success(f"Updated IP address for {full_hostname} (FQDN) to {ip_with_cidr}")
            else:
                print_success(f"Updated IP address for {full_hostname} to {ip_with_cidr}")
            return True
        except Exception as e:
            print_error(f"Error updating IP address: {e}")
            return False
    
    # Create new IP address record
    try:
        ip_data = {
            'address': ip_with_cidr,
            'dns_name': full_hostname,  # FQDN if domain provided, otherwise just hostname
            'description': f"Set by setip.py script for {hostname}",
            'status': 'active'
        }
        
        # Add tenant if provided
        if tenant_id:
            ip_data['tenant'] = tenant_id
        
        # Associate with prefix if we found one (required for NetBox validation)
        if prefix_obj:
            ip_data['prefix'] = prefix_obj.id
            print_info(f"Associating IP with prefix: {prefix_obj.prefix} (ID: {prefix_obj.id})")
        
        # Direct creation
        nb.ipam.ip_addresses.create(**ip_data)
        if domain:
            print_success(f"Created IP address {ip_with_cidr} with FQDN {full_hostname} in NetBox")
        else:
            print_success(f"Created IP address {ip_with_cidr} with DNS name {full_hostname} in NetBox")
        return True
    except Exception as e:
        error_str = str(e)
        if 'duplicate' in error_str.lower() or 'already exists' in error_str.lower():
            print_error(f"IP address {ip_with_cidr} already exists in NetBox")
            return False
        elif '403' in error_str or 'permission' in error_str.lower():
            print_error(f"Insufficient permissions to create IP address in NetBox")
            print_error(f"Please verify token permissions in NetBox")
            return False
        else:
            print_error(f"Failed to create IP address: {e}")
            return False


def main():
    if len(sys.argv) != 3:
        print_error("Usage: setip.py <hostname> <ip_address>")
        print_error("Example: setip.py myserver 192.168.1.100")
        print_error("Note: If domain is configured in proxmox.ini, FQDN (hostname.domain) will be used")
        sys.exit(1)
    
    hostname = sys.argv[1].strip()
    ip_address = sys.argv[2].strip()
    
    if not hostname:
        print_error("Hostname cannot be empty")
        sys.exit(1)
    
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
    netbox_domain = config.get_netbox_domain()
    netbox_tenant_slug = config.get_netbox_tenant()
    netbox_subnet = config.get_netbox_subnet()
    
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
    
    # Get tenant ID if tenant slug is configured
    tenant_id = None
    if netbox_tenant_slug:
        tenant_id = get_tenant_id(nb, netbox_tenant_slug)
        if tenant_id is None:
            print_error(f"Failed to find tenant '{netbox_tenant_slug}' in NetBox")
            sys.exit(1)
        print_info(f"Using tenant: {netbox_tenant_slug} (ID: {tenant_id})")
    
    # Show what DNS name will be used
    if netbox_domain:
        dns_name = f"{hostname}.{netbox_domain}"
        print_info(f"Setting IP {ip_address} for FQDN: {dns_name}")
    else:
        dns_name = hostname
        print_info(f"Setting IP {ip_address} for hostname: {dns_name} (no domain configured)")
    
    # Set IP address
    if set_ip_address(nb, hostname, ip_address, netbox_domain, tenant_id, netbox_subnet):
        sys.exit(0)
    else:
        sys.exit(1)


if __name__ == '__main__':
    main()
