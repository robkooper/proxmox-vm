#!/usr/bin/env python3
"""
NetBox Management Utilities

Common functions for NetBox API interaction, IP address management,
DNS record management, and hostname validation.
"""

import ipaddress
import socket
from typing import Optional, Tuple

# Import logger from proxmox_utils
from proxmox_utils import logger


# Custom exceptions for NetBox error handling

class NetboxError(Exception):
    """Base exception for NetBox-related errors"""
    pass


class NetboxConnectionError(NetboxError):
    """Raised when connection to NetBox fails"""
    pass


class NetboxDependencyError(NetboxError):
    """Raised when required NetBox dependencies are missing"""
    pass


# NetBox integration functions

def connect_netbox(url: str, token: str):
    """
    Connect to NetBox API
    
    Args:
        url: NetBox API URL (e.g., 'https://netbox.example.com')
        token: NetBox API token
    
    Returns:
        NetBox API instance
    """
    try:
        import pynetbox
    except ImportError:
        raise NetboxDependencyError("pynetbox library not installed. Install it with: pip install pynetbox")
    
    nb = pynetbox.api(url, token=token)
    # Test connection using the status endpoint (lightweight and purpose-built)
    try:
        # Use the status endpoint to verify connection and authentication
        # This is more efficient than querying data endpoints
        nb.status()
    except Exception as e:
        raise NetboxConnectionError(f"Failed to connect to NetBox: {e}") from e
    
    return nb


def check_ip_assigned_to_hostname(nb, ip_address: str, expected_hostname: str, domain: Optional[str] = None) -> Tuple[bool, Optional[str]]:
    """
    Check if an IP address is already assigned to a hostname in NetBox IPAM
    
    Args:
        nb: NetBox API instance
        ip_address: IP address to check (can be with or without CIDR)
        expected_hostname: The hostname we want to assign this IP to
        domain: Optional domain name (full FQDN will be hostname.domain)
    
    Returns:
        Tuple of (is_conflict, existing_hostname)
        - is_conflict: True if IP is assigned to a different hostname, False otherwise
        - existing_hostname: The hostname currently assigned to this IP (None if not assigned or matches expected)
    """
    try:
        # Extract IP without CIDR for lookup
        ip_without_cidr = ip_address.split('/')[0]
        expected_full_hostname = f"{expected_hostname}.{domain}" if domain else expected_hostname
        
        # Try to find IP address in NetBox IPAM
        # Try with CIDR first, then without
        ip_variants = [ip_address]
        if '/' not in ip_address:
            # Try to find what CIDR this IP might have
            try:
                all_ips = nb.ipam.ip_addresses.filter(address__icontains=ip_without_cidr)
                for ip_obj in all_ips:
                    ip_str = str(ip_obj.address).split('/')[0]
                    if ip_str == ip_without_cidr:
                        ip_variants.append(str(ip_obj.address))
                        break
            except Exception:
                pass
        
        # Check all IP variants
        for ip_variant in ip_variants:
            try:
                ip_addresses = nb.ipam.ip_addresses.filter(address=ip_variant)
                ip_list = list(ip_addresses)
                
                if ip_list:
                    # IP exists - check the DNS name
                    ip_obj = ip_list[0]
                    existing_dns_name = getattr(ip_obj, 'dns_name', None) or ''
                    
                    if existing_dns_name:
                        # IP is assigned to a hostname
                        if existing_dns_name.lower() != expected_full_hostname.lower() and existing_dns_name.lower() != expected_hostname.lower():
                            # Different hostname - this is a conflict
                            return (True, existing_dns_name)
                        # Same hostname - no conflict
                        return (False, existing_dns_name)
                    else:
                        # IP exists but no DNS name - might be reserved or unassigned
                        # This is OK, we can assign it
                        return (False, None)
            except Exception:
                continue
        
        # IP not found in NetBox - no conflict
        return (False, None)
        
    except Exception as e:
        # On error, assume no conflict (safer to proceed than to block)
        logger.error(f"Error checking IP assignment in NetBox: {e}")
        return (False, None)


def check_hostname_in_dns(hostname: str, domain: Optional[str] = None) -> bool:
    """
    Check if a hostname exists in DNS
    
    Performs a DNS lookup to see if the hostname resolves to an IP address.
    This checks actual DNS, not just NetBox records.
    
    Args:
        hostname: Hostname to check
        domain: Optional domain name (full FQDN will be hostname.domain)
    
    Returns:
        True if hostname exists in DNS (resolves to an IP), False if it doesn't exist
    """
    # Try both hostname alone and with domain
    hostnames_to_check = [hostname]
    if domain:
        full_hostname = f"{hostname}.{domain}"
        hostnames_to_check.append(full_hostname)
    
    for hostname_to_check in hostnames_to_check:
        try:
            # Try to resolve the hostname
            socket.gethostbyname(hostname_to_check)
            # If we get here, the hostname exists in DNS
            return True
        except socket.gaierror:
            # Hostname doesn't exist in DNS - this is what we want
            continue
        except Exception:
            # Other errors (network issues, etc.) - assume it doesn't exist
            continue
    
    # None of the hostnames resolved
    return False


def check_hostname_available(nb, hostname: str, domain: Optional[str] = None) -> bool:
    """
    Check if a hostname is available in NetBox
    
    Checks for existing devices and IP addresses with DNS names in IPAM
    
    Args:
        nb: NetBox API instance
        hostname: Hostname to check
        domain: Optional domain name (full FQDN will be hostname.domain)
    
    Returns:
        True if hostname is available, False if it exists
    """
    full_hostname = f"{hostname}.{domain}" if domain else hostname
    
    # Check for existing devices with this name
    try:
        devices = nb.dcim.devices.filter(name=hostname)
        if list(devices):
            return False
    except Exception:
        pass  # API might not support filtering or device might not exist
    
    # Also check IP addresses with DNS name in IPAM
    try:
        ip_addresses = nb.ipam.ip_addresses.filter(dns_name=full_hostname)
        if list(ip_addresses):
            return False
        # Also check without domain
        ip_addresses = nb.ipam.ip_addresses.filter(dns_name=hostname)
        if list(ip_addresses):
            return False
    except Exception:
        pass
    
    return True


def find_prefix_for_subnet(nb, subnet_cidr: str):
    """
    Find the prefix object in NetBox that matches the given subnet
    
    This function searches for a prefix in NetBox that matches the provided subnet CIDR.
    It first tries an exact match, then falls back to network matching.
    
    Args:
        nb: NetBox API instance
        subnet_cidr: Subnet in CIDR notation (e.g., '192.168.1.0/24')
    
    Returns:
        Prefix object or None if not found
    """
    try:
        # Try exact match first
        prefixes = nb.ipam.prefixes.filter(prefix=subnet_cidr)
        prefix_list = list(prefixes)
        if prefix_list:
            return prefix_list[0]
        
        # Try to find by network matching
        try:
            network = ipaddress.ip_network(subnet_cidr, strict=False)
            all_prefixes = nb.ipam.prefixes.all()
            for p in all_prefixes:
                try:
                    prefix_net = ipaddress.ip_network(p.prefix, strict=False)
                    if network == prefix_net:
                        return p
                except Exception:
                    continue
        except Exception:
            pass
        
        return None
    except Exception as e:
        logger.error(f"Error finding prefix for subnet {subnet_cidr}: {e}")
        return None


def get_available_ip_from_subnet(nb, subnet_cidr: str) -> Tuple[Optional[str], Optional]:
    """
    Get an available IP address from a NetBox subnet/prefix
    
    Args:
        nb: NetBox API instance
        subnet_cidr: Subnet in CIDR notation (e.g., '192.168.1.0/24')
    
    Returns:
        Tuple of (available IP address as string without CIDR, prefix object) or (None, None) if none available
    """
    try:
        # Find the prefix in NetBox using shared function
        prefix = find_prefix_for_subnet(nb, subnet_cidr)
        
        if not prefix:
            logger.error(f"Subnet {subnet_cidr} not found in NetBox")
            return (None, None)
        
        # Get all IP addresses in this prefix from IPAM
        used_ips = set()
        network = ipaddress.ip_network(subnet_cidr, strict=False)
        
        try:
            # Try filtering by prefix first (more efficient)
            ip_addresses = nb.ipam.ip_addresses.filter(prefix=str(prefix.prefix))
            for ip_obj in ip_addresses:
                try:
                    # Extract IP address (remove /CIDR if present)
                    ip_str = str(ip_obj.address).split('/')[0]
                    ip_addr = ipaddress.ip_address(ip_str)
                    if ip_addr in network:
                        used_ips.add(ip_addr)
                except Exception:
                    continue
        except Exception:
            # If filtering by prefix fails, get all IPs and filter manually
            try:
                all_ips = nb.ipam.ip_addresses.all()
                for ip_obj in all_ips:
                    try:
                        ip_str = str(ip_obj.address).split('/')[0]
                        ip_addr = ipaddress.ip_address(ip_str)
                        if ip_addr in network:
                            used_ips.add(ip_addr)
                    except Exception:
                        continue
            except Exception:
                logger.error(f"Failed to retrieve IP addresses from NetBox")
                return (None, None)
        
        # Try to use NetBox's available_ips endpoint if available (most reliable)
        # This endpoint correctly excludes reserved IPs like gateways
        try:
            if hasattr(prefix, 'available_ips'):
                available_ips_list = list(prefix.available_ips.list()[:1])  # Get first available
                if available_ips_list:
                    # Extract IP from first available (IPAddress object with address attribute)
                    first_available = available_ips_list[0]
                    # IPAddress object has 'address' attribute in format 'IP/CIDR'
                    if hasattr(first_available, 'address'):
                        ip_with_cidr = str(first_available.address)
                        ip_str = ip_with_cidr.split('/')[0]
                        logger.info(f"→ Using NetBox available_ips endpoint: {ip_str}")
                        return (ip_str, prefix)
                    else:
                        # Fallback: convert to string and extract
                        ip_str = str(first_available).split('/')[0]
                        logger.info(f"→ Using NetBox available_ips endpoint: {ip_str}")
                        return (ip_str, prefix)
        except (AttributeError, Exception) as e:
            # available_ips endpoint not available or error, fall back to manual calculation
            logger.info(f"→ NetBox available_ips endpoint not available, using manual calculation")
        
        # Find first available IP (excluding network and broadcast)
        # Skip .1 as it's typically the gateway IP
        network = ipaddress.ip_network(subnet_cidr, strict=False)
        for ip in network.hosts():  # hosts() excludes network and broadcast
            # Skip .1 (typical gateway) and .2 (sometimes reserved) to avoid conflicts
            if ip not in used_ips and ip != network.network_address + 1 and ip != network.network_address + 2:
                return (str(ip), prefix)
        
        # If all IPs except .1/.2 are used, try .1 and .2 as last resort
        for ip in network.hosts():
            if ip not in used_ips:
                logger.info(f"→ Warning: Using potentially reserved IP {ip} (gateway/reserved range)")
                return (str(ip), prefix)
        
        logger.error(f"No available IP addresses in subnet {subnet_cidr}")
        return (None, None)
        
    except Exception as e:
        logger.error(f"Error getting available IP from NetBox: {e}")
        return (None, None)


def create_ip_address_in_netbox(nb, ip_address: str, hostname: str, domain: Optional[str] = None, description: Optional[str] = None, prefix_obj=None, tenant_id: Optional[int] = None) -> bool:
    """
    Create an IP address record in NetBox IPAM
    
    Args:
        nb: NetBox API instance
        ip_address: IP address (can include CIDR, e.g., '192.168.1.100/24')
        hostname: Hostname for this IP
        domain: Optional domain name (full FQDN will be hostname.domain)
        description: Optional description
        prefix_obj: Optional prefix object (for using available_ips endpoint)
        tenant_id: Optional tenant ID to associate with the IP address
    
    Returns:
        True if successful, False otherwise (MUST return False on failure to prevent duplicate IPs)
    """
    try:
        # Ensure IP has CIDR notation (try to get from existing IPs or use /32)
        ip_with_cidr = ip_address
        if '/' not in ip_address:
            # Try to find subnet for this IP
            try:
                ip_obj = ipaddress.ip_address(ip_address)
                # Get all prefixes and find which one contains this IP
                prefixes = nb.ipam.prefixes.all()
                for prefix in prefixes:
                    try:
                        prefix_net = ipaddress.ip_network(prefix.prefix, strict=False)
                        if ip_obj in prefix_net:
                            ip_with_cidr = f"{ip_address}/{prefix_net.prefixlen}"
                            if prefix_obj is None:
                                prefix_obj = prefix
                            break
                    except Exception:
                        continue
                else:
                    # Default to /32 if no subnet found
                    ip_with_cidr = f"{ip_address}/32"
            except Exception:
                ip_with_cidr = f"{ip_address}/32"
        
        full_hostname = f"{hostname}.{domain}" if domain else hostname
        
        # Try method 1: Use available_ips endpoint if we have the prefix (preferred method)
        if prefix_obj and hasattr(prefix_obj, 'available_ips'):
            try:
                # Create IP using the prefix's available_ips endpoint
                # This automatically assigns an available IP and associates it with the prefix
                available_ip_data = {
                    'dns_name': full_hostname
                }
                # Add tenant if provided
                if tenant_id:
                    available_ip_data['tenant'] = tenant_id
                result = prefix_obj.available_ips.create(available_ip_data)
                created_ip = result.address if hasattr(result, 'address') else str(result)
                logger.info(f"✓ Created IP address {created_ip} in NetBox with DNS name {full_hostname}")
                return True
            except Exception as e:
                error_str = str(e)
                if '403' in error_str or 'permission' in error_str.lower() or 'forbidden' in error_str.lower():
                    # Permission error - try direct creation method below
                    pass
                elif 'duplicate' in error_str.lower() or '400' in error_str or 'already exists' in error_str.lower():
                    # IP already exists - this is a problem, need to stop
                    logger.error(f"IP address already exists in NetBox (duplicate detected via available_ips)")
                    logger.error(f"This would cause IP conflicts - stopping VM creation")
                    return False  # Stop - duplicate IP detected
                else:
                    # Other error - try direct creation method below
                    pass
        
        # Method 2: Direct IP address creation
        ip_data = {
            'address': ip_with_cidr,
            'dns_name': full_hostname,
            'status': 'active'
        }
        
        # Add tenant if provided
        if tenant_id:
            ip_data['tenant'] = tenant_id
        
        # Associate with prefix if we have it (required for NetBox validation in some cases)
        if prefix_obj:
            ip_data['prefix'] = prefix_obj.id
            logger.info(f"→ Associating IP with prefix: {prefix_obj.prefix} (ID: {prefix_obj.id})")
        
        try:
            nb.ipam.ip_addresses.create(**ip_data)
            logger.info(f"✓ Created IP address {ip_with_cidr} in NetBox with DNS name {full_hostname}")
            return True
        except Exception as e:
            error_str = str(e)
            # Check if error is about permissions (403) - this is a critical error, must stop
            if '403' in error_str or 'permission' in error_str.lower() or 'forbidden' in error_str.lower():
                logger.error(f"Insufficient permissions to create IP address in NetBox (403 Forbidden)")
                logger.error(f"The NetBox API token does not have 'ipam | ip address | add' permission")
                logger.error(f"Please verify token permissions in NetBox: Admin → API Tokens → Edit Token")
                logger.error(f"Required permission: ipam | ip address | add (or full ipam permissions)")
                logger.error(f"Cannot proceed without creating IP address record - stopping VM creation")
                return False  # Stop - cannot create IP without proper permissions
            # Check if error is about duplicate IP
            elif 'duplicate' in error_str.lower() or '400' in error_str or 'already exists' in error_str.lower():
                # IP already exists - check if it's for the same hostname or different
                try:
                    # Try to find the existing IP
                    existing_ips = nb.ipam.ip_addresses.filter(address=ip_with_cidr)
                    existing_list = list(existing_ips)
                    if existing_list:
                        ip_obj = existing_list[0]
                        # Check if DNS name matches
                        current_dns = getattr(ip_obj, 'dns_name', None) or ''
                        if current_dns == full_hostname or current_dns == hostname:
                            # Same hostname - already exists (this is OK, maybe script was run twice)
                            logger.info(f"✓ IP address {ip_with_cidr} already exists in NetBox for {full_hostname} - verified")
                            return True
                        else:
                            # Different hostname - this is a conflict!
                            logger.error(f"IP address {ip_with_cidr} already exists in NetBox with different DNS name: {current_dns}")
                            logger.error(f"Cannot assign same IP to {full_hostname} - this would cause IP conflicts")
                            logger.error(f"Stopping VM creation to prevent duplicate IP assignment")
                            return False  # Stop - IP conflict with different hostname
                    else:
                        # IP exists but we can't find it via filter - might be a constraint issue
                        logger.error(f"IP address {ip_with_cidr} already exists in NetBox but cannot be verified")
                        logger.error(f"This could cause IP conflicts - stopping VM creation")
                        return False  # Stop - IP conflict detected
                except Exception as update_err:
                    logger.error(f"IP {ip_with_cidr} exists in NetBox but couldn't verify it: {update_err}")
                    logger.error(f"Cannot verify IP status - stopping VM creation to prevent conflicts")
                    return False  # Stop - cannot verify IP status
            else:
                logger.error(f"Failed to create IP address in NetBox: {e}")
                return False
    
    except Exception as e:
        logger.error(f"Error creating IP address in NetBox: {e}")
        return False


def get_tenant_id(nb, tenant_slug: Optional[str] = None) -> Optional[int]:
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
            logger.error(f"Tenant '{tenant_slug}' not found in NetBox")
            return None
    except Exception as e:
        logger.error(f"Error looking up tenant '{tenant_slug}': {e}")
        return None


def create_ip_address_for_hostname_in_netbox(nb, hostname: str, ip_address: str, domain: Optional[str] = None, tenant_id: Optional[int] = None, subnet_cidr: Optional[str] = None) -> bool:
    """
    Create IP address for a hostname in NetBox IPAM with validation
    
    Performs hostname-specific validation checks, then uses create_ip_address_in_netbox()
    to create the IP address record. This is a higher-level function that validates
    hostname/IP relationships before creating the IP address.
    
    Args:
        nb: NetBox API instance
        hostname: Hostname to set IP for
        ip_address: IP address to set
        domain: Optional domain name (if provided, creates FQDN: hostname.domain)
        tenant_id: Optional tenant ID
        subnet_cidr: Optional subnet CIDR to find prefix
    
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
        logger.error(f"Invalid IP address: {ip_address}")
        return False
    
    # Find existing IP address for this hostname (using FQDN) in IPAM
    try:
        existing_ips = nb.ipam.ip_addresses.filter(dns_name=full_hostname)
        existing_list = list(existing_ips)
        
        # Also check without domain (in case old records exist)
        existing_ips_short = nb.ipam.ip_addresses.filter(dns_name=hostname)
        existing_list.extend(list(existing_ips_short))
    except Exception as e:
        logger.error(f"Error querying NetBox for existing IPs: {e}")
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
                    logger.info(f"→ Using prefix from config: {prefix_obj.prefix}")
                else:
                    logger.error(f"IP {ip_address} is not in the configured subnet {subnet_cidr}")
                    return False
            except Exception as e:
                logger.error(f"Error processing prefix {prefix_obj.prefix}: {e}")
                return False
        else:
            logger.error(f"Subnet {subnet_cidr} from config not found in NetBox")
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
            logger.info(f"→ Could not determine subnet for IP, using /32: {e}")
            ip_with_cidr = f"{ip_address}/32"
    
    # Check if the IP already exists with a different hostname (before updating)
    try:
        # Try multiple CIDR variations to find existing IP
        ip_variations = [ip_with_cidr]
        if '/' in ip_with_cidr:
            # Also try without CIDR and with /32
            ip_variations.append(ip_address)
            ip_variations.append(f"{ip_address}/32")
        
        for ip_var in ip_variations:
            try:
                ip_check = nb.ipam.ip_addresses.filter(address=ip_var)
                ip_check_list = list(ip_check)
                if ip_check_list:
                    for existing_ip_obj in ip_check_list:
                        existing_dns = getattr(existing_ip_obj, 'dns_name', None) or ''
                        # If IP exists with different FQDN, it's a conflict
                        if existing_dns and existing_dns != full_hostname and existing_dns != hostname:
                            logger.error(f"IP address {ip_address} already exists with different DNS name: {existing_dns}")
                            logger.error(f"Cannot assign same IP to {full_hostname}")
                            return False
            except Exception:
                continue
    except Exception:
        pass  # Continue if check fails
    
    # If IP record exists for this hostname, check if it matches
    if existing_list:
        try:
            # If multiple IPs exist for this hostname, check the first one
            ip_obj_to_check = existing_list[0]
            current_ip = str(ip_obj_to_check.address).split('/')[0]
            
            # If the IP is already correct, just verify and return
            if current_ip == ip_address:
                if domain:
                    logger.info(f"✓ IP address for {full_hostname} (FQDN) is already set to {ip_with_cidr}")
                else:
                    logger.info(f"✓ IP address for {full_hostname} is already set to {ip_with_cidr}")
                return True
            
            # Hostname exists with a different IP - error out
            logger.error(f"Hostname '{full_hostname}' already exists in NetBox with IP address {current_ip}")
            logger.error(f"Cannot assign different IP {ip_address} to existing hostname")
            logger.error(f"Use delete-dns.py to remove the existing record first, or use a different hostname")
            return False
        except Exception as e:
            logger.error(f"Error checking existing IP address: {e}")
            return False
    
    # Create new IP address record using IPAM
    return create_ip_address_in_netbox(nb, ip_with_cidr, hostname, domain, prefix_obj=prefix_obj, tenant_id=tenant_id)


def delete_ip_address_in_netbox(nb, ip_address: str) -> bool:
    """
    Delete IP address from NetBox IPAM
    
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
        logger.error(f"Invalid IP address: {ip_address}")
        return False
    
    # Extract IP without CIDR for lookup
    ip_without_cidr = str(ip_obj)
    
    # Try to find the IP address in NetBox IPAM
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
            logger.error(f"Error searching for IP address: {e}")
            return False
    
    if not ip_found:
        logger.error(f"IP address {ip_address} not found in NetBox")
        return False
    
    # Get DNS name if available for confirmation message
    dns_name = getattr(ip_found, 'dns_name', None) or ''
    ip_with_cidr = str(ip_found.address)
    
    # Delete the IP address
    try:
        ip_found.delete()
        if dns_name:
            logger.info(f"✓ Deleted IP address {ip_with_cidr} (DNS name: {dns_name}) from NetBox")
        else:
            logger.info(f"✓ Deleted IP address {ip_with_cidr} from NetBox")
        return True
    except Exception as e:
        error_str = str(e)
        if '403' in error_str or 'permission' in error_str.lower() or 'forbidden' in error_str.lower():
            logger.error(f"Insufficient permissions to delete IP address in NetBox")
            logger.error(f"Please verify token permissions in NetBox")
            return False
        else:
            logger.error(f"Failed to delete IP address: {e}")
            return False


def delete_ip_address_by_hostname_in_netbox(nb, hostname: str, domain: Optional[str] = None) -> bool:
    """
    Delete IP address from NetBox IPAM by hostname
    
    Args:
        nb: NetBox API instance
        hostname: Hostname to delete
        domain: Optional domain name (full FQDN will be hostname.domain)
    
    Returns:
        True if successful, False otherwise
    """
    # Build full hostname (FQDN) if domain is provided
    if domain:
        full_hostname = f"{hostname}.{domain}"
    else:
        full_hostname = hostname
    
    # Try to find IP addresses by DNS name
    # Try both FQDN and just hostname (in case domain wasn't used when creating)
    ip_found = None
    hostnames_to_try = [full_hostname]
    if domain:
        hostnames_to_try.append(hostname)  # Also try without domain
    
    for dns_name_to_try in hostnames_to_try:
        try:
            ip_addresses = nb.ipam.ip_addresses.filter(dns_name=dns_name_to_try)
            ip_list = list(ip_addresses)
            if ip_list:
                ip_found = ip_list[0]
                break
        except Exception as e:
            logger.error(f"Error searching for hostname '{dns_name_to_try}': {e}")
            continue
    
    if not ip_found:
        logger.error(f"Hostname '{full_hostname}' not found in NetBox")
        return False
    
    # Get IP address and DNS name for confirmation message
    ip_with_cidr = str(ip_found.address)
    dns_name = getattr(ip_found, 'dns_name', None) or ''
    
    # Delete the IP address
    try:
        ip_found.delete()
        logger.info(f"✓ Deleted IP address {ip_with_cidr} (DNS name: {dns_name}) from NetBox")
        return True
    except Exception as e:
        error_str = str(e)
        if '403' in error_str or 'permission' in error_str.lower() or 'forbidden' in error_str.lower():
            logger.error(f"Insufficient permissions to delete IP address in NetBox")
            logger.error(f"Please verify token permissions in NetBox")
            return False
        else:
            logger.error(f"Failed to delete IP address: {e}")
            return False


