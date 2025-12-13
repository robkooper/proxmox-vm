#!/usr/bin/env python3
"""
Proxmox VM Creation Script

Create VMs in Proxmox from cloud-init templates with custom configuration.
Supports user management, SSH keys, puppet integration, and resource allocation.
"""

import argparse
import base64
import getpass
import os
import pycdlib
import shutil
import sys
import tempfile
import time
from typing import List, Optional
import requests
from proxmox.proxmox_utils import (
    ProxmoxConfig,
    connect_proxmox,
    select_best_node,
    get_next_vmid,
    generate_cloud_init_config,
    generate_network_config,
    validate_os_name,
    encrypt_password,
    logger,
    setup_default_firewall_rules,
    IMAGES,
    ProxmoxError,
    ProxmoxConnectionError,
    ProxmoxNodeError,
    ProxmoxVMIDError
)
from proxmox.netbox_utils import (
    connect_netbox,
    check_hostname_available,
    check_ip_assigned_to_hostname,
    get_available_ip_from_subnet,
    create_ip_address_in_netbox,
    get_tenant_id,
    NetboxError,
    NetboxConnectionError,
    NetboxDependencyError
)


class ManualInterventionRequired(Exception):
    """
    Exception raised when VM creation requires manual intervention.
    
    This exception is raised when the VM is created but disk attachment failed,
    requiring manual steps to complete the setup.
    """
    def __init__(self, vmid: int, ip_address: Optional[str], node: str, 
                 image_volid: str, proxmox_filename: str, storage: str, disk_size: int):
        self.vmid = vmid
        self.ip_address = ip_address
        self.node = node
        self.image_volid = image_volid
        self.proxmox_filename = proxmox_filename
        self.storage = storage
        self.disk_size = disk_size
        super().__init__(f"VM {vmid} created but requires manual disk import")


class ImageNotFoundError(Exception):
    """Raised when required OS image is not found in Proxmox storage"""
    pass


class NetboxConfigurationError(Exception):
    """Raised when NetBox configuration is incomplete or invalid"""
    pass


class CloudInitError(Exception):
    """Raised when cloud-init ISO creation or upload fails"""
    pass


def set_vm_tags(proxmox, node: str, vmid: int, tags: List[str], max_retries: int = 3) -> bool:
    """
    Set tags on a VM with retry logic for timeout errors
    
    Args:
        proxmox: ProxmoxAPI instance
        node: Node name
        vmid: VM ID
        tags: List of tag strings
        max_retries: Maximum number of retry attempts (default: 3)
    
    Returns:
        True if successful, False otherwise
    """
    if not tags:
        return True
    
    tags_str = ','.join(tags)
    
    for attempt in range(1, max_retries + 1):
        try:
            # Proxmox API expects tags as comma-separated string
            proxmox.nodes(node).qemu(vmid).config.post(tags=tags_str)
            logger.info(f"✓ Set tags on VM {vmid}: {', '.join(tags)}")
            return True
        except Exception as e:
            error_str = str(e).lower()
            # Check if it's a timeout error
            is_timeout = 'timeout' in error_str or 'timed out' in error_str or 'read timeout' in error_str
            
            if is_timeout and attempt < max_retries:
                wait_time = attempt * 2  # Exponential backoff: 2s, 4s, 6s
                logger.info(f"→ Timeout setting tags on VM {vmid} (attempt {attempt}/{max_retries}), retrying in {wait_time}s...")
                time.sleep(wait_time)
                continue
            else:
                # Final attempt failed or non-timeout error
                logger.error(f"Failed to set tags on VM {vmid}: {e}")
                if is_timeout:
                    logger.error("This is a timeout error - the VM was created but tags could not be set.")
                    logger.error("You can manually set tags later in the Proxmox web interface.")
                # Don't fail VM creation if tags fail - just warn
                return False
    
    return False


def verify_vm_created(proxmox, node: str, vmid: int, result) -> bool:
    """
    Verify that a VM was actually created after a creation API call
    
    Args:
        proxmox: ProxmoxAPI instance
        node: Node name
        vmid: VM ID
        result: Result from VM creation API call
    
    Returns:
        True if VM exists, False otherwise
    
    Raises:
        Exception if VM creation failed or VM doesn't exist
    """
    # Check for errors in the response (Proxmox can return 200 with errors in JSON)
    if isinstance(result, dict):
        # Check for error fields
        if 'errors' in result:
            error_msg = result.get('errors', 'Unknown error')
            raise Exception(f"VM creation failed: {error_msg}")
        
        # Check if result indicates failure
        if result.get('status') == 'error' or 'error' in str(result).lower():
            raise Exception(f"VM creation failed: {result}")
    
    # Verify VM was actually created by checking if it exists
    try:
        vm_config = proxmox.nodes(node).qemu(vmid).config.get()
        if not vm_config:
            raise Exception("VM was not created - config is empty")
        return True
    except Exception as check_err:
        error_str = str(check_err)
        if "does not exist" in error_str.lower() or "404" in error_str or "not found" in error_str.lower():
            raise Exception(f"VM {vmid} does not exist after creation attempt. Response: {result}")
        # Re-raise other errors
        raise


def wait_for_vm_task(proxmox, node: str, vmid: int, task_description: str = "VM operation", max_wait: int = 300) -> bool:
    """
    Wait for any pending tasks on a VM to complete and lock to be released
    
    Uses the status/current endpoint which returns lock information
    
    Args:
        proxmox: ProxmoxAPI instance
        node: Node name
        vmid: VM ID
        task_description: Description of what we're waiting for
        max_wait: Maximum time to wait in seconds (default: 5 minutes)
    
    Returns:
        True if tasks completed, False if timeout
    """
    elapsed = 0
    check_interval = 2  # Check every 2 seconds
    
    logger.info(f"→ Waiting for {task_description} to complete...")
    
    while elapsed < max_wait:
        try:
            # Check VM status - the lock field tells us if VM is locked
            # According to Proxmox API docs: status/current returns lock info
            status = proxmox.nodes(node).qemu(vmid).status.current.get()
            
            # Lock field may be present when locked, or missing/empty when unlocked
            # Check if lock field exists and has a value
            lock = status.get('lock')
            
            # If lock field is missing, None, or empty string, VM is not locked
            if lock is None or lock == '':
                # VM is not locked - task is complete
                if elapsed > 0:
                    logger.info(f"✓ {task_description} completed")
                return True
            else:
                # VM is locked - lock field contains lock info like "create" or task ID
                # Continue waiting
                pass
                        
        except Exception as e:
            error_str = str(e)
            # If we can't read status, check what kind of error it is
            if "lock" in error_str.lower():
                # Explicit lock error - VM is locked, continue waiting
                pass
            elif "500" in error_str or "timeout" in error_str.lower():
                # Server error or timeout might indicate lock
                pass
            elif "does not exist" in error_str.lower() or "404" in error_str:
                # VM doesn't exist yet (shouldn't happen after creation starts, but handle it)
                # Wait a bit more - VM creation might be in progress
                pass
            else:
                # Other error - might be transient, try again
                pass
            
        # Wait and check again
        time.sleep(check_interval)
        elapsed += check_interval
        
        # Print progress every 10 seconds
        if elapsed % 10 == 0 and elapsed > 0:
            logger.info(f"→ Still waiting... ({elapsed}s elapsed)")
    
    # Final check - maybe lock was just cleared
    try:
        status = proxmox.nodes(node).qemu(vmid).status.current.get()
        lock = status.get('lock', '')
        if not lock or lock == '' or lock is None:
            logger.info(f"→ {task_description} completed")
            return True
    except:
        pass
    
    logger.error(f"{task_description} timed out after {max_wait} seconds")
    return False


def wait_for_proxmox_task(proxmox, node: str, upid: str, task_description: str = "task", max_wait: int = 600) -> bool:
    """
    Wait for a Proxmox task (identified by UPID) to complete
    
    Args:
        proxmox: ProxmoxAPI instance
        node: Node name
        upid: Task UPID
        task_description: Description of the task
        max_wait: Maximum time to wait in seconds
    
    Returns:
        True if task completed successfully, False if failed or timeout
    """
    elapsed = 0
    check_interval = 2
    
    logger.info(f"→ Waiting for {task_description} to complete...")
    
    while elapsed < max_wait:
        try:
            task_status = proxmox.nodes(node).tasks(upid).status.get()
            current_status = task_status.get('status', 'unknown')
            exitstatus = task_status.get('exitstatus', '')
            
            if current_status == 'stopped':
                if exitstatus == 'OK':
                    logger.info(f"✓ {task_description} completed successfully")
                    return True
                else:
                    logger.error(f"{task_description} failed with exit status: {exitstatus}")
                    return False
            
            # Task still running, wait
            if elapsed % 10 == 0 and elapsed > 0:
                logger.info(f"→ Task in progress... ({elapsed}s elapsed)")
            
            time.sleep(check_interval)
            elapsed += check_interval
            
        except Exception as e:
            # Task might not be visible yet, or completed
            if "not found" in str(e).lower() or "does not exist" in str(e).lower():
                if elapsed < 30:
                    # First 30 seconds, task might not be visible yet
                    time.sleep(check_interval)
                    elapsed += check_interval
                    continue
                else:
                    # Task completed and cleaned up, assume success
                    logger.info(f"→ {task_description} appears to have completed")
                    return True
            
            # Other error, wait and retry
            time.sleep(check_interval)
            elapsed += check_interval
    
    logger.error(f"{task_description} timed out after {max_wait} seconds")
    return False


def ensure_image_exists(proxmox, node: str, storage: str, os_name: str) -> tuple:
    """
    Check if the OS image exists in Proxmox storage
    
    Args:
        proxmox: ProxmoxAPI instance
        node: Node name
        storage: Storage name
        os_name: OS type (ubuntu22, ubuntu24)
    
    Returns:
        Tuple of (image_volid, proxmox_filename)
    
    Raises:
        ImageNotFoundError if image not found or OS is unknown
    """
    if os_name not in IMAGES:
        raise ImageNotFoundError(f"Unknown OS: {os_name}")
    
    proxmox_filename = IMAGES[os_name]['filename']
    
    logger.info(f"→ Checking for image: {proxmox_filename} in storage {storage}...")
    image_found = False
    image_volid = None
    
    try:
        storage_contents = proxmox.nodes(node).storage(storage).content.get()
        for item in storage_contents:
            volid = item.get('volid', '')
            # Look for image in import or iso area
            if proxmox_filename in volid and ('import/' in volid or 'iso/' in volid):
                image_found = True
                image_volid = volid
                logger.info(f"✓ Found image: {volid}")
                break
    except Exception as e:
        raise ImageNotFoundError(f"Could not check storage contents: {e}") from e
    
    if not image_found:
        raise ImageNotFoundError(
            f"Image {proxmox_filename} not found in storage {storage}. "
            f"Please download the image first: ./manage-images.py --os {os_name}"
        )
    
    return (image_volid, proxmox_filename)


def setup_netbox_ip(config: ProxmoxConfig, name: str, vmid: int) -> tuple:
    """
    Set up NetBox IP address allocation and DNS records
    
    Args:
        config: ProxmoxConfig instance
        name: VM hostname
        vmid: VM ID
    
    Returns:
        Tuple of (ip_address, gateway, dns_servers) or (None, None, []) if NetBox not configured
    
    Raises:
        NetboxConfigurationError if NetBox configuration is incomplete
        NetboxError if NetBox integration fails
    """
    ip_address = None
    gateway = None
    dns_servers = []
    
    if not config.has_netbox_config():
        return (ip_address, gateway, dns_servers)
    
    netbox_subnet = config.get_netbox_subnet()
    netbox_domain = config.get_netbox_domain()
    dns_servers = config.get_netbox_dns_servers()
    
    if not netbox_subnet:
        raise NetboxConfigurationError("NetBox configuration incomplete: subnet is required")
    
    # NetBox API-based IP management
    logger.info(f"→ NetBox API integration enabled, checking hostname and getting IP address...")
    
    netbox_url = config.get_netbox_url()
    netbox_token = config.get_netbox_token()
    
    if not netbox_url or not netbox_token:
        raise NetboxConfigurationError("NetBox configuration incomplete: url and token are required")
    
    try:
        # Connect to NetBox (these exceptions are already defined in proxmox_utils)
        nb = connect_netbox(netbox_url, netbox_token)
        logger.info("✓ Connected to NetBox")
        
        # Check if hostname is available
        if not check_hostname_available(nb, name, netbox_domain):
            full_hostname = f"{name}.{netbox_domain}" if netbox_domain else name
            raise NetboxConfigurationError(
                f"Hostname '{name}' is already in use in NetBox"
                + (f" (Full hostname would be: {full_hostname})" if netbox_domain else "")
            )
        logger.info(f"✓ Hostname '{name}' is available")
        
        # Get available IP address from subnet
        ip_address_raw, prefix_obj = get_available_ip_from_subnet(nb, netbox_subnet)
        if not ip_address_raw:
            raise NetboxError(f"Could not get available IP address from subnet {netbox_subnet}")
        
        # Determine CIDR notation for the IP
        try:
            import ipaddress as ip_lib
            subnet_net = ip_lib.ip_network(netbox_subnet, strict=False)
            ip_with_cidr = f"{ip_address_raw}/{subnet_net.prefixlen}"
            ip_address = ip_with_cidr
            
            # Derive gateway (assume .1 in subnet)
            gateway = str(subnet_net.network_address + 1)
            
            logger.info(f"✓ Allocated IP address: {ip_with_cidr}")
            if gateway:
                logger.info(f"→ Using gateway: {gateway}")
        except Exception as e:
            raise NetboxError(f"Error formatting IP address: {e}") from e
        
        # Check if IP is already assigned to a different hostname in NetBox
        logger.info(f"→ Checking if IP {ip_address_raw} is already assigned to a different hostname...")
        is_conflict, existing_hostname = check_ip_assigned_to_hostname(nb, ip_with_cidr, name, netbox_domain)
        if is_conflict:
            full_hostname = f"{name}.{netbox_domain}" if netbox_domain else name
            raise NetboxError(
                f"IP address {ip_address_raw} is already assigned to hostname '{existing_hostname}' in NetBox. "
                f"Cannot assign it to '{full_hostname}'. Please choose a different IP or hostname."
            )
        if existing_hostname:
            # IP is assigned to the same hostname - that's OK
            logger.info(f"✓ IP {ip_address_raw} is already assigned to '{existing_hostname}' (matches expected hostname)")
        else:
            logger.info(f"✓ IP {ip_address_raw} is not assigned to any hostname - OK to proceed")
        
        # Get tenant ID if configured
        tenant_id = None
        netbox_tenant_slug = config.get_netbox_tenant()
        if netbox_tenant_slug:
            tenant_id = get_tenant_id(nb, netbox_tenant_slug)
            if tenant_id:
                logger.info(f"→ Using tenant: {netbox_tenant_slug} (ID: {tenant_id})")
            else:
                logger.info(f"→ Warning: Tenant '{netbox_tenant_slug}' not found in NetBox, proceeding without tenant")
        
        # Create IP address record in NetBox IPAM (pass prefix_obj to use available_ips endpoint)
        # This MUST succeed - stop if it fails to prevent duplicate IPs
        if not create_ip_address_in_netbox(nb, ip_with_cidr, name, netbox_domain, description=f"VM created by create-vm.py (VMID: {vmid})", prefix_obj=prefix_obj, tenant_id=tenant_id):
            raise NetboxError(
                "Failed to create IP address record in NetBox. "
                "Stopping VM creation to prevent IP conflicts"
            )
        
    except (NetboxConfigurationError, NetboxError, NetboxConnectionError, NetboxDependencyError):
        # Re-raise NetBox-specific exceptions
        raise
    except Exception as e:
        raise NetboxError(f"NetBox integration failed: {e}") from e
    
    return (ip_address, gateway, dns_servers)


def create_and_upload_cloud_init(
    proxmox,
    config: ProxmoxConfig,
    node: str,
    vmid: int,
    name: str,
    username: str,
    ssh_keys: Optional[List[str]],
    password: Optional[str],
    puppet_server: Optional[str],
    ip_address: Optional[str],
    gateway: Optional[str],
    dns_servers: List[str],
    os_name: Optional[str] = None
) -> str:
    """
    Create and upload cloud-init ISO to Proxmox storage
    
    Args:
        proxmox: ProxmoxAPI instance
        config: ProxmoxConfig instance
        node: Node name
        vmid: VM ID
        name: VM name
        username: Primary user to create
        ssh_keys: List of SSH public keys
        password: User password
        puppet_server: Puppet server hostname
        ip_address: IP address with CIDR (optional)
        gateway: Gateway IP (optional)
        dns_servers: List of DNS servers
        os_name: OS name (e.g., 'ubuntu22', 'rocky8') - used to determine network interface
    
    Returns:
        Path to cloud-init ISO in Proxmox storage
    
    Raises:
        CloudInitError if ISO creation or upload fails
    """
    storage = config.get_storage()
    
    # Generate cloud-init configuration
    cloud_init = generate_cloud_init_config(
        username=username,
        ssh_keys=ssh_keys,
        password=password,
        puppet_server=puppet_server
    )
    
    # Create cloud-init ISO file and upload it to Proxmox storage
    logger.info(f"→ Creating cloud-init ISO file...")
    
    # Use the configured storage from ini file
    iso_storage = storage
    
    # Verify the configured storage supports ISO uploads
    try:
        storages = proxmox.storage.get()
        storage_info = None
        if isinstance(storages, list):
            for s in storages:
                if isinstance(s, dict) and s.get('storage') == iso_storage:
                    storage_info = s
                    break
        
        if storage_info:
            content = storage_info.get('content', '')
            if isinstance(content, str):
                content = content.split(',')
            if 'iso' not in content:
                raise CloudInitError(
                    f"Storage '{iso_storage}' (from proxmox.ini) does not support 'iso' content type. "
                    f"Storage supports: {content}. "
                    "Please enable 'ISO image' in this storage: "
                    "Proxmox UI → Datacenter → Storage → Select storage → Edit → Content → Enable 'ISO image' checkbox"
                )
            logger.info(f"→ Using configured storage: {iso_storage}")
        else:
            raise CloudInitError(f"Storage '{iso_storage}' (from proxmox.ini) not found")
    except CloudInitError:
        raise
    except Exception as e:
        raise CloudInitError(f"Could not verify storage '{iso_storage}': {e}") from e
    
    # Create temporary directory for ISO files
    iso_filename = f"cloud-init-{vmid}.iso"
    tmp_dir = tempfile.mkdtemp()
    meta_data_path = os.path.join(tmp_dir, 'meta-data')
    user_data_path = os.path.join(tmp_dir, 'user-data')
    network_config_path = os.path.join(tmp_dir, 'network-config')
    iso_path = os.path.join(tmp_dir, iso_filename)
    cloud_init_iso_path = None
    
    try:
        # Create meta-data file
        meta_data_content = f"instance-id: {vmid}\nlocal-hostname: {name}\n"
        with open(meta_data_path, 'w') as f:
            f.write(meta_data_content)
        
        # Create user-data file (cloud-init YAML)
        with open(user_data_path, 'w') as f:
            f.write(cloud_init)
        
        # Create network-config file (required for static IP configuration)
        network_config = generate_network_config(
            ip_address=ip_address,
            gateway=gateway,
            dns_servers=dns_servers if dns_servers else None,
            os_name=os_name
        )
        with open(network_config_path, 'w') as f:
            f.write(network_config)
        
        # Generate ISO using pycdlib
        logger.info(f"→ Generating ISO image...")
        
        try:
            iso = pycdlib.PyCdlib()
            iso.new(joliet=3, rock_ridge='1.09', vol_ident='cidata')
            
            iso.add_file(meta_data_path, '/METADATA.;1', 
                        joliet_path='/meta-data',
                        rr_name='meta-data')
            iso.add_file(user_data_path, '/USERDATA.;1', 
                        joliet_path='/user-data',
                        rr_name='user-data')
            iso.add_file(network_config_path, '/NETWORK.;1',
                        joliet_path='/network-config',
                        rr_name='network-config')
            
            iso.write(iso_path)
            iso.close()
            
            logger.info(f"✓ ISO created: {iso_filename} (volume ID: cidata)")
        except Exception as e:
            raise CloudInitError(f"Failed to create ISO with pycdlib: {e}") from e
        
        # Check if ISO already exists in storage and delete it
        expected_volid = f"{iso_storage}:iso/{iso_filename}"
        logger.info(f"→ Checking if ISO already exists in storage: {expected_volid}")
        
        actual_volid = None
        try:
            storage_contents = proxmox.nodes(node).storage(iso_storage).content.get()
            for item in storage_contents:
                volid = item.get('volid', '')
                if (iso_filename in volid and 'iso' in volid) or expected_volid in volid:
                    actual_volid = volid
                    logger.info(f"→ Existing ISO found in storage: {volid}")
                    logger.info(f"→ Deleting existing ISO to ensure fresh upload...")
                    try:
                        proxmox.nodes(node).storage(iso_storage).content(volid).delete()
                        logger.info(f"✓ Existing ISO deleted: {volid}")
                        time.sleep(1)
                    except Exception as del_err:
                        logger.error(f"Failed to delete existing ISO: {del_err}")
                        logger.info(f"→ Will attempt to upload anyway (may fail if file is locked)")
                    break
        except Exception as check_err:
            logger.info(f"→ Could not check for existing ISO: {check_err}")
        
        # Upload the ISO
        logger.info(f"→ Uploading ISO to storage '{iso_storage}'...")
        
        auth_method, auth_params = config.get_auth_method()
        upload_url = f"{config.config.get('proxmox', 'host')}/api2/json/nodes/{node}/storage/{iso_storage}/upload"
        
        if auth_method == 'token':
            token_id_full = f"{auth_params['user']}!{auth_params['token_name']}"
            token_secret = auth_params['token_value']
            headers = {'Authorization': f'PVEAPIToken={token_id_full}={token_secret}'}
        else:
            raise CloudInitError("Password authentication not supported for ISO upload")
        
        # Upload the ISO file
        with open(iso_path, 'rb') as f:
            files = {'filename': (iso_filename, f, 'application/x-iso9660-image')}
            data = {'content': 'iso'}
            response = requests.post(upload_url, headers=headers, files=files, data=data, verify=False)
            
            if response.status_code != 200:
                error_data = response.json() if response.text else {}
                error_msg = error_data.get('errors', response.text)
                raise CloudInitError(f"Failed to upload ISO: HTTP {response.status_code}: {error_msg}")
            
            # Check response body for errors
            upload_upid = None
            try:
                response_data = response.json()
                if 'errors' in response_data:
                    error_msg = response_data.get('errors', 'Unknown error')
                    raise CloudInitError(f"ISO upload failed: {error_msg}")
                
                if 'data' in response_data:
                    upload_upid = response_data['data']
                elif 'upid' in response_data or 'UPID' in response_data:
                    upload_upid = response_data.get('upid') or response_data.get('UPID')
            except:
                pass
        
        # Verify ISO exists in storage
        logger.info(f"→ Verifying ISO exists in storage: {expected_volid}")
        time.sleep(1)
        
        iso_verified = False
        try:
            storage_contents = proxmox.nodes(node).storage(iso_storage).content.get()
            for item in storage_contents:
                volid = item.get('volid', '')
                if (iso_filename in volid and 'iso' in volid) or expected_volid in volid:
                    iso_verified = True
                    actual_volid = volid
                    logger.info(f"✓ ISO verified in storage: {volid}")
                    break
        except Exception as verify_err:
            logger.info(f"→ Could not immediately verify ISO: {verify_err}")
        
        # Wait for task if ISO not found and we have a UPID
        if not iso_verified and upload_upid:
            logger.info(f"→ ISO upload task started: {upload_upid}")
            if not wait_for_proxmox_task(proxmox, node, upload_upid, "ISO upload", max_wait=300):
                raise CloudInitError("ISO upload task did not complete successfully")
            
            time.sleep(1)
            try:
                storage_contents = proxmox.nodes(node).storage(iso_storage).content.get()
                for item in storage_contents:
                    volid = item.get('volid', '')
                    if (iso_filename in volid and 'iso' in volid) or expected_volid in volid:
                        iso_verified = True
                        actual_volid = volid
                        logger.info(f"✓ ISO verified in storage: {volid}")
                        break
            except Exception as verify_err:
                logger.info(f"→ Could not verify ISO after task: {verify_err}")
        
        # Final verification with retries
        if not iso_verified:
            max_verify_attempts = 5
            for attempt in range(max_verify_attempts):
                try:
                    storage_contents = proxmox.nodes(node).storage(iso_storage).content.get()
                    for item in storage_contents:
                        volid = item.get('volid', '')
                        if (iso_filename in volid and 'iso' in volid) or expected_volid in volid:
                            iso_verified = True
                            actual_volid = volid
                            logger.info(f"✓ ISO verified in storage: {volid}")
                            break
                    
                    if iso_verified:
                        break
                        
                    if attempt < max_verify_attempts - 1:
                        time.sleep(2)
                        if attempt % 2 == 0:
                            logger.info(f"→ Still waiting for ISO to appear in storage... (attempt {attempt + 1}/{max_verify_attempts})")
                except Exception as verify_err:
                    if attempt < max_verify_attempts - 1:
                        time.sleep(2)
                        continue
                    else:
                        raise CloudInitError(f"Failed to verify ISO in storage: {verify_err}")
        
        if not iso_verified:
            raise CloudInitError(
                f"ISO {iso_filename} not found in storage {iso_storage} after upload. "
                f"Expected path: {expected_volid}. "
                "Upload may have failed silently. Please check Proxmox storage manually."
            )
        
        # Use the actual volid from storage
        cloud_init_iso_path = actual_volid if actual_volid else expected_volid
        logger.info(f"✓ ISO ready: {cloud_init_iso_path}")
        
    except CloudInitError:
        raise
    except Exception as e:
        raise CloudInitError(f"Failed to create/upload cloud-init ISO: {e}") from e
    finally:
        # Clean up temporary directory
        try:
            shutil.rmtree(tmp_dir)
        except:
            pass
    
    if not cloud_init_iso_path:
        raise CloudInitError("Cloud-init ISO path not set - cannot proceed")
    
    return cloud_init_iso_path


def read_ssh_key(key_file: str) -> str:
    """
    Read SSH public key from file
    
    Args:
        key_file: Path to SSH public key file (supports ~ expansion)
    
    Returns:
        SSH public key content
    
    Raises:
        FileNotFoundError if key file doesn't exist
        ValueError if key file is empty
        IOError if key file cannot be read
    """
    # Expand ~ to home directory
    key_file = os.path.expanduser(key_file)
    
    if not os.path.exists(key_file):
        raise FileNotFoundError(f"SSH key file not found: {key_file}")
    
    try:
        with open(key_file, 'r') as f:
            key = f.read().strip()
        
        if not key:
            raise ValueError(f"SSH key file is empty: {key_file}")
        
        return key
    except (FileNotFoundError, ValueError):
        raise
    except Exception as e:
        raise IOError(f"Failed to read SSH key: {e}") from e


def create_vm_instance(
    proxmox,
    config: ProxmoxConfig,
    node: str,
    vmid: int,
    name: str,
    cores: int,
    memory: int,
    disk_size: int,
    storage: str,
    image_volid: str,
    proxmox_filename: str,
    cloud_init_iso_path: str,
    puppet: bool,
    ip_address: Optional[str],
    tags: Optional[List[str]] = None,
    cpu_type: str = 'host'
) -> bool:
    """
    Create VM instance with disk attachment (handles multiple fallback strategies)
    
    Args:
        proxmox: ProxmoxAPI instance
        config: ProxmoxConfig instance
        node: Node name
        vmid: VM ID
        name: VM name
        cores: Number of CPU cores
        memory: Memory in MB
        disk_size: Disk size in GB
        storage: Storage name
        image_volid: Image volume ID in storage
        proxmox_filename: Image filename
        cloud_init_iso_path: Path to cloud-init ISO in storage
        puppet: Enable puppet agent
        ip_address: IP address (for exception if manual intervention needed)
        tags: Optional list of additional tags to apply to the VM
    
    Returns:
        True if disk was successfully attached, False otherwise
    
    Raises:
        ManualInterventionRequired if VM created but disk attachment failed
    """
    bridge = config.get_bridge()
    
    vm_params_base = {
        'vmid': vmid,
        'name': name,
        'memory': memory,
        'cores': cores,
        'cpu': cpu_type,
        'net0': f"virtio,bridge={bridge},firewall=1",
        'scsihw': 'virtio-scsi-pci',
        'ostype': 'l26',
        'agent': 'enabled=1',
        'boot': 'order=scsi0',
        'ide2': f"{cloud_init_iso_path},media=cdrom",
    }
    
    disk_attached = False
    
    # Try method 1: Use import-from parameter
    try:
        logger.info(f"→ Trying to create VM with disk using import-from parameter...")
        logger.info(f"→ Source image: {image_volid}")
        
        import_volid = image_volid
        if 'iso/' in import_volid:
            import_volid = import_volid.replace(':iso/', ':import/')
            logger.info(f"→ Converting to import path for import-from: {import_volid}")
        
        vm_params = vm_params_base.copy()
        vm_params['scsi0'] = f"{storage}:0,import-from={import_volid}"
        
        result = proxmox.nodes(node).qemu.post(**vm_params)
        verify_vm_created(proxmox, node, vmid, result)
        logger.info(f"✓ VM {vmid} created with disk importing from {import_volid}")
        
        # Wait for disk import
        if not wait_for_vm_task(proxmox, node, vmid, "Disk import", max_wait=600):
            logger.error("Disk import did not complete - VM may still be functional")
        
        time.sleep(2)
        
        # Set tags
        vm_tags = []
        if puppet:
            vm_tags.append('puppet')
        if tags:
            vm_tags.extend(tags)
        set_vm_tags(proxmox, node, vmid, vm_tags)
        
        disk_attached = True
        return True
        
    except Exception as e1:
        logger.info(f"→ Import-from method failed: {e1}")
        
        # Try method 2: Reference file directly
        try:
            logger.info(f"→ Trying to attach disk using file_id reference...")
            vm_params = vm_params_base.copy()
            vm_params['scsi0'] = f"{storage}:{disk_size},format=qcow2,file={image_volid}"
            result = proxmox.nodes(node).qemu.post(**vm_params)
            verify_vm_created(proxmox, node, vmid, result)
            logger.info(f"✓ VM {vmid} created with disk reference")
            
            wait_for_vm_task(proxmox, node, vmid, "VM creation", max_wait=60)
            time.sleep(2)
            
            vm_tags = []
            if puppet:
                vm_tags.append('puppet')
            if tags:
                vm_tags.extend(tags)
            set_vm_tags(proxmox, node, vmid, vm_tags)
            
            disk_attached = True
            return True
        except Exception as e2:
            logger.info(f"→ File reference method failed: {e2}")
            
            # Try method 3: Create VM without disk, then attach
            try:
                logger.info(f"→ Creating VM without disk, will try to attach...")
                result = proxmox.nodes(node).qemu.post(**vm_params_base)
                verify_vm_created(proxmox, node, vmid, result)
                logger.info(f"✓ VM {vmid} created")
                
                wait_for_vm_task(proxmox, node, vmid, "VM creation", max_wait=60)
                time.sleep(2)
                
                vm_tags = []
                if puppet:
                    vm_tags.append('puppet')
                if tags:
                    vm_tags.extend(tags)
                set_vm_tags(proxmox, node, vmid, vm_tags)
                
                attachment_attempts = [
                    f"{storage}:{disk_size},format=qcow2,import-from={image_volid}",
                    f"{storage}:{disk_size},format=qcow2,file={proxmox_filename}",
                    image_volid.replace(':iso/', f':{disk_size},format=qcow2,import-from='),
                ]
                
                for attempt in attachment_attempts:
                    try:
                        logger.info(f"→ Trying disk attachment format: {attempt[:60]}...")
                        proxmox.nodes(node).qemu(vmid).config.post(scsi0=attempt)
                        logger.info(f"✓ Disk attached successfully")
                        disk_attached = True
                        return True
                    except Exception as e3:
                        logger.info(f"→ Attachment attempt failed: {str(e3)[:80]}")
                        continue
                        
            except Exception as e4:
                logger.info(f"→ VM creation failed: {e4}")
    
    # Fallback: Create VM with empty disk
    if not disk_attached:
        try:
            logger.info(f"→ Creating VM with empty disk as fallback...")
            vm_params_fallback = vm_params_base.copy()
            vm_params_fallback['scsi0'] = f"{storage}:{disk_size},format=qcow2"
            result = proxmox.nodes(node).qemu.post(**vm_params_fallback)
            verify_vm_created(proxmox, node, vmid, result)
            logger.info(f"✓ VM {vmid} created with empty disk")
            
            wait_for_vm_task(proxmox, node, vmid, "VM creation", max_wait=60)
            time.sleep(2)
            
            vm_tags = []
            if puppet:
                vm_tags.append('puppet')
            if tags:
                vm_tags.extend(tags)
            set_vm_tags(proxmox, node, vmid, vm_tags)
        except Exception as e:
            raise ProxmoxError(f"Failed to create VM: {e}") from e
        
        # Raise exception for manual intervention
        raise ManualInterventionRequired(
            vmid=vmid,
            ip_address=ip_address,
            node=node,
            image_volid=image_volid,
            proxmox_filename=proxmox_filename,
            storage=storage,
            disk_size=disk_size
        )
    
    return False


def create_vm(
    proxmox,
    config: ProxmoxConfig,
    name: str,
    os_name: str,
    cores: int,
    memory: int,
    disk_size: int,
    username: str,
    ssh_keys: Optional[List[str]] = None,
    password: Optional[str] = None,
    puppet: bool = False,
    puppet_server: Optional[str] = None,
    node: Optional[str] = None,
    start: bool = True,
    tags: Optional[List[str]] = None,
    cpu_type: Optional[str] = None
) -> tuple:
    """
    Create a new VM from downloaded Ubuntu cloud image
    
    Args:
        proxmox: ProxmoxAPI instance
        config: ProxmoxConfig instance
        name: VM name
        os_name: OS type (ubuntu22, ubuntu24, rocky8, etc.)
        cores: Number of CPU cores
        memory: Memory in MB
        disk_size: Disk size in GB
        username: Primary user to create
        ssh_keys: List of SSH public keys
        password: User password
        puppet: Enable puppet agent
        puppet_server: Puppet server hostname (required if puppet=True)
        node: Target node (auto-select if None)
        start: Start VM after creation
        tags: Optional list of additional tags to apply to the VM (OS tag is automatically added)
        cpu_type: CPU type (e.g., x86-64-v2-AES, host, kvm64). If None, uses config default
    
    Returns:
        Tuple of (VM ID, IP address, node) where IP address can be None if not configured
    """
    # Validate OS
    if not validate_os_name(os_name):
        supported = ', '.join(sorted(IMAGES.keys()))
        raise ValueError(f"Unsupported OS: {os_name}. Supported: {supported}")
    
    storage = config.get_storage()
    
    # Select node
    if not node:
        logger.info(f"→ Auto-selecting best node...")
        node = select_best_node(proxmox, memory, cores)
    
    logger.info(f"→ Target node: {node}")
    
    # Ensure image exists in storage
    image_volid, proxmox_filename = ensure_image_exists(proxmox, node, storage, os_name)
    
    # Get next available VM ID
    vmid_min, vmid_max = config.get_vmid_range()
    vmid = get_next_vmid(proxmox, vmid_min, vmid_max)
    logger.info(f"→ Assigned VM ID: {vmid}")
    
    # Set up NetBox IP allocation
    ip_address, gateway, dns_servers = setup_netbox_ip(config, name, vmid)
    
    # Create and upload cloud-init ISO
    cloud_init_iso_path = create_and_upload_cloud_init(
        proxmox=proxmox,
        config=config,
        node=node,
        vmid=vmid,
        name=name,
        username=username,
        ssh_keys=ssh_keys,
        password=password,
        puppet_server=puppet_server if puppet and puppet_server else None,
        ip_address=ip_address,
        gateway=gateway,
        dns_servers=dns_servers,
        os_name=os_name
    )
    
    # Build tags list: OS tag + user-provided tags
    vm_tags = [os_name]  # Add OS shortname as tag (e.g., ubuntu22, ubuntu24)
    if tags:
        vm_tags.extend(tags)
    
    # Determine CPU type
    if not cpu_type:
        cpu_type = config.get_default_cpu_type()
    
    # Create VM instance with disk attachment
    logger.info(f"→ Creating new VM {vmid}...")
    create_vm_instance(
        proxmox=proxmox,
        config=config,
        node=node,
        vmid=vmid,
        name=name,
        cores=cores,
        memory=memory,
        disk_size=disk_size,
        storage=storage,
        image_volid=image_volid,
        proxmox_filename=proxmox_filename,
        cloud_init_iso_path=cloud_init_iso_path,
        puppet=puppet,
        ip_address=ip_address,
        tags=vm_tags,
        cpu_type=cpu_type
    )
    
    # Resize disk if needed
    if disk_size > 3:  # Ubuntu images are typically ~2-3GB
        logger.info(f"→ Resizing disk to {disk_size}GB...")
        try:
            resize_result = proxmox.nodes(node).qemu(vmid).resize.put(
                disk='scsi0',
                size=f"{disk_size}G"
            )
            
            resize_upid = None
            if isinstance(resize_result, dict):
                resize_upid = resize_result.get('data') or resize_result.get('upid')
            elif isinstance(resize_result, str) and 'UPID' in resize_result:
                resize_upid = resize_result
            
            if resize_upid:
                wait_for_proxmox_task(proxmox, node, resize_upid, "Disk resize", max_wait=300)
            else:
                wait_for_vm_task(proxmox, node, vmid, "Disk resize", max_wait=300)
            
            logger.info(f"✓ Disk resized to {disk_size}GB")
        except Exception as resize_err:
            error_str = str(resize_err)
            if "lock" in error_str.lower() or "timeout" in error_str.lower():
                logger.info(f"→ Disk resize waiting for lock...")
                wait_for_vm_task(proxmox, node, vmid, "Disk resize", max_wait=300)
                try:
                    proxmox.nodes(node).qemu(vmid).resize.put(
                        disk='scsi0',
                        size=f"{disk_size}G"
                    )
                    wait_for_vm_task(proxmox, node, vmid, "Disk resize", max_wait=300)
                    logger.info(f"✓ Disk resized to {disk_size}GB")
                except Exception as retry_err:
                    logger.error(f"Disk resize failed: {retry_err}")
            else:
                logger.error(f"Disk resize failed: {resize_err}")
    
    # Start VM if requested
    if start:
        logger.info(f"→ Starting VM...")
        try:
            start_result = proxmox.nodes(node).qemu(vmid).status.start.post()
            start_upid = None
            if isinstance(start_result, dict):
                start_upid = start_result.get('data') or start_result.get('upid')
            elif isinstance(start_result, str) and 'UPID' in start_result:
                start_upid = start_result
            
            if start_upid:
                wait_for_proxmox_task(proxmox, node, start_upid, "VM start", max_wait=120)
            else:
                wait_for_vm_task(proxmox, node, vmid, "VM start", max_wait=120)
            
            logger.info(f"✓ VM started")
        except Exception as start_err:
            error_str = str(start_err)
            if "lock" in error_str.lower() or "timeout" in error_str.lower():
                logger.info(f"→ VM start waiting for lock...")
                wait_for_vm_task(proxmox, node, vmid, "VM start", max_wait=120)
                try:
                    status = proxmox.nodes(node).qemu(vmid).status.current.get()
                    if status.get('status') == 'running':
                        logger.info(f"✓ VM started")
                    else:
                        logger.error(f"VM start may have failed, status: {status.get('status')}")
                except:
                    pass
            else:
                logger.error(f"VM start failed: {start_err}")
    
    # Set up default firewall rules (ports 22, 80, 443, and ICMP)
    logger.info(f"→ Setting up default firewall rules...")
    setup_default_firewall_rules(proxmox, node, vmid)
    
    return (vmid, ip_address, node)


def main():
    parser = argparse.ArgumentParser(
        description='Create a VM in Proxmox from downloaded Ubuntu cloud images',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  # Create VM with SSH key authentication
  %(prog)s -n webserver -o ubuntu24 -c 4 -m 4096 -b 50 -u admin -k ~/.ssh/id_rsa.pub
  
  # Create VM with puppet enabled
  %(prog)s -n dbserver -o ubuntu22 -u admin -k ~/.ssh/id_rsa.pub -p
  
  # Create VM with specific node
  %(prog)s -n testvm -o ubuntu24 -u admin -k ~/.ssh/id_rsa.pub --node pve1
  
  # Create VM without starting it
  %(prog)s -n newvm -o ubuntu24 -u admin -k ~/.ssh/id_rsa.pub --no-start
  
  # Create VM with custom tags
  %(prog)s -n webserver -o ubuntu24 -u admin -k ~/.ssh/id_rsa.pub --tag production --tag web
  %(prog)s -n webserver -o ubuntu24 -u admin -k ~/.ssh/id_rsa.pub -t production -t web
        '''
    )
    
    # Required arguments
    parser.add_argument('-n', '--name', required=True,
                        help='VM name (required)')
    parser.add_argument('-u', '--username', default=None,
                        help='Primary user to create (default: from config or admin)')
    
    # OS and resources
    parser.add_argument('-o', '--os', dest='os_name', default='ubuntu24',
                        choices=list(IMAGES.keys()),
                        help='OS type (default: ubuntu24). Available: ' + ', '.join(sorted(IMAGES.keys())))
    parser.add_argument('-c', '--cores', type=int,
                        help='Number of CPU cores (default: from config)')
    parser.add_argument('-m', '--memory', type=int,
                        help='Memory in MB (default: from config)')
    parser.add_argument('-b', '--bootsize', dest='disk_size', type=int,
                        help='Disk size in GB (default: from config)')
    parser.add_argument('--cpu-type',
                        help='CPU type (e.g., x86-64-v2-AES, host, kvm64). Overrides config default and Rocky OS auto-detection')
    
    # Authentication
    parser.add_argument('-k', '--keyfile', dest='ssh_key_file',
                        help='SSH public key file path')
    parser.add_argument('--password',
                        help='Encrypted password hash for the user (SHA-512 format: $6$rounds=4096$salt$hash)')
    parser.add_argument('--plain-password', action='store_true',
                        help='Prompt for plaintext password and encrypt it (more secure than --password)')
    
    # Optional features
    parser.add_argument('-p', '--puppet', action='store_true',
                        help='Enable puppet agent installation and configuration')
    parser.add_argument('--puppet-server',
                        help='Puppet server hostname (overrides config file, required if -p used without config)')
    parser.add_argument('--node',
                        help='Specific node to create VM on (default: auto-select)')
    parser.add_argument('--no-start', action='store_true',
                        help='Do not start the VM after creation')
    parser.add_argument('-t', '--tag', dest='tags', action='append',
                        help='Additional tag to apply to the VM (can be specified multiple times, OS tag is automatically added)')
    
    # Configuration
    parser.add_argument('--config', default='proxmox.ini',
                        help='Path to configuration file (default: proxmox.ini)')
    
    args = parser.parse_args()
    
    # Load configuration
    try:
        config = ProxmoxConfig(args.config)
    except Exception as e:
        logger.error(f"Failed to load configuration: {e}")
        logger.info(f"→ Copy proxmox.ini.example to proxmox.ini and configure it")
        sys.exit(1)
    
    # Get defaults from config
    cores = args.cores if args.cores else config.get_default_cores()
    memory = args.memory if args.memory else config.get_default_memory()
    disk_size = args.disk_size if args.disk_size else config.get_default_disk_size()
    username = args.username if args.username else config.get_default_username()
    
    # Determine CPU type with Rocky OS special handling
    cpu_type = None
    if args.cpu_type:
        # Explicit CPU type from CLI overrides everything
        cpu_type = args.cpu_type
    elif args.os_name.startswith('rocky'):
        # Rocky Linux requires 'host' CPU type to avoid boot issues
        # Only override if user didn't explicitly set --cpu-type
        cpu_type = 'host'
        logger.warning(f"⚠️  Rocky Linux detected: Using 'host' CPU type to avoid boot hang issues")
        logger.warning(f"    (Rocky Linux may hang at 'Probing EDD' if 'host' CPU type is not used)")
        logger.warning(f"    Use --cpu-type to override if needed")
    else:
        # Use config default for other OS types
        cpu_type = config.get_default_cpu_type()
    
    # Read SSH key if provided
    ssh_keys = []
    ssh_key_file = args.ssh_key_file if args.ssh_key_file else config.get_default_ssh_key_file()
    if ssh_key_file:
        try:
            ssh_key = read_ssh_key(ssh_key_file)
            ssh_keys.append(ssh_key)
        except (FileNotFoundError, ValueError, IOError) as e:
            logger.error(str(e))
            sys.exit(1)
    
    # Handle password options
    encrypted_password = None
    if args.plain_password:
        # Prompt for plaintext password and encrypt it
        try:
            plain_password = getpass.getpass("Enter password for user: ")
            if not plain_password:
                logger.error("Password cannot be empty")
                sys.exit(1)
            confirm_password = getpass.getpass("Confirm password: ")
            if plain_password != confirm_password:
                logger.error("Passwords do not match")
                sys.exit(1)
            encrypted_password = encrypt_password(plain_password)
            logger.info(f"✓ Password encrypted successfully")
        except (KeyboardInterrupt, EOFError):
            logger.error("\nPassword input cancelled")
            sys.exit(1)
    elif args.password:
        # Validate that the password is in encrypted format
        if not args.password.startswith('$6$'):
            logger.error("Password must be an encrypted hash (SHA-512 format: $6$rounds=4096$salt$hash)")
            logger.error("Use --plain-password to provide a plaintext password, or generate an encrypted hash with: mkpasswd --method=SHA-512")
            sys.exit(1)
        encrypted_password = args.password
    else:
        # Check for default password from config
        default_password = config.get_default_password()
        if default_password:
            # Validate that the password is in encrypted format
            if not default_password.startswith('$6$'):
                logger.error("Default password in config must be an encrypted hash (SHA-512 format: $6$rounds=4096$salt$hash)")
                logger.error("Generate an encrypted hash with: mkpasswd --method=SHA-512")
                sys.exit(1)
            encrypted_password = default_password
    
    # Validate authentication method
    if not ssh_keys and not encrypted_password:
        logger.error("Must provide either SSH key (--keyfile) or password (--password, --plain-password, or default in config)")
        sys.exit(1)
    
    # Validate puppet configuration
    puppet_server = None
    if args.puppet:
        # Check if puppet server is provided via CLI or config
        if args.puppet_server:
            puppet_server = args.puppet_server
        else:
            puppet_server = config.get_puppet_server()
            if not puppet_server:
                logger.error("Puppet is enabled (-p) but no puppet server configured.")
                logger.error("Either set 'puppet_server' in proxmox.ini or use --puppet-server option")
                sys.exit(1)
    
    # Connect to Proxmox
    try:
        proxmox = connect_proxmox(config)
    except ProxmoxConnectionError as e:
        logger.error(str(e))
        sys.exit(1)
    logger.info(f"✓ Connected to Proxmox")
    
    # Display configuration
    print("\n" + "=" * 80)
    print("VM Configuration:")
    print("=" * 80)
    print(f"  Name:      {args.name}")
    print(f"  OS:        {args.os_name}")
    print(f"  Cores:     {cores}")
    print(f"  Memory:    {memory} MB")
    print(f"  Disk:      {disk_size} GB")
    print(f"  User:      {username}")
    print(f"  SSH Key:   {'Yes' if ssh_keys else 'No'}")
    print(f"  Password:  {'Yes (encrypted)' if encrypted_password else 'No'}")
    print(f"  CPU Type:  {cpu_type}")
    print(f"  Puppet:    {'Yes' if args.puppet else 'No'}")
    if args.puppet:
        print(f"  Puppet Server: {puppet_server}")
    print(f"  Node:      {args.node if args.node else 'Auto-select'}")
    print(f"  Tags:      {args.os_name}" + (f", {', '.join(args.tags)}" if args.tags else ""))
    print("=" * 80 + "\n")
    
    # Create VM
    try:
        vmid, ip_address, node = create_vm(
            proxmox=proxmox,
            config=config,
            name=args.name,
            os_name=args.os_name,
            cores=cores,
            memory=memory,
            disk_size=disk_size,
            username=username,
            ssh_keys=ssh_keys if ssh_keys else None,
            password=encrypted_password,
            puppet=args.puppet,
            puppet_server=puppet_server if args.puppet else None,
            node=args.node,
            start=not args.no_start,
            tags=args.tags,
            cpu_type=cpu_type
        )
        
        print("\n" + "=" * 80)
        logger.info(f"✓ VM successfully created!")
        print("=" * 80)
        print(f"  VM ID:    {vmid}")
        print(f"  Name:     {args.name}")
        if ip_address:
            # Extract IP without CIDR for display
            ip_display = ip_address.split('/')[0]
            print(f"  IP:       {ip_display}")
        print(f"  Status:   {'Running' if not args.no_start else 'Stopped'}")
        print(f"  Node:     {node}")
        print(f"  OS:       {args.os_name}")
        print(f"  Cores:    {cores}")
        print(f"  Memory:   {memory} MB")
        print(f"  Disk:     {disk_size} GB")
        print(f"  User:     {username}")
        print(f"  SSH Key:  {'Yes' if ssh_keys else 'No'}")
        print(f"  Password: {'Yes (encrypted)' if encrypted_password else 'No'}")
        print(f"  CPU Type: {cpu_type}")
        print(f"  Puppet:   {'Yes' if args.puppet else 'No'}")
        if args.puppet:
            print(f"  Puppet Server: {puppet_server}")
        print(f"  Tags:     {args.os_name}" + (f", {', '.join(args.tags)}" if args.tags else ""))
        print("=" * 80)
        print("\nNote: Wait a few minutes for cloud-init to complete initial setup.")
        print("      You can monitor progress in the Proxmox web interface.")
        print("=" * 80 + "\n")
        
    except (ImageNotFoundError, ValueError) as e:
        logger.error(str(e))
        sys.exit(1)
    except (NetboxConfigurationError, NetboxError, NetboxConnectionError, NetboxDependencyError) as e:
        logger.error(str(e))
        sys.exit(1)
    except CloudInitError as e:
        logger.error(str(e))
        sys.exit(1)
    except (ProxmoxError, ProxmoxConnectionError, ProxmoxNodeError, ProxmoxVMIDError) as e:
        logger.error(str(e))
        sys.exit(1)
    except ManualInterventionRequired as e:
        # VM was created but requires manual disk import
        print("\n" + "=" * 80)
        logger.error("VM CREATED BUT REQUIRES MANUAL INTERVENTION")
        print("=" * 80)
        print(f"  VM ID:   {e.vmid}")
        print(f"  Name:    {args.name}")
        if e.ip_address:
            # Extract IP without CIDR for display
            ip_display = e.ip_address.split('/')[0]
            print(f"  IP:      {ip_display}")
        print(f"  Status:  Created with empty disk (manual import required)")
        print("=" * 80)
        
        logger.error(f"\n{'=' * 80}")
        logger.error("IMPORTANT: Manual disk import required")
        logger.error(f"{'=' * 80}")
        logger.error(f"\nThe VM {e.vmid} was created with an empty disk.")
        logger.error(f"The Ubuntu image is in storage but needs to be imported manually.")
        logger.error(f"\nImage location: {e.image_volid}")
        logger.error(f"\nRun these commands on Proxmox node '{e.node}':")
        logger.error(f"\n  # Remove the empty disk first")
        logger.error(f"  qm set {e.vmid} --delete scsi0")
        logger.error(f"\n  # Import the image as a disk")
        logger.error(f"  qm disk import {e.vmid} {e.proxmox_filename} {e.storage} --format qcow2")
        logger.error(f"\n  # Attach the imported disk")
        logger.error(f"  qm set {e.vmid} --scsi0 {e.storage}:vm-{e.vmid}-disk-0")
        logger.error(f"\n  # Resize disk if needed (currently set to {e.disk_size}GB)")
        if e.disk_size > 2:
            logger.error(f"  qm disk resize {e.vmid} scsi0 {e.disk_size}G")
        logger.error(f"\n  # Start the VM")
        logger.error(f"  qm start {e.vmid}")
        logger.error(f"\n{'=' * 80}")
        logger.info(f"→ \nNote: This is a Proxmox API limitation - disk import from iso storage cannot be automated.")
        logger.info(f"→ VM {e.vmid} is ready for manual disk import steps above.")
        print("=" * 80 + "\n")
        sys.exit(1)
        
    except KeyboardInterrupt:
        print("\n\nOperation cancelled by user")
        sys.exit(1)
    except Exception as e:
        logger.error(f"Unexpected error: {e}")
        sys.exit(1)


if __name__ == '__main__':
    main()

