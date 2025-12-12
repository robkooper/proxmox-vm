#!/usr/bin/env python3
"""
Proxmox VM Deletion Script

Delete VMs in Proxmox by name or ID with confirmation prompts.
Supports deleting multiple VMs with the same name.
"""

import argparse
import sys
from proxmox.proxmox_utils import (
    ProxmoxConfig,
    connect_proxmox,
    logger,
    ProxmoxError,
    ProxmoxConnectionError
)
from proxmox.netbox_utils import (
    connect_netbox,
    delete_ip_address_by_hostname_in_netbox,
    NetboxConnectionError,
    NetboxDependencyError
)


def find_vms_by_name(proxmox, name: str) -> list:
    """
    Find all VMs matching the given name
    
    Args:
        proxmox: ProxmoxAPI instance
        name: VM name to search for
    
    Returns:
        List of VM info dicts with 'vmid' and 'name'
    """
    matching_vms = []
    
    try:
        # Get all VMs from all nodes
        nodes = proxmox.nodes.get()
        for node in nodes:
            node_name = node['node']
            try:
                vms = proxmox.nodes(node_name).qemu.get()
                for vm in vms:
                    vm_name = vm.get('name', '')
                    vm_vmid = vm.get('vmid')
                    if vm_name == name:
                        matching_vms.append({
                            'vmid': vm_vmid,
                            'name': vm_name,
                            'node': node_name,
                            'status': vm.get('status', 'unknown')
                        })
            except Exception as e:
                logger.error(f"Error querying node {node_name}: {e}")
                continue
    except Exception as e:
        logger.error(f"Error querying nodes: {e}")
        raise
    
    return matching_vms


def find_vm_by_id(proxmox, vmid: int) -> dict:
    """
    Find VM by ID
    
    Args:
        proxmox: ProxmoxAPI instance
        vmid: VM ID to search for
    
    Returns:
        VM info dict with 'vmid', 'name', 'node', 'status' or None if not found
    """
    try:
        nodes = proxmox.nodes.get()
        for node in nodes:
            node_name = node['node']
            try:
                vms = proxmox.nodes(node_name).qemu.get()
                for vm in vms:
                    if vm.get('vmid') == vmid:
                        return {
                            'vmid': vm.get('vmid'),
                            'name': vm.get('name', ''),
                            'node': node_name,
                            'status': vm.get('status', 'unknown')
                        }
            except Exception as e:
                logger.error(f"Error querying node {node_name}: {e}")
                continue
    except Exception as e:
        logger.error(f"Error querying nodes: {e}")
        raise
    
    return None


def delete_cloud_init_iso(proxmox, node: str, storage: str, vmid: int) -> bool:
    """
    Delete the cloud-init ISO file associated with a VM
    
    Args:
        proxmox: ProxmoxAPI instance
        node: Node name
        storage: Storage name
        vmid: VM ID
    
    Returns:
        True if ISO was found and deleted, False if not found or error
    """
    iso_filename = f"cloud-init-{vmid}.iso"
    expected_volid = f"{storage}:iso/{iso_filename}"
    
    try:
        # Search for the ISO file in storage
        storage_contents = proxmox.nodes(node).storage(storage).content.get()
        matching_volid = None
        
        for item in storage_contents:
            volid = item.get('volid', '')
            # Check if this is our cloud-init ISO (match by filename or full path)
            if (iso_filename in volid and 'iso' in volid) or expected_volid in volid:
                matching_volid = volid
                break
        
        if matching_volid:
            logger.info(f"→ Deleting cloud-init ISO: {matching_volid}")
            try:
                proxmox.nodes(node).storage(storage).content(matching_volid).delete()
                logger.info(f"✓ Cloud-init ISO deleted: {matching_volid}")
                return True
            except Exception as del_err:
                logger.error(f"Failed to delete cloud-init ISO: {del_err}")
                return False
        else:
            # ISO not found - that's okay, it might have been deleted already
            logger.info(f"→ Cloud-init ISO not found (may have been deleted already): {expected_volid}")
            return False
            
    except Exception as e:
        # If we can't check/delete the ISO, log it but don't fail the VM deletion
        logger.info(f"→ Could not delete cloud-init ISO (non-fatal): {e}")
        return False


def delete_vm(proxmox, vm_info: dict, config: ProxmoxConfig, force: bool = False) -> bool:
    """
    Delete a VM with optional confirmation
    
    Args:
        proxmox: ProxmoxAPI instance
        vm_info: Dict with 'vmid', 'name', 'node', 'status'
        config: ProxmoxConfig instance to check vmid range
        force: Skip confirmation if True
    
    Returns:
        True if deleted, False if cancelled or outside range
    """
    vmid = vm_info['vmid']
    name = vm_info['name']
    node = vm_info['node']
    status = vm_info['status']
    
    # Check if VM ID is within the configured range
    vmid_min, vmid_max = config.get_vmid_range()
    if vmid < vmid_min or vmid > vmid_max:
        logger.error(f"\nVM {vmid} ({name}) is outside the configured VM ID range ({vmid_min}-{vmid_max})")
        logger.error("Deletion aborted for safety. To delete VMs outside this range, adjust vmid_min/vmid_max in proxmox.ini")
        return False
    
    logger.info(f"→\nVM {vmid} ({name}) on node {node} (status: {status})")
    
    if not force:
        # Prompt for confirmation
        response = input(f"Delete VM {vmid} ({name})? [y/N]: ").strip().lower()
        if response != 'y':
            logger.info(f"→ Skipping VM {vmid}")
            return False
    
    try:
        # Stop VM if it's running
        if status == 'running':
            logger.info(f"→ Stopping VM {vmid}...")
            proxmox.nodes(node).qemu(vmid).status.stop.post()
            
            # Wait for VM to stop
            import time
            max_wait = 60  # 60 second timeout
            elapsed = 0
            while elapsed < max_wait:
                vm_status = proxmox.nodes(node).qemu(vmid).status.current.get()
                if vm_status.get('status') == 'stopped':
                    break
                time.sleep(1)
                elapsed += 1
            
            if elapsed >= max_wait:
                logger.error(f"VM {vmid} did not stop within timeout, attempting to delete anyway...")
        
        # Delete the VM
        logger.info(f"→ Deleting VM {vmid}...")
        proxmox.nodes(node).qemu(vmid).delete()
        logger.info(f"✓ VM {vmid} ({name}) deleted successfully")
        
        # Delete the associated cloud-init ISO file
        storage = config.get_storage()
        delete_cloud_init_iso(proxmox, node, storage, vmid)
        
        # Delete DNS entry from NetBox if configured
        if config.has_netbox_config():
            try:
                netbox_url = config.get_netbox_url()
                netbox_token = config.get_netbox_token()
                netbox_domain = config.get_netbox_domain()
                
                if netbox_url and netbox_token:
                    try:
                        nb = connect_netbox(netbox_url, netbox_token)
                        logger.info(f"→ Deleting DNS entry for {name}...")
                        if delete_ip_address_by_hostname_in_netbox(nb, name, netbox_domain):
                            logger.info(f"✓ DNS entry deleted successfully")
                        else:
                            logger.info(f"→ DNS entry not found or already deleted (non-fatal)")
                    except (NetboxDependencyError, NetboxConnectionError) as e:
                        logger.info(f"→ Could not delete DNS entry (non-fatal): {e}")
                    except Exception as e:
                        logger.info(f"→ Error deleting DNS entry (non-fatal): {e}")
            except Exception as e:
                logger.info(f"→ Could not delete DNS entry (non-fatal): {e}")
        
        return True
        
    except Exception as e:
        logger.error(f"Failed to delete VM {vmid}: {e}")
        return False


def main():
    parser = argparse.ArgumentParser(
        description='Delete VMs in Proxmox by name or ID',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  # Delete VM by name (with confirmation for each match)
  %(prog)s -n webserver
  
  # Delete VM by ID
  %(prog)s -i 100
  
  # Force delete without confirmation
  %(prog)s -n testvm -f
  
  # Delete VM by ID without confirmation
  %(prog)s -i 101 -f
        '''
    )
    
    parser.add_argument('--config', default='proxmox.ini',
                        help='Path to configuration file (default: proxmox.ini)')
    parser.add_argument('-n', '--name', dest='vm_name',
                        help='VM name to delete (will delete all matching VMs)')
    parser.add_argument('-i', '--id', dest='vm_id', type=int,
                        help='VM ID to delete')
    parser.add_argument('-f', '--force', action='store_true',
                        help='Force delete without confirmation')
    
    args = parser.parse_args()
    
    # Validate arguments
    if not args.vm_name and args.vm_id is None:
        logger.error("Must specify either --name (-n) or --id (-i)")
        parser.print_help()
        sys.exit(1)
    
    if args.vm_name and args.vm_id is not None:
        logger.error("Cannot specify both --name and --id")
        sys.exit(1)
    
    # Load configuration
    try:
        config = ProxmoxConfig(args.config)
    except Exception as e:
        logger.error(f"Failed to load configuration: {e}")
        sys.exit(1)
    
    # Connect to Proxmox
    try:
        proxmox = connect_proxmox(config)
    except ProxmoxConnectionError as e:
        logger.error(str(e))
        sys.exit(1)
    logger.info("✓ Connected to Proxmox")
    
    # Find VMs to delete
    vms_to_delete = []
    
    if args.vm_name:
        logger.info(f"→ Searching for VMs with name '{args.vm_name}'...")
        vms_to_delete = find_vms_by_name(proxmox, args.vm_name)
        
        if not vms_to_delete:
            logger.error(f"No VMs found with name '{args.vm_name}'")
            sys.exit(1)
        
        logger.info(f"✓ Found {len(vms_to_delete)} VM(s) with name '{args.vm_name}'")
        for vm in vms_to_delete:
            logger.info(f"→   VM {vm['vmid']} on node {vm['node']} (status: {vm['status']})")
    
    elif args.vm_id is not None:
        logger.info(f"→ Searching for VM with ID {args.vm_id}...")
        vm = find_vm_by_id(proxmox, args.vm_id)
        
        if not vm:
            logger.error(f"VM with ID {args.vm_id} not found")
            sys.exit(1)
        
        vms_to_delete = [vm]
        logger.info(f"✓ Found VM {args.vm_id} ({vm['name']}) on node {vm['node']}")
    
    # Delete VMs
    deleted_count = 0
    skipped_count = 0
    
    for vm in vms_to_delete:
        if delete_vm(proxmox, vm, config, force=args.force):
            deleted_count += 1
        else:
            skipped_count += 1
    
    # Summary
    print(f"\n{'=' * 80}")
    print(f"Summary:")
    print(f"  Deleted: {deleted_count}")
    print(f"  Skipped: {skipped_count}")
    print(f"{'=' * 80}")
    
    if deleted_count > 0:
        logger.info("✓ Deletion completed")
    else:
        logger.info("→ No VMs were deleted")


if __name__ == '__main__':
    main()

