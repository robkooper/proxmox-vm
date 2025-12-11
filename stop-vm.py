#!/usr/bin/env python3
"""
Proxmox VM Stop Script

Stop VMs in Proxmox by name or ID.
"""

import argparse
import sys
import time
from proxmox_utils import (
    ProxmoxConfig,
    connect_proxmox,
    print_error,
    print_success,
    print_info,
    ProxmoxError,
    ProxmoxConnectionError,
    find_vm_by_name,
    find_vm_by_id
)


def stop_vm(proxmox, vm_info: dict) -> bool:
    """
    Stop a VM
    
    Args:
        proxmox: ProxmoxAPI instance
        vm_info: Dict with 'vmid', 'name', 'node', 'status'
    
    Returns:
        True if stopped successfully, False otherwise
    """
    vmid = vm_info['vmid']
    name = vm_info['name']
    node = vm_info['node']
    status = vm_info['status']
    
    print_info(f"VM {vmid} ({name}) on node {node} (status: {status})")
    
    # Check if VM is already stopped
    if status == 'stopped':
        print_info(f"VM {vmid} is already stopped")
        return True
    
    try:
        # Stop the VM
        print_info(f"Stopping VM {vmid}...")
        proxmox.nodes(node).qemu(vmid).status.stop.post()
        
        # Wait for VM to stop
        max_wait = 60  # 60 second timeout
        elapsed = 0
        while elapsed < max_wait:
            vm_status = proxmox.nodes(node).qemu(vmid).status.current.get()
            if vm_status.get('status') == 'stopped':
                print_success(f"VM {vmid} ({name}) stopped successfully")
                return True
            time.sleep(1)
            elapsed += 1
        
        if elapsed >= max_wait:
            print_error(f"VM {vmid} did not stop within timeout")
            return False
        
    except Exception as e:
        print_error(f"Failed to stop VM {vmid}: {e}")
        return False


def main():
    parser = argparse.ArgumentParser(
        description='Stop VMs in Proxmox by name or ID',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  # Stop VM by name
  %(prog)s -n webserver
  
  # Stop VM by ID
  %(prog)s -i 100
        '''
    )
    
    parser.add_argument('--config', default='proxmox.ini',
                        help='Path to configuration file (default: proxmox.ini)')
    parser.add_argument('-n', '--name', dest='vm_name',
                        help='VM name to stop')
    parser.add_argument('-i', '--id', dest='vm_id', type=int,
                        help='VM ID to stop')
    
    args = parser.parse_args()
    
    # Validate arguments
    if not args.vm_name and args.vm_id is None:
        print_error("Must specify either --name (-n) or --id (-i)")
        parser.print_help()
        sys.exit(1)
    
    if args.vm_name and args.vm_id is not None:
        print_error("Cannot specify both --name and --id")
        sys.exit(1)
    
    # Load configuration
    try:
        config = ProxmoxConfig(args.config)
    except Exception as e:
        print_error(f"Failed to load configuration: {e}")
        sys.exit(1)
    
    # Connect to Proxmox
    try:
        proxmox = connect_proxmox(config)
    except ProxmoxConnectionError as e:
        print_error(str(e))
        sys.exit(1)
    print_success("Connected to Proxmox")
    
    # Find VM
    vm = None
    
    if args.vm_name:
        print_info(f"Searching for VM with name '{args.vm_name}'...")
        vm = find_vm_by_name(proxmox, args.vm_name)
        
        if not vm:
            print_error(f"VM with name '{args.vm_name}' not found")
            sys.exit(1)
        
        print_success(f"Found VM {vm['vmid']} ({vm['name']}) on node {vm['node']}")
    
    elif args.vm_id is not None:
        print_info(f"Searching for VM with ID {args.vm_id}...")
        vm = find_vm_by_id(proxmox, args.vm_id)
        
        if not vm:
            print_error(f"VM with ID {args.vm_id} not found")
            sys.exit(1)
        
        print_success(f"Found VM {args.vm_id} ({vm['name']}) on node {vm['node']}")
    
    # Stop VM
    if stop_vm(proxmox, vm):
        print_success("VM stop completed")
    else:
        print_error("VM stop failed")
        sys.exit(1)


if __name__ == '__main__':
    main()
