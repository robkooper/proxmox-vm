#!/usr/bin/env python3
"""
Proxmox VM Start Script

Start VMs in Proxmox by name or ID.
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


def start_vm(proxmox, vm_info: dict) -> bool:
    """
    Start a VM
    
    Args:
        proxmox: ProxmoxAPI instance
        vm_info: Dict with 'vmid', 'name', 'node', 'status'
    
    Returns:
        True if started successfully, False otherwise
    """
    vmid = vm_info['vmid']
    name = vm_info['name']
    node = vm_info['node']
    status = vm_info['status']
    
    print_info(f"VM {vmid} ({name}) on node {node} (status: {status})")
    
    # Check if VM is already running
    if status == 'running':
        print_info(f"VM {vmid} is already running")
        return True
    
    try:
        # Start the VM
        print_info(f"Starting VM {vmid}...")
        proxmox.nodes(node).qemu(vmid).status.start.post()
        
        # Wait for VM to start
        max_wait = 60  # 60 second timeout
        elapsed = 0
        while elapsed < max_wait:
            vm_status = proxmox.nodes(node).qemu(vmid).status.current.get()
            if vm_status.get('status') == 'running':
                print_success(f"VM {vmid} ({name}) started successfully")
                return True
            time.sleep(1)
            elapsed += 1
        
        if elapsed >= max_wait:
            print_error(f"VM {vmid} did not start within timeout")
            return False
        
    except Exception as e:
        print_error(f"Failed to start VM {vmid}: {e}")
        return False


def main():
    parser = argparse.ArgumentParser(
        description='Start VMs in Proxmox by name or ID',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  # Start VM by name
  %(prog)s -n webserver
  
  # Start VM by ID
  %(prog)s -i 100
        '''
    )
    
    parser.add_argument('--config', default='proxmox.ini',
                        help='Path to configuration file (default: proxmox.ini)')
    parser.add_argument('-n', '--name', dest='vm_name',
                        help='VM name to start')
    parser.add_argument('-i', '--id', dest='vm_id', type=int,
                        help='VM ID to start')
    
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
    
    # Start VM
    if start_vm(proxmox, vm):
        print_success("VM start completed")
    else:
        print_error("VM start failed")
        sys.exit(1)


if __name__ == '__main__':
    main()
