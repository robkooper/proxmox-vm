"""VM management commands"""

import argparse
import getpass
import os
import sys
import time

from proxmox.proxmox_utils import (
    ProxmoxConfig,
    connect_proxmox,
    IMAGES,
    logger,
    ProxmoxError,
    ProxmoxConnectionError,
    ProxmoxNodeError,
    ProxmoxVMIDError,
    encrypt_password,
    find_vm_by_name,
    find_vm_by_id,
)
from proxmox.netbox_utils import (
    NetboxConnectionError,
    NetboxDependencyError,
)
from proxmox.vm_create import (
    create_vm,
    read_ssh_key,
    ImageNotFoundError,
    NetboxConfigurationError,
    NetboxError,
    CloudInitError,
    ManualInterventionRequired,
)


def setup_create_parser(parser):
    """Setup argument parser for VM create command"""
    # Required arguments
    parser.add_argument('vm',
                        help='VM name (required)')
    parser.add_argument('-u', '--username', default='admin',
                        help='Primary user to create (default: admin)')
    
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


def setup_delete_parser(parser):
    """Setup argument parser for VM delete command"""
    parser.add_argument('vm',
                        help='VM name or ID to delete (will delete all matching VMs if name matches multiple)')
    parser.add_argument('-f', '--force', action='store_true',
                        help='Force delete without confirmation')


def setup_start_parser(parser):
    """Setup argument parser for VM start command"""
    parser.add_argument('vm',
                        help='VM name or ID to start')


def setup_stop_parser(parser):
    """Setup argument parser for VM stop command"""
    parser.add_argument('vm',
                        help='VM name or ID to stop')


def setup_list_parser(parser):
    """Setup argument parser for VM list command"""
    parser.add_argument('-s', '--sort', choices=['name', 'node', 'id'], default='id',
                        help='Sort by name, node, or id (default: id)')
    parser.add_argument('-f', '--filter', action='append',
                        help='Filter by node, tag, or status. Format: node:value, tag:value, or status:value. Can be specified multiple times (AND logic)')


def handle_create(args):
    """Handle VM create command"""
    # Load configuration
    try:
        config = ProxmoxConfig(args.config)
    except FileNotFoundError as e:
        logger.error(str(e))
        sys.exit(1)
    except Exception as e:
        logger.error(f"Failed to load configuration: {e}")
        sys.exit(1)
    
    # Get defaults from config
    cores = args.cores if args.cores else config.get_default_cores()
    memory = args.memory if args.memory else config.get_default_memory()
    disk_size = args.disk_size if args.disk_size else config.get_default_disk_size()
    
    # Read SSH key if provided
    ssh_keys = []
    if args.ssh_key_file:
        try:
            ssh_key = read_ssh_key(args.ssh_key_file)
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
    
    # Validate authentication method
    if not ssh_keys and not encrypted_password:
        logger.error("Must provide either SSH key (--keyfile) or password (--password or --plain-password)")
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
                logger.error(f"Either set 'puppet_server' in {config.config_file} or use --puppet-server option")
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
    print(f"  Name:      {args.vm}")
    print(f"  OS:        {args.os_name}")
    print(f"  Cores:     {cores}")
    print(f"  Memory:    {memory} MB")
    print(f"  Disk:      {disk_size} GB")
    print(f"  User:      {args.username}")
    print(f"  SSH Key:   {'Yes' if ssh_keys else 'No'}")
    print(f"  Password:  {'Yes (encrypted)' if encrypted_password else 'No'}")
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
            name=args.vm,
            os_name=args.os_name,
            cores=cores,
            memory=memory,
            disk_size=disk_size,
            username=args.username,
            ssh_keys=ssh_keys if ssh_keys else None,
            password=encrypted_password,
            puppet=args.puppet,
            puppet_server=puppet_server if args.puppet else None,
            node=args.node,
            start=not args.no_start,
            tags=args.tags
        )
        
        print("\n" + "=" * 80)
        logger.info(f"✓ VM successfully created!")
        print("=" * 80)
        print(f"  VM ID:    {vmid}")
        print(f"  Name:     {args.vm}")
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
        print(f"  User:     {args.username}")
        print(f"  SSH Key:  {'Yes' if ssh_keys else 'No'}")
        print(f"  Password: {'Yes (encrypted)' if encrypted_password else 'No'}")
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
        print(f"  Name:    {args.vm}")
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


def handle_delete(args):
    """Handle VM delete command"""
    # Load configuration
    try:
        config = ProxmoxConfig(args.config)
    except FileNotFoundError as e:
        logger.error(str(e))
        sys.exit(1)
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
    
    # Import delete functions from vm_delete.py
    from proxmox.vm_delete import find_vms_by_name, find_vm_by_id, delete_vm
    
    # Try to parse as integer (VM ID), otherwise treat as name
    vms_to_delete = []
    
    try:
        vm_id = int(args.vm)
        # It's a VM ID
        logger.info(f"→ Searching for VM with ID {vm_id}...")
        vm = find_vm_by_id(proxmox, vm_id)
        
        if not vm:
            logger.error(f"VM with ID {vm_id} not found")
            sys.exit(1)
        
        vms_to_delete = [vm]
        logger.info(f"✓ Found VM {vm_id} ({vm['name']}) on node {vm['node']}")
    except ValueError:
        # Not an integer, treat as VM name
        logger.info(f"→ Searching for VMs with name '{args.vm}'...")
        vms_to_delete = find_vms_by_name(proxmox, args.vm)
        
        if not vms_to_delete:
            logger.error(f"No VMs found with name '{args.vm}'")
            sys.exit(1)
        
        logger.info(f"✓ Found {len(vms_to_delete)} VM(s) with name '{args.vm}'")
        for vm in vms_to_delete:
            logger.info(f"→   VM {vm['vmid']} on node {vm['node']} (status: {vm['status']})")
    
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


def find_vm_identifier(proxmox, vm_identifier: str):
    """
    Find VM by name or ID
    
    Args:
        proxmox: ProxmoxAPI instance
        vm_identifier: VM name or ID (as string)
    
    Returns:
        VM info dict with 'vmid', 'name', 'node', 'status' or None if not found
    """
    # Try to parse as integer (VM ID)
    try:
        vm_id = int(vm_identifier)
        logger.info(f"→ Searching for VM with ID {vm_id}...")
        vm = find_vm_by_id(proxmox, vm_id)
        if vm:
            logger.info(f"✓ Found VM {vm_id} ({vm['name']}) on node {vm['node']}")
        return vm
    except ValueError:
        # Not an integer, treat as VM name
        logger.info(f"→ Searching for VM with name '{vm_identifier}'...")
        vm = find_vm_by_name(proxmox, vm_identifier)
        if vm:
            logger.info(f"✓ Found VM {vm['vmid']} ({vm['name']}) on node {vm['node']}")
        return vm


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
    
    logger.info(f"→ VM {vmid} ({name}) on node {node} (status: {status})")
    
    # Check if VM is already running
    if status == 'running':
        logger.info(f"→ VM {vmid} is already running")
        return True
    
    try:
        # Start the VM
        logger.info(f"→ Starting VM {vmid}...")
        proxmox.nodes(node).qemu(vmid).status.start.post()
        
        # Wait for VM to start
        max_wait = 60  # 60 second timeout
        elapsed = 0
        while elapsed < max_wait:
            vm_status = proxmox.nodes(node).qemu(vmid).status.current.get()
            if vm_status.get('status') == 'running':
                logger.info(f"✓ VM {vmid} ({name}) started successfully")
                return True
            time.sleep(1)
            elapsed += 1
        
        if elapsed >= max_wait:
            logger.error(f"VM {vmid} did not start within timeout")
            return False
        
    except Exception as e:
        logger.error(f"Failed to start VM {vmid}: {e}")
        return False


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
    
    logger.info(f"→ VM {vmid} ({name}) on node {node} (status: {status})")
    
    # Check if VM is already stopped
    if status == 'stopped':
        logger.info(f"→ VM {vmid} is already stopped")
        return True
    
    try:
        # Stop the VM
        logger.info(f"→ Stopping VM {vmid}...")
        proxmox.nodes(node).qemu(vmid).status.stop.post()
        
        # Wait for VM to stop
        max_wait = 60  # 60 second timeout
        elapsed = 0
        while elapsed < max_wait:
            vm_status = proxmox.nodes(node).qemu(vmid).status.current.get()
            if vm_status.get('status') == 'stopped':
                logger.info(f"✓ VM {vmid} ({name}) stopped successfully")
                return True
            time.sleep(1)
            elapsed += 1
        
        if elapsed >= max_wait:
            logger.error(f"VM {vmid} did not stop within timeout")
            return False
        
    except Exception as e:
        logger.error(f"Failed to stop VM {vmid}: {e}")
        return False


def handle_start(args):
    """Handle VM start command"""
    # Load configuration
    try:
        config = ProxmoxConfig(args.config)
    except FileNotFoundError as e:
        logger.error(str(e))
        sys.exit(1)
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
    
    # Find VM by name or ID
    vm = find_vm_identifier(proxmox, args.vm)
    if not vm:
        logger.error(f"VM '{args.vm}' not found")
        sys.exit(1)
    
    # Start VM
    if start_vm(proxmox, vm):
        logger.info("✓ VM start completed")
    else:
        logger.error("VM start failed")
        sys.exit(1)


def handle_stop(args):
    """Handle VM stop command"""
    # Load configuration
    try:
        config = ProxmoxConfig(args.config)
    except FileNotFoundError as e:
        logger.error(str(e))
        sys.exit(1)
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
    
    # Find VM by name or ID
    vm = find_vm_identifier(proxmox, args.vm)
    if not vm:
        logger.error(f"VM '{args.vm}' not found")
        sys.exit(1)
    
    # Stop VM
    if stop_vm(proxmox, vm):
        logger.info("✓ VM stop completed")
    else:
        logger.error("VM stop failed")
        sys.exit(1)


def list_all_vms(proxmox):
    """
    List all VMs from all nodes with tags
    
    Args:
        proxmox: ProxmoxAPI instance
    
    Returns:
        List of VM info dicts with 'vmid', 'name', 'node', 'status', 'tags'
    """
    all_vms = []
    try:
        nodes = proxmox.nodes.get()
        for node in nodes:
            node_name = node['node']
            try:
                vms = proxmox.nodes(node_name).qemu.get()
                for vm in vms:
                    vmid = vm.get('vmid')
                    # Get tags for this VM
                    tags = []
                    try:
                        vm_config = proxmox.nodes(node_name).qemu(vmid).config.get()
                        tags_str = vm_config.get('tags', '')
                        if tags_str:
                            # Proxmox stores tags as semicolon-separated string
                            tags = [tag.strip() for tag in tags_str.split(';') if tag.strip()]
                    except Exception:
                        # If we can't get tags, continue with empty list
                        pass
                    
                    all_vms.append({
                        'vmid': vmid,
                        'name': vm.get('name', ''),
                        'node': node_name,
                        'status': vm.get('status', 'unknown'),
                        'tags': tags
                    })
            except Exception as e:
                logger.error(f"Error querying node {node_name}: {e}")
                continue
    except Exception as e:
        logger.error(f"Error querying nodes: {e}")
        raise
    
    return all_vms


def handle_list(args):
    """Handle VM list command"""
    # Load configuration
    try:
        config = ProxmoxConfig(args.config)
    except FileNotFoundError as e:
        logger.error(str(e))
        sys.exit(1)
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
    
    # List all VMs
    vms = list_all_vms(proxmox)
    
    # Apply filters if specified (all filters must match - AND logic)
    if args.filter:
        for filter_str in args.filter:
            filter_parts = filter_str.split(':', 1)
            if len(filter_parts) != 2:
                logger.error(f"Filter format must be 'type:value' (e.g., 'node:pve1', 'tag:production', 'status:running'). Got: {filter_str}")
                sys.exit(1)
            
            filter_type = filter_parts[0].lower()
            filter_value = filter_parts[1]
            
            if filter_type == 'node':
                vms = [vm for vm in vms if vm['node'].lower() == filter_value.lower()]
            elif filter_type == 'tag':
                # Filter VMs that have the specified tag (case-insensitive match)
                filter_tag_lower = filter_value.lower()
                vms = [vm for vm in vms if any(tag.lower() == filter_tag_lower for tag in vm['tags'])]
            elif filter_type == 'status':
                vms = [vm for vm in vms if vm['status'].lower() == filter_value.lower()]
            else:
                logger.error(f"Invalid filter type: {filter_type}. Must be 'node', 'tag', or 'status'")
                sys.exit(1)
    
    if not vms:
        print("\nNo VMs found")
        return
    
    # Print header
    print("\n" + "=" * 100)
    print("VMs:")
    print("=" * 100)
    print(f"{'VM ID':<8} {'Name':<30} {'Node':<20} {'Status':<15} {'Tags':<30}")
    print("-" * 100)
    
    # Sort based on user's choice
    sort_key = args.sort
    if sort_key == 'name':
        vms_sorted = sorted(vms, key=lambda x: (x['name'].lower(), x['vmid']))
    elif sort_key == 'node':
        vms_sorted = sorted(vms, key=lambda x: (x['node'].lower(), x['vmid']))
    else:  # 'id' (default)
        vms_sorted = sorted(vms, key=lambda x: x['vmid'])
    
    # Print each VM
    for vm in vms_sorted:
        tags_str = ', '.join(vm['tags']) if vm['tags'] else '(none)'
        # Truncate tags if too long
        if len(tags_str) > 28:
            tags_str = tags_str[:25] + '...'
        print(f"{vm['vmid']:<8} {vm['name']:<30} {vm['node']:<20} {vm['status']:<15} {tags_str:<30}")
    
    print("=" * 100)
    print(f"\nTotal: {len(vms)} VM(s)")
