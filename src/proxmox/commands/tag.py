"""Tag management commands for VMs"""

import argparse
import sys
import time

from proxmox.proxmox_utils import (
    ProxmoxConfig,
    connect_proxmox,
    logger,
    ProxmoxConnectionError,
    find_vm_by_name,
    find_vm_by_id,
)


def setup_create_parser(parser):
    """Setup argument parser for tag create command"""
    parser.add_argument('vm',
                        help='VM name or ID to add tag to')
    parser.add_argument('tag',
                        help='Tag to add to the VM')


def setup_delete_parser(parser):
    """Setup argument parser for tag delete command"""
    parser.add_argument('vm',
                        help='VM name or ID to remove tag from')
    parser.add_argument('tag',
                        help='Tag to remove from the VM')


def get_vm_tags(proxmox, node: str, vmid: int) -> list:
    """
    Get current tags from a VM
    
    Args:
        proxmox: ProxmoxAPI instance
        node: Node name
        vmid: VM ID
    
    Returns:
        List of tag strings (empty list if no tags)
    """
    try:
        vm_config = proxmox.nodes(node).qemu(vmid).config.get()
        tags_str = vm_config.get('tags', '')
        if tags_str:
            # Tags are stored as comma-separated string
            return [tag.strip() for tag in tags_str.split(',') if tag.strip()]
        return []
    except Exception as e:
        logger.error(f"Failed to get tags from VM {vmid}: {e}")
        return []


def set_vm_tags(proxmox, node: str, vmid: int, tags: list, max_retries: int = 3) -> bool:
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
    tags_str = ','.join(tags) if tags else ''
    
    for attempt in range(1, max_retries + 1):
        try:
            # Proxmox API expects tags as comma-separated string
            proxmox.nodes(node).qemu(vmid).config.post(tags=tags_str)
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
                return False
    
    return False


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


def handle_create(args):
    """Handle tag create command"""
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
    
    vmid = vm['vmid']
    node = vm['node']
    name = vm['name']
    
    # Get current tags
    current_tags = get_vm_tags(proxmox, node, vmid)
    
    # Check if tag already exists
    if args.tag in current_tags:
        logger.info(f"Tag '{args.tag}' already exists on VM {vmid} ({name})")
        logger.info(f"Current tags: {', '.join(current_tags) if current_tags else '(none)'}")
        return
    
    # Add the new tag
    new_tags = current_tags + [args.tag]
    
    # Set updated tags
    logger.info(f"→ Adding tag '{args.tag}' to VM {vmid} ({name})...")
    if set_vm_tags(proxmox, node, vmid, new_tags):
        logger.info(f"✓ Tag '{args.tag}' added successfully")
        logger.info(f"Current tags: {', '.join(new_tags)}")
    else:
        logger.error(f"Failed to add tag '{args.tag}' to VM {vmid}")
        sys.exit(1)


def handle_delete(args):
    """Handle tag delete command"""
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
    
    vmid = vm['vmid']
    node = vm['node']
    name = vm['name']
    
    # Get current tags
    current_tags = get_vm_tags(proxmox, node, vmid)
    
    # Check if tag exists
    if args.tag not in current_tags:
        logger.info(f"Tag '{args.tag}' does not exist on VM {vmid} ({name})")
        logger.info(f"Current tags: {', '.join(current_tags) if current_tags else '(none)'}")
        return
    
    # Remove the tag
    new_tags = [tag for tag in current_tags if tag != args.tag]
    
    # Set updated tags
    logger.info(f"→ Removing tag '{args.tag}' from VM {vmid} ({name})...")
    if set_vm_tags(proxmox, node, vmid, new_tags):
        logger.info(f"✓ Tag '{args.tag}' removed successfully")
        if new_tags:
            logger.info(f"Current tags: {', '.join(new_tags)}")
        else:
            logger.info("Current tags: (none)")
    else:
        logger.error(f"Failed to remove tag '{args.tag}' from VM {vmid}")
        sys.exit(1)
