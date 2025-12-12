#!/usr/bin/env python3
"""
Proxmox Ubuntu Image Management

Download and update Ubuntu cloud images in Proxmox storage.
Supports Ubuntu 22.04 (Jammy) and 24.04 (Noble) LTS releases.
"""

import argparse
import sys
import time
from proxmox_utils import (
    ProxmoxConfig,
    connect_proxmox,
    logger,
    IMAGES,
    ProxmoxError,
    ProxmoxConnectionError
)


def download_image_to_proxmox(
    proxmox,
    node: str,
    storage: str,
    image_url: str,
    filename: str
) -> str:
    """
    Download image directly to Proxmox storage via API
    
    Args:
        proxmox: ProxmoxAPI instance
        node: Target node
        storage: Storage name
        image_url: URL to download image from
        filename: Filename to save as in storage
    
    Returns:
        Filename in storage
    """
    logger.info(f"→ f"Downloading image directly to Proxmox storage {storage}...")
    logger.info(f"→ f"URL: {image_url}")
    
    try:
        # Verify storage supports ISO uploads first
        try:
            storage_info_raw = proxmox.nodes(node).storage(storage).get()
            # Handle both list and dict responses
            if isinstance(storage_info_raw, list):
                if len(storage_info_raw) > 0:
                    storage_info = storage_info_raw[0]
                else:
                    storage_info = {}
            else:
                storage_info = storage_info_raw
            
            if isinstance(storage_info, dict):
                content_types = storage_info.get('content', '')
                if isinstance(content_types, str):
                    content_types = content_types.split(',')
                
                # Check if storage supports ISO uploads
                all_types = ','.join(content_types) if isinstance(content_types, list) else content_types
                if 'iso' not in all_types:
                    logger.info(f"→ f"Storage '{storage}' content types: {content_types}")
                    logger.info(f"→ "Note: 'iso' content type should be enabled for disk images")
        except Exception as e:
            logger.info(f"→ f"Could not verify storage configuration: {e}")
            # Continue anyway - download might still work
        
        # Check if file already exists and delete it
        try:
            storage_contents = proxmox.nodes(node).storage(storage).content.get()
            # Look for the file in storage contents
            matching_volid = None
            for item in storage_contents:
                volid = item.get('volid', '')
                # Check if filename matches (could be in different formats)
                if filename in volid or volid.endswith(f'/{filename}') or volid.endswith(filename):
                    matching_volid = volid
                    break
            
            if matching_volid:
                logger.info(f"→ f"File already exists in storage: {matching_volid}")
                logger.info(f"→ "Deleting existing file...")
                try:
                    # Delete the existing file
                    proxmox.nodes(node).storage(storage).content(matching_volid).delete()
                    logger.info(f"✓ "Existing file deleted")
                    # Wait a moment for deletion to complete
                    time.sleep(2)
                except Exception as del_err:
                    logger.error(f"Failed to delete existing file: {del_err}")
                    logger.info(f"→ "You may need to delete it manually via Proxmox UI or:")
                    logger.info(f"→ f"  Delete via API or run: rm /mnt/pve/{storage}/template/iso/{filename}")
                    logger.info(f"→ "Trying to download anyway (will likely fail if file still exists)...")
        except Exception as e:
            # If we can't check/list storage, continue anyway
            logger.info(f"→ f"Could not check for existing files: {e}")
            logger.info(f"→ "Proceeding with download (may fail if file exists)...")
        
        # Use proxmoxer's download-url endpoint
        # Download to "import" content type so we can use import-from parameter
        # The import-from parameter requires source to be in 'images' or 'import' content type
        # Filename already has .qcow2 extension
        result = proxmox.nodes(node).storage(storage)("download-url").post(
            url=image_url,
            content="import",
            filename=filename
        )
        
        # Result contains UPID (unique process ID) for the task
        # Handle different response formats
        if isinstance(result, dict):
            if 'data' in result:
                upid = result['data']
            else:
                # Try to find UPID in the dict
                upid = result.get('upid') or result.get('UPID') or str(result)
        else:
            upid = result
        
        # Extract just the UPID string if it's in a different format
        if isinstance(upid, str) and ':' in upid:
            # UPID format: UPID:node:pid:timestamp:taskid:taskname:user
            upid_str = upid
        elif isinstance(upid, dict):
            upid_str = upid.get('upid', str(upid))
        else:
            upid_str = str(upid)
        
        logger.info(f"✓ f"Download task started: {upid_str}")
        logger.info(f"→ "Waiting for download to complete...")
        
        # Wait for task to complete (with timeout)
        max_wait = 3600  # 1 hour timeout
        elapsed = 0
        last_status = None
        
        while elapsed < max_wait:
            try:
                task_status = proxmox.nodes(node).tasks(upid_str).status.get()
                current_status = task_status.get('status', 'unknown')
                
                # Only print status if it changed
                if current_status != last_status:
                    if current_status == 'running':
                        logger.info(f"→ f"Download in progress... (status: {current_status})")
                    last_status = current_status
                
                if current_status == 'stopped':
                    exitstatus = task_status.get('exitstatus', '')
                    if exitstatus == 'OK':
                        logger.info(f"✓ f"Download completed: {filename}")
                        return filename
                    else:
                        # Get detailed error information
                        error_msg = task_status.get('errormsg', '')
                        if not error_msg:
                            error_msg = f"Exit status: {exitstatus}"
                        
                        # Try to get log output for more details
                        try:
                            log_data = proxmox.nodes(node).tasks(upid_str).log.get()
                            if log_data and 'data' in log_data:
                                log_lines = [line.get('t', '') for line in log_data['data']]
                                if log_lines:
                                    error_msg += f"\nLog output: {' '.join(log_lines[-5:])}"  # Last 5 lines
                        except Exception as log_err:
                            # Failed to get logs, continue without them
                            pass
                        
                        logger.error(f"Download failed: {error_msg}")
                        raise Exception(f"Download task failed: {error_msg}")
                
                time.sleep(5)  # Check every 5 seconds
                elapsed += 5
                
            except Exception as e:
                error_str = str(e)
                # If it's our own exception (download failed), re-raise it
                if "Download task failed" in error_str:
                    raise
                
                # For other exceptions (like task not found), wait and retry
                if "not found" in error_str.lower() or "does not exist" in error_str.lower():
                    if elapsed < 30:  # First 30 seconds, task might not be visible yet
                        time.sleep(2)
                        elapsed += 2
                        continue
                
                # Unknown error, but wait a bit and retry once more
                if elapsed < 60:
                    time.sleep(5)
                    elapsed += 5
                    continue
                
                # Too many errors or timeout
                logger.error(f"Failed to check task status: {e}")
                raise Exception(f"Could not verify download task status: {e}")
        
        # Timeout
        raise Exception(f"Download timed out after {max_wait} seconds. Check task {upid_str} in Proxmox UI.")
        
    except Exception as e:
        logger.error(f"Failed to download image: {e}")
        raise


def list_images(proxmox, config: ProxmoxConfig):
    """List available cloud images in Proxmox storage"""
    print("\nCloud Images in Storage:")
    print("-" * 80)
    
    storage = config.get_storage()
    seen_volids = set()  # Track seen images to avoid duplicates on shared storage
    images_found = False
    
    # Check storage on first available node (shared storage appears on all nodes)
    for node in proxmox.nodes.get():
        node_name = node['node']
        try:
            storage_contents = proxmox.nodes(node_name).storage(storage).content.get()
            
            for item in storage_contents:
                volid = item.get('volid', '')
                
                # Skip if we've already seen this volid (shared storage duplicate)
                if volid in seen_volids:
                    continue
                
                # Look for cloud image files
                for os_name, img_info in IMAGES.items():
                    if img_info['filename'] in volid:
                        seen_volids.add(volid)
                        images_found = True
                        size_mb = item.get('size', 0) / (1024 * 1024) if item.get('size') else 0
                        print(f"  {img_info['name']:30s}  |  {volid:50s}  |  {size_mb:.0f} MB")
                        break
            break  # Only check first node since storage is shared
        except Exception as e:
            logger.error(f"Error querying storage on node {node_name}: {e}")
            continue
    
    if not images_found:
        print("  No cloud images found in storage")
    
    print("-" * 80)


def main():
    parser = argparse.ArgumentParser(
        description='Download and update Ubuntu cloud images in Proxmox storage',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  # Download/update images for all Ubuntu versions (default action)
  %(prog)s
  
  # Download/update Ubuntu 24.04 image only
  %(prog)s --os ubuntu24
  
  # List available images in storage
  %(prog)s --list
        '''
    )
    
    parser.add_argument('--config', default='proxmox.ini',
                        help='Path to configuration file (default: proxmox.ini)')
    parser.add_argument('--list', action='store_true',
                        help='List available images in storage (default: download/update images)')
    parser.add_argument('--os', choices=list(IMAGES.keys()),
                        help='Specific OS to download/update (default: all)')
    parser.add_argument('--node',
                        help='Specific node to use (default: auto-select first online node)')
    
    args = parser.parse_args()
    
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
    logger.info(f"✓ "Connected to Proxmox")
    
    # List images if requested
    if args.list:
        list_images(proxmox, config)
        return
    
    # Default action: Download/update images
    # If no OS specified, download all available images
    os_list = [args.os] if args.os else list(IMAGES.keys())
    storage = config.get_storage()
    
    # Select node
    if not args.node:
        nodes = proxmox.nodes.get()
        if not nodes:
            logger.error("No nodes found")
            sys.exit(1)
        # Use first online node
        for n in nodes:
            if n['status'] == 'online':
                args.node = n['node']
                break
        if not args.node:
            logger.error("No online nodes found")
            sys.exit(1)
    
    for os_name in os_list:
        print(f"\n{'=' * 80}")
        print(f"Processing: {IMAGES[os_name]['name']}")
        print('=' * 80)
        
        image_url = IMAGES[os_name]['url']
        filename = IMAGES[os_name]['filename']
        
        try:
            downloaded_filename = download_image_to_proxmox(
                proxmox, args.node, storage, image_url, filename
            )
            logger.info(f"✓ f"Image '{downloaded_filename}' ready in storage '{storage}'")
        except Exception as e:
            logger.error(f"Failed to download {os_name}: {e}")
            continue
    
    print(f"\n{'=' * 80}")
    logger.info(f"✓ "All operations completed")
    print('=' * 80)


if __name__ == '__main__':
    main()
