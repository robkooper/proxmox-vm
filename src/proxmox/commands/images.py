"""Image management commands"""

import argparse
import sys
import time

from proxmox.proxmox_utils import (
    ProxmoxConfig,
    connect_proxmox,
    IMAGES,
    logger,
    ProxmoxConnectionError
)


def check_image_exists(proxmox, node: str, storage: str, filename: str) -> bool:
    """
    Check if an image already exists in Proxmox storage
    
    Args:
        proxmox: ProxmoxAPI instance
        node: Node name
        storage: Storage name
        filename: Image filename to check
    
    Returns:
        True if image exists, False otherwise
    """
    try:
        storage_contents = proxmox.nodes(node).storage(storage).content.get()
        for item in storage_contents:
            volid = item.get('volid', '')
            # Check if filename matches (could be in different formats)
            if filename in volid or volid.endswith(f'/{filename}') or volid.endswith(filename):
                return True
        return False
    except Exception as e:
        logger.error(f"Error checking for existing image: {e}")
        return False


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
    logger.info(f"→ Downloading image directly to Proxmox storage {storage}...")
    logger.info(f"→ URL: {image_url}")
    
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
                    logger.info(f"→ Storage '{storage}' content types: {content_types}")
                    logger.info("→ Note: 'iso' content type should be enabled for disk images")
        except Exception as e:
            logger.info(f"→ Could not verify storage configuration: {e}")
            # Continue anyway - download might still work
        
        # Check if file already exists and delete it (for update/delete operations)
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
                logger.info(f"→ File already exists in storage: {matching_volid}")
                logger.info("→ Deleting existing file...")
                try:
                    # Delete the existing file
                    proxmox.nodes(node).storage(storage).content(matching_volid).delete()
                    logger.info("✓ Existing file deleted")
                    # Wait a moment for deletion to complete
                    time.sleep(2)
                except Exception as del_err:
                    logger.error(f"Failed to delete existing file: {del_err}")
                    logger.info("→ You may need to delete it manually via Proxmox UI or:")
                    logger.info(f"→   Delete via API or run: rm /mnt/pve/{storage}/template/iso/{filename}")
                    logger.info("→ Trying to download anyway (will likely fail if file still exists)...")
        except Exception as e:
            # If we can't check/list storage, continue anyway
            logger.info(f"→ Could not check for existing files: {e}")
            logger.info("→ Proceeding with download (may fail if file exists)...")
        
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
        
        logger.info(f"✓ Download task started: {upid_str}")
        logger.info("→ Waiting for download to complete...")
        
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
                        logger.info(f"→ Download in progress... (status: {current_status})")
                    last_status = current_status
                
                if current_status == 'stopped':
                    exitstatus = task_status.get('exitstatus', '')
                    if exitstatus == 'OK':
                        logger.info(f"✓ Download completed: {filename}")
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


def delete_image_from_proxmox(proxmox, node: str, storage: str, filename: str) -> bool:
    """
    Delete an image from Proxmox storage
    
    Args:
        proxmox: ProxmoxAPI instance
        node: Node name
        storage: Storage name
        filename: Image filename to delete
    
    Returns:
        True if deleted successfully, False otherwise
    """
    try:
        storage_contents = proxmox.nodes(node).storage(storage).content.get()
        matching_volid = None
        
        for item in storage_contents:
            volid = item.get('volid', '')
            # Check if filename matches (could be in different formats)
            if filename in volid or volid.endswith(f'/{filename}') or volid.endswith(filename):
                matching_volid = volid
                break
        
        if not matching_volid:
            logger.info(f"→ Image '{filename}' not found in storage")
            return False
        
        logger.info(f"→ Deleting image: {matching_volid}")
        proxmox.nodes(node).storage(storage).content(matching_volid).delete()
        logger.info(f"✓ Image deleted: {filename}")
        return True
        
    except Exception as e:
        logger.error(f"Failed to delete image: {e}")
        return False


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


def get_node(proxmox, node_arg: str = None) -> str:
    """
    Get node name, either from argument or auto-select first online node
    
    Args:
        proxmox: ProxmoxAPI instance
        node_arg: Optional node name from argument
    
    Returns:
        Node name
    """
    if node_arg:
        return node_arg
    
    nodes = proxmox.nodes.get()
    if not nodes:
        raise Exception("No nodes found")
    
    # Use first online node
    for n in nodes:
        if n['status'] == 'online':
            return n['node']
    
    raise Exception("No online nodes found")


def get_image_list(image_arg: str) -> list:
    """
    Get list of images to process based on argument
    
    Args:
        image_arg: Image name or "all" for all images
    
    Returns:
        List of image names (OS keys from IMAGES)
    """
    if image_arg.lower() == 'all':
        return list(IMAGES.keys())
    
    if image_arg not in IMAGES:
        valid_images = ', '.join(sorted(IMAGES.keys()))
        raise ValueError(f"Invalid image name: {image_arg}. Valid options: {valid_images}, or 'all'")
    
    return [image_arg]


def setup_create_parser(parser):
    """Setup argument parser for images create command"""
    parser.add_argument('image',
                        help='Image name to create (or "all" for all images). Valid options: ' + ', '.join(sorted(IMAGES.keys())) + ', all')
    parser.add_argument('--node',
                        help='Specific node to use (default: auto-select first online node)')


def setup_delete_parser(parser):
    """Setup argument parser for images delete command"""
    parser.add_argument('image',
                        help='Image name to delete (or "all" for all images). Valid options: ' + ', '.join(sorted(IMAGES.keys())) + ', all')
    parser.add_argument('--node',
                        help='Specific node to use (default: auto-select first online node)')


def setup_update_parser(parser):
    """Setup argument parser for images update command"""
    parser.add_argument('image',
                        help='Image name to update (or "all" for all images). Valid options: ' + ', '.join(sorted(IMAGES.keys())) + ', all')
    parser.add_argument('--node',
                        help='Specific node to use (default: auto-select first online node)')


def handle_create(args):
    """Handle images create command"""
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
    
    # Get list of images to process
    try:
        image_list = get_image_list(args.image)
    except ValueError as e:
        logger.error(str(e))
        sys.exit(1)
    
    # Get node
    try:
        node = get_node(proxmox, args.node)
    except Exception as e:
        logger.error(str(e))
        sys.exit(1)
    
    storage = config.get_storage()
    
    # Process each image
    created_count = 0
    skipped_count = 0
    
    for os_name in image_list:
        print(f"\n{'=' * 80}")
        print(f"Processing: {IMAGES[os_name]['name']}")
        print('=' * 80)
        
        image_url = IMAGES[os_name]['url']
        filename = IMAGES[os_name]['filename']
        
        # Check if image already exists
        if check_image_exists(proxmox, node, storage, filename):
            logger.info(f"→ Image '{filename}' already exists in storage, skipping creation")
            skipped_count += 1
            continue
        
        try:
            downloaded_filename = download_image_to_proxmox(
                proxmox, node, storage, image_url, filename
            )
            logger.info(f"✓ Image '{downloaded_filename}' created in storage '{storage}'")
            created_count += 1
        except Exception as e:
            logger.error(f"Failed to create {os_name}: {e}")
            continue
    
    print(f"\n{'=' * 80}")
    logger.info(f"✓ Operations completed: {created_count} created, {skipped_count} skipped")
    print('=' * 80)


def handle_delete(args):
    """Handle images delete command"""
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
    
    # Get list of images to process
    try:
        image_list = get_image_list(args.image)
    except ValueError as e:
        logger.error(str(e))
        sys.exit(1)
    
    # Get node
    try:
        node = get_node(proxmox, args.node)
    except Exception as e:
        logger.error(str(e))
        sys.exit(1)
    
    storage = config.get_storage()
    
    # Process each image
    deleted_count = 0
    not_found_count = 0
    
    for os_name in image_list:
        print(f"\n{'=' * 80}")
        print(f"Processing: {IMAGES[os_name]['name']}")
        print('=' * 80)
        
        filename = IMAGES[os_name]['filename']
        
        if delete_image_from_proxmox(proxmox, node, storage, filename):
            deleted_count += 1
        else:
            not_found_count += 1
    
    print(f"\n{'=' * 80}")
    logger.info(f"✓ Operations completed: {deleted_count} deleted, {not_found_count} not found")
    print('=' * 80)


def handle_update(args):
    """Handle images update command"""
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
    
    # Get list of images to process
    try:
        image_list = get_image_list(args.image)
    except ValueError as e:
        logger.error(str(e))
        sys.exit(1)
    
    # Get node
    try:
        node = get_node(proxmox, args.node)
    except Exception as e:
        logger.error(str(e))
        sys.exit(1)
    
    storage = config.get_storage()
    
    # Process each image (update = delete + create)
    updated_count = 0
    failed_count = 0
    
    for os_name in image_list:
        print(f"\n{'=' * 80}")
        print(f"Processing: {IMAGES[os_name]['name']}")
        print('=' * 80)
        
        image_url = IMAGES[os_name]['url']
        filename = IMAGES[os_name]['filename']
        
        # Delete existing image if it exists
        if check_image_exists(proxmox, node, storage, filename):
            logger.info(f"→ Deleting existing image '{filename}'...")
            if not delete_image_from_proxmox(proxmox, node, storage, filename):
                logger.error(f"Failed to delete existing image, skipping update")
                failed_count += 1
                continue
            # Wait a moment for deletion to complete
            time.sleep(2)
        
        # Download new image
        try:
            downloaded_filename = download_image_to_proxmox(
                proxmox, node, storage, image_url, filename
            )
            logger.info(f"✓ Image '{downloaded_filename}' updated in storage '{storage}'")
            updated_count += 1
        except Exception as e:
            logger.error(f"Failed to update {os_name}: {e}")
            failed_count += 1
            continue
    
    print(f"\n{'=' * 80}")
    logger.info(f"✓ Operations completed: {updated_count} updated, {failed_count} failed")
    print('=' * 80)
