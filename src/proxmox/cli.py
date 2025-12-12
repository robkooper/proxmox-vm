#!/usr/bin/env python3
"""
Proxmox CLI Entry Point

Main CLI application that provides commands for VM, DNS, and firewall management.
"""

import argparse
import sys

from proxmox.commands import vm, dns, firewall, images as image, tag


def main():
    """Main CLI entry point"""
    parser = argparse.ArgumentParser(
        description='Proxmox VM Management CLI',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  # VM operations
  proxmox vm create webserver -o ubuntu24 -u admin -k ~/.ssh/id_rsa.pub
  proxmox vm delete webserver
  proxmox vm delete 100  # Using VM ID
  proxmox vm start webserver
  proxmox vm stop webserver
  proxmox vm start 100  # Using VM ID
  proxmox vm list  # List all VMs
  
  # DNS operations
  proxmox dns create myserver 192.168.1.100
  proxmox dns delete myserver  # By hostname
  proxmox dns delete 192.168.1.100  # By IP address
  proxmox dns list  # List all DNS entries in NetBox for subnet
  
  # Firewall operations
  proxmox firewall create webserver 8080
  proxmox firewall create webserver  # ICMP (no port)
  proxmox firewall delete webserver 8080
  proxmox firewall delete 100 80  # Using VM ID
  proxmox firewall list webserver  # List all firewall rules for VM
  
  # Image operations
  proxmox image create ubuntu24
  proxmox image create all
  proxmox image delete ubuntu22
  proxmox image update ubuntu24
  proxmox image list  # List all images
  
  # Tag operations
  proxmox tag create webserver production
  proxmox tag create 100 web  # Using VM ID
  proxmox tag delete webserver production
  proxmox tag delete 100 web  # Using VM ID
  proxmox tag list webserver  # List all tags for VM
        '''
    )
    
    # Create subparsers for commands
    subparsers = parser.add_subparsers(dest='command', help='Command to execute', required=True)
    
    # VM command
    vm_parser = subparsers.add_parser('vm', help='VM management commands')
    vm_subparsers = vm_parser.add_subparsers(dest='action', help='VM action', required=True)
    
    # VM create
    vm_create = vm_subparsers.add_parser('create', help='Create a new VM')
    vm_create.add_argument('--config', default=None,
                           help='Path to configuration file (default: searches ./proxmox.ini, ~/.config/proxmox/proxmox.ini, ~/.proxmox.ini)')
    vm.setup_create_parser(vm_create)
    
    # VM delete
    vm_delete = vm_subparsers.add_parser('delete', help='Delete a VM')
    vm_delete.add_argument('--config', default=None,
                           help='Path to configuration file (default: searches ./proxmox.ini, ~/.config/proxmox/proxmox.ini, ~/.proxmox.ini)')
    vm.setup_delete_parser(vm_delete)
    
    # VM start
    vm_start = vm_subparsers.add_parser('start', help='Start a VM')
    vm_start.add_argument('--config', default=None,
                          help='Path to configuration file (default: searches ./proxmox.ini, ~/.config/proxmox/proxmox.ini, ~/.proxmox.ini)')
    vm.setup_start_parser(vm_start)
    
    # VM stop
    vm_stop = vm_subparsers.add_parser('stop', help='Stop a VM')
    vm_stop.add_argument('--config', default=None,
                         help='Path to configuration file (default: searches ./proxmox.ini, ~/.config/proxmox/proxmox.ini, ~/.proxmox.ini)')
    vm.setup_stop_parser(vm_stop)
    
    # VM list
    vm_list = vm_subparsers.add_parser('list', help='List all VMs')
    vm_list.add_argument('--config', default=None,
                         help='Path to configuration file (default: searches ./proxmox.ini, ~/.config/proxmox/proxmox.ini, ~/.proxmox.ini)')
    vm.setup_list_parser(vm_list)
    
    # DNS command
    dns_parser = subparsers.add_parser('dns', help='DNS management commands')
    dns_subparsers = dns_parser.add_subparsers(dest='action', help='DNS action', required=True)
    
    # DNS create
    dns_create = dns_subparsers.add_parser('create', help='Create a DNS record')
    dns_create.add_argument('--config', default=None,
                            help='Path to configuration file (default: searches ./proxmox.ini, ~/.config/proxmox/proxmox.ini, ~/.proxmox.ini)')
    dns.setup_create_parser(dns_create)
    
    # DNS delete
    dns_delete = dns_subparsers.add_parser('delete', help='Delete a DNS record')
    dns_delete.add_argument('--config', default=None,
                            help='Path to configuration file (default: searches ./proxmox.ini, ~/.config/proxmox/proxmox.ini, ~/.proxmox.ini)')
    dns.setup_delete_parser(dns_delete)
    
    # DNS list
    dns_list = dns_subparsers.add_parser('list', help='List all DNS entries in NetBox for subnet')
    dns_list.add_argument('--config', default=None,
                          help='Path to configuration file (default: searches ./proxmox.ini, ~/.config/proxmox/proxmox.ini, ~/.proxmox.ini)')
    dns.setup_list_parser(dns_list)
    
    # Firewall command
    firewall_parser = subparsers.add_parser('firewall', help='Firewall management commands')
    firewall_subparsers = firewall_parser.add_subparsers(dest='action', help='Firewall action', required=True)
    
    # Firewall create
    firewall_create = firewall_subparsers.add_parser('create', help='Create a firewall rule')
    firewall_create.add_argument('--config', default=None,
                                 help='Path to configuration file (default: searches ./proxmox.ini, ~/.config/proxmox/proxmox.ini, ~/.proxmox.ini)')
    firewall.setup_create_parser(firewall_create)
    
    # Firewall delete
    firewall_delete = firewall_subparsers.add_parser('delete', help='Delete a firewall rule')
    firewall_delete.add_argument('--config', default=None,
                                 help='Path to configuration file (default: searches ./proxmox.ini, ~/.config/proxmox/proxmox.ini, ~/.proxmox.ini)')
    firewall.setup_delete_parser(firewall_delete)
    
    # Firewall list
    firewall_list = firewall_subparsers.add_parser('list', help='List all firewall rules for a VM')
    firewall_list.add_argument('--config', default=None,
                               help='Path to configuration file (default: searches ./proxmox.ini, ~/.config/proxmox/proxmox.ini, ~/.proxmox.ini)')
    firewall.setup_list_parser(firewall_list)
    
    # Image command
    image_parser = subparsers.add_parser('image', help='Image management commands')
    image_subparsers = image_parser.add_subparsers(dest='action', help='Image action', required=True)
    
    # Image create
    image_create = image_subparsers.add_parser('create', help='Create/download an image')
    image_create.add_argument('--config', default=None,
                              help='Path to configuration file (default: searches ./proxmox.ini, ~/.config/proxmox/proxmox.ini, ~/.proxmox.ini)')
    image.setup_create_parser(image_create)
    
    # Image delete
    image_delete = image_subparsers.add_parser('delete', help='Delete an image')
    image_delete.add_argument('--config', default=None,
                               help='Path to configuration file (default: searches ./proxmox.ini, ~/.config/proxmox/proxmox.ini, ~/.proxmox.ini)')
    image.setup_delete_parser(image_delete)
    
    # Image update
    image_update = image_subparsers.add_parser('update', help='Update an image (delete and re-download)')
    image_update.add_argument('--config', default=None,
                              help='Path to configuration file (default: searches ./proxmox.ini, ~/.config/proxmox/proxmox.ini, ~/.proxmox.ini)')
    image.setup_update_parser(image_update)
    
    # Image list
    image_list = image_subparsers.add_parser('list', help='List all images')
    image_list.add_argument('--config', default=None,
                            help='Path to configuration file (default: searches ./proxmox.ini, ~/.config/proxmox/proxmox.ini, ~/.proxmox.ini)')
    image.setup_list_parser(image_list)
    
    # Tag command
    tag_parser = subparsers.add_parser('tag', help='Tag management commands')
    tag_subparsers = tag_parser.add_subparsers(dest='action', help='Tag action', required=True)
    
    # Tag create
    tag_create = tag_subparsers.add_parser('create', help='Add a tag to a VM')
    tag_create.add_argument('--config', default=None,
                            help='Path to configuration file (default: searches ./proxmox.ini, ~/.config/proxmox/proxmox.ini, ~/.proxmox.ini)')
    tag.setup_create_parser(tag_create)
    
    # Tag delete
    tag_delete = tag_subparsers.add_parser('delete', help='Remove a tag from a VM')
    tag_delete.add_argument('--config', default=None,
                            help='Path to configuration file (default: searches ./proxmox.ini, ~/.config/proxmox/proxmox.ini, ~/.proxmox.ini)')
    tag.setup_delete_parser(tag_delete)
    
    # Tag list
    tag_list = tag_subparsers.add_parser('list', help='List all tags for a VM')
    tag_list.add_argument('--config', default=None,
                          help='Path to configuration file (default: searches ./proxmox.ini, ~/.config/proxmox/proxmox.ini, ~/.proxmox.ini)')
    tag.setup_list_parser(tag_list)
    
    args = parser.parse_args()
    
    # Execute the appropriate command
    try:
        if args.command == 'vm':
            if args.action == 'create':
                vm.handle_create(args)
            elif args.action == 'delete':
                vm.handle_delete(args)
            elif args.action == 'start':
                vm.handle_start(args)
            elif args.action == 'stop':
                vm.handle_stop(args)
            elif args.action == 'list':
                vm.handle_list(args)
        elif args.command == 'dns':
            if args.action == 'create':
                dns.handle_create(args)
            elif args.action == 'delete':
                dns.handle_delete(args)
            elif args.action == 'list':
                dns.handle_list(args)
        elif args.command == 'firewall':
            if args.action == 'create':
                firewall.handle_create(args)
            elif args.action == 'delete':
                firewall.handle_delete(args)
            elif args.action == 'list':
                firewall.handle_list(args)
        elif args.command == 'image':
            if args.action == 'create':
                image.handle_create(args)
            elif args.action == 'delete':
                image.handle_delete(args)
            elif args.action == 'update':
                image.handle_update(args)
            elif args.action == 'list':
                image.handle_list(args)
        elif args.command == 'tag':
            if args.action == 'create':
                tag.handle_create(args)
            elif args.action == 'delete':
                tag.handle_delete(args)
            elif args.action == 'list':
                tag.handle_list(args)
    except KeyboardInterrupt:
        print("\n\nOperation cancelled by user")
        sys.exit(1)
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == '__main__':
    main()
