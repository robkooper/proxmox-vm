#!/usr/bin/env python3
"""
Proxmox VM Management Utilities

Common functions for Proxmox API interaction, cloud-init generation,
and node selection.
"""

import base64
import configparser
import ipaddress
import logging
import os
import secrets
import socket
import sys
from pathlib import Path
from typing import Dict, List, Optional, Tuple
import yaml
from proxmoxer import ProxmoxAPI

# Configure logging
# Use a logger named after the module
logger = logging.getLogger(__name__)

# Set up default logging configuration if not already configured
if not logger.handlers:
    # Handler for INFO/WARNING (stdout) - filters out ERROR and above
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(logging.INFO)
    console_handler.addFilter(lambda record: record.levelno < logging.ERROR)
    console_formatter = logging.Formatter('%(message)s')
    console_handler.setFormatter(console_formatter)
    
    # Handler for ERROR/CRITICAL (stderr)
    error_handler = logging.StreamHandler(sys.stderr)
    error_handler.setLevel(logging.ERROR)
    error_formatter = logging.Formatter('Error: %(message)s')
    error_handler.setFormatter(error_formatter)
    
    logger.addHandler(console_handler)
    logger.addHandler(error_handler)
    logger.setLevel(logging.INFO)


# Custom exceptions for better error handling

class ProxmoxError(Exception):
    """Base exception for Proxmox-related errors"""
    pass


class ProxmoxConnectionError(ProxmoxError):
    """Raised when connection to Proxmox fails"""
    pass


class ProxmoxNodeError(ProxmoxError):
    """Raised when node selection or node-related operations fail"""
    pass


class ProxmoxVMIDError(ProxmoxError):
    """Raised when VM ID operations fail"""
    pass




# Cloud image URLs and filenames
IMAGES = {
    'ubuntu22': {
        'name': 'Ubuntu 22.04 LTS (Jammy)',
        'url': 'https://cloud-images.ubuntu.com/jammy/current/jammy-server-cloudimg-amd64.img',
        'filename': 'jammy-server-cloudimg-amd64.qcow2'  # Use .qcow2 for import storage
    },
    'ubuntu24': {
        'name': 'Ubuntu 24.04 LTS (Noble)',
        'url': 'https://cloud-images.ubuntu.com/noble/current/noble-server-cloudimg-amd64.img',
        'filename': 'noble-server-cloudimg-amd64.qcow2'  # Use .qcow2 for import storage
    },
    'rocky8': {
        'name': 'Rocky Linux 8',
        'url': 'https://download.rockylinux.org/pub/rocky/8.10/images/x86_64/Rocky-8-GenericCloud.latest.x86_64.qcow2',
        'filename': 'Rocky-8-GenericCloud.latest.x86_64.qcow2'
    },
    'rocky9': {
        'name': 'Rocky Linux 9',
        'url': 'https://download.rockylinux.org/pub/rocky/9.7/images/x86_64/Rocky-9-GenericCloud.latest.x86_64.qcow2',
        'filename': 'Rocky-9-GenericCloud.latest.x86_64.qcow2'
    },
    'rocky10': {
        'name': 'Rocky Linux 10',
        'url': 'https://download.rockylinux.org/pub/rocky/10/images/x86_64/Rocky-10-GenericCloud-Base.latest.x86_64.qcow2',
        'filename': 'Rocky-10-GenericCloud-Base.latest.x86_64.qcow2'
    }
}


def find_config_file(config_file: Optional[str] = None) -> str:
    """
    Find configuration file in standard locations.
    
    Search order:
    1. Explicit path (if provided)
    2. Current directory: ./proxmox.ini
    3. XDG config directory: ~/.config/proxmox/proxmox.ini
    4. Home directory: ~/.proxmox.ini
    
    Args:
        config_file: Explicit path to config file, or None to search
        
    Returns:
        Path to found config file
        
    Raises:
        FileNotFoundError: If config file not found in any location
    """
    # If explicit path provided, use it directly
    if config_file:
        if os.path.isfile(config_file):
            return config_file
        raise FileNotFoundError(f"Configuration file '{config_file}' not found")
    
    # Search in order of preference
    search_paths = [
        # Current directory
        Path.cwd() / "proxmox.ini",
        # XDG config directory (~/.config/proxmox/proxmox.ini)
        Path.home() / ".config" / "proxmox" / "proxmox.ini",
        # Home directory (~/.proxmox.ini)
        Path.home() / ".proxmox.ini",
    ]
    
    for path in search_paths:
        if path.is_file():
            return str(path)
    
    # Not found in any location
    raise FileNotFoundError(
        f"Configuration file 'proxmox.ini' not found in any of the following locations:\n"
        f"  - {Path.cwd() / 'proxmox.ini'}\n"
        f"  - {Path.home() / '.config' / 'proxmox' / 'proxmox.ini'}\n"
        f"  - {Path.home() / '.proxmox.ini'}\n"
        f"\nCopy proxmox.ini.example to one of these locations and configure it."
    )


class ProxmoxConfig:
    """Load and parse Proxmox configuration from INI file"""
    
    def __init__(self, config_file: Optional[str] = None):
        """
        Initialize ProxmoxConfig.
        
        Args:
            config_file: Path to config file, or None to search in standard locations
        """
        self.config_file = find_config_file(config_file)
        self.config = configparser.ConfigParser()
        
        if not self.config.read(self.config_file):
            raise FileNotFoundError(f"Configuration file '{self.config_file}' not found")
        
        self._validate_config()
    
    def _validate_config(self):
        """Validate required configuration sections exist"""
        required_sections = ['proxmox', 'defaults']
        for section in required_sections:
            if not self.config.has_section(section):
                raise ValueError(f"Missing required section [{section}] in config file")
    
    def get_proxmox_host(self) -> str:
        """Get Proxmox host URL"""
        return self.config.get('proxmox', 'host')
    
    def get_proxmox_hostname(self) -> str:
        """Get Proxmox hostname (for SSH/SCP commands)"""
        host = self.get_proxmox_host()
        # Remove protocol
        if host.startswith('https://'):
            host = host[8:]
        elif host.startswith('http://'):
            host = host[7:]
        # Remove port and trailing slash
        if ':' in host:
            host = host.split(':')[0]
        if host.endswith('/'):
            host = host[:-1]
        return host
    
    def get_verify_ssl(self) -> bool:
        """Get SSL verification setting (defaults to True for security)"""
        return self.config.getboolean('proxmox', 'verify_ssl', fallback=True)
    
    def get_timeout(self) -> int:
        """Get API request timeout in seconds (default: 30)"""
        return self.config.getint('proxmox', 'timeout', fallback=30)
    
    def get_auth_method(self) -> Tuple[str, Dict]:
        """
        Determine authentication method and return credentials
        Returns: (method, credentials_dict)
        method is either 'token' or 'password'
        """
        # Try [proxmox] section first, fallback to [auth] for backward compatibility
        token_id = self.config.get('proxmox', 'token_id', fallback='').strip()
        token_secret = self.config.get('proxmox', 'token_secret', fallback='').strip()
        
        # Fallback to [auth] section if not found in [proxmox]
        if not token_id or not token_secret:
            token_id = self.config.get('auth', 'token_id', fallback='').strip()
            token_secret = self.config.get('auth', 'token_secret', fallback='').strip()
        
        if token_id and token_secret:
            # Split token_id into user@realm and token_name
            # Format: user@realm!tokenname (e.g., root@pam!vmcreator)
            if '!' in token_id:
                user, token_name = token_id.split('!', 1)
            else:
                raise ValueError("token_id must be in format: user@realm!tokenname")
            
            return ('token', {
                'user': user,
                'token_name': token_name,
                'token_value': token_secret
            })
        
        # Try [proxmox] section first, fallback to [auth] for backward compatibility
        username = self.config.get('proxmox', 'user', fallback='').strip()
        password = self.config.get('proxmox', 'password', fallback='').strip()
        
        # Fallback to [auth] section if not found in [proxmox]
        if not username or not password:
            username = self.config.get('auth', 'user', fallback='').strip()
            password = self.config.get('auth', 'password', fallback='').strip()
        
        if username and password:
            return ('password', {'user': username, 'password': password})
        
        raise ValueError("No valid authentication method found in config. "
                        "Provide either token_id/token_secret or user/password")
    
    def get_storage(self) -> str:
        """Get default storage name"""
        return self.config.get('defaults', 'storage')
    
    def get_bridge(self) -> str:
        """Get default network bridge"""
        return self.config.get('defaults', 'bridge', fallback='vmbr0')
    
    def get_vmid_range(self) -> Tuple[int, int]:
        """Get VM ID range"""
        vmid_min = self.config.getint('defaults', 'vmid_min', fallback=100)
        vmid_max = self.config.getint('defaults', 'vmid_max', fallback=999)
        return (vmid_min, vmid_max)
    
    def get_puppet_server(self) -> Optional[str]:
        """Get puppet server hostname"""
        puppet_server = self.config.get('defaults', 'puppet_server', fallback='').strip()
        return puppet_server if puppet_server else None
    
    def get_default_cores(self) -> int:
        """Get default CPU cores"""
        return self.config.getint('defaults', 'cores', fallback=2)
    
    def get_default_memory(self) -> int:
        """Get default memory in MB"""
        return self.config.getint('defaults', 'memory', fallback=2048)
    
    def get_default_disk_size(self) -> int:
        """Get default disk size in GB"""
        return self.config.getint('defaults', 'disk_size', fallback=20)
    
    def get_template_id(self, os_name: str) -> Optional[int]:
        """Get template ID for a given OS name"""
        if not self.config.has_section('images'):
            return None
        template_id = self.config.get('images', os_name, fallback='').strip()
        return int(template_id) if template_id else None
    
    def set_template_id(self, os_name: str, template_id: int):
        """Set template ID for a given OS name"""
        if not self.config.has_section('images'):
            self.config.add_section('images')
        self.config.set('images', os_name, str(template_id))
    
    def save(self):
        """Save configuration back to file"""
        with open(self.config_file, 'w') as f:
            self.config.write(f)
    
    def has_netbox_config(self) -> bool:
        """Check if NetBox configuration section exists"""
        return self.config.has_section('netbox')
    
    def get_netbox_url(self) -> Optional[str]:
        """Get NetBox API URL"""
        if not self.has_netbox_config():
            return None
        url = self.config.get('netbox', 'url', fallback='').strip()
        return url if url else None
    
    def get_netbox_token(self) -> Optional[str]:
        """Get NetBox API token"""
        if not self.has_netbox_config():
            return None
        token = self.config.get('netbox', 'token', fallback='').strip()
        return token if token else None
    
    def get_netbox_subnet(self) -> Optional[str]:
        """Get NetBox subnet/mask (e.g., '192.168.1.0/24')"""
        if not self.has_netbox_config():
            return None
        subnet = self.config.get('netbox', 'subnet', fallback='').strip()
        return subnet if subnet else None
    
    def get_network_ipaddress(self) -> str:
        """Get IP address assignment method: 'dhcp', 'netbox', or specific IP address"""
        if not self.config.has_section('network'):
            return 'dhcp'
        ipaddress = self.config.get('network', 'ipaddress', fallback='dhcp').strip().lower()
        return ipaddress if ipaddress else 'dhcp'
    
    def get_network_register(self) -> str:
        """Get DNS registration method: 'none' or 'netbox'"""
        if not self.config.has_section('network'):
            return 'none'
        register = self.config.get('network', 'register', fallback='none').strip().lower()
        return register if register else 'none'
    
    def get_network_domain(self) -> Optional[str]:
        """Get DNS domain name from network section"""
        if not self.config.has_section('network'):
            return None
        domain = self.config.get('network', 'domain', fallback='').strip()
        return domain if domain else None
    
    def get_network_dns_servers(self) -> List[str]:
        """Get DNS servers as list (space-separated in config) from network section"""
        if not self.config.has_section('network'):
            # Default: Cloudflare and Google DNS
            return ['1.1.1.1', '8.8.8.8']
        dns_servers = self.config.get('network', 'dns_servers', fallback='').strip()
        if not dns_servers:
            # Default: Cloudflare and Google DNS
            return ['1.1.1.1', '8.8.8.8']
        return [s.strip() for s in dns_servers.split() if s.strip()]
    
    def get_netbox_dns_servers(self) -> List[str]:
        """Get DNS servers as list (space-separated in config) - deprecated, use get_network_dns_servers"""
        # Try network section first, fallback to netbox for backward compatibility
        dns_servers = self.get_network_dns_servers()
        if dns_servers:
            return dns_servers
        if not self.has_netbox_config():
            # Default: Cloudflare and Google DNS
            return ['1.1.1.1', '8.8.8.8']
        dns_servers = self.config.get('netbox', 'dns_servers', fallback='').strip()
        if not dns_servers:
            # Default: Cloudflare and Google DNS
            return ['1.1.1.1', '8.8.8.8']
        return [s.strip() for s in dns_servers.split() if s.strip()]
    
    def get_netbox_domain(self) -> Optional[str]:
        """Get DNS domain name - deprecated, use get_network_domain"""
        # Try network section first, fallback to netbox for backward compatibility
        domain = self.get_network_domain()
        if domain:
            return domain
        if not self.has_netbox_config():
            return None
        domain = self.config.get('netbox', 'domain', fallback='').strip()
        return domain if domain else None
    
    def get_netbox_tenant(self) -> Optional[str]:
        """Get NetBox tenant slug"""
        if not self.has_netbox_config():
            return None
        tenant = self.config.get('netbox', 'tenant', fallback='').strip()
        return tenant if tenant else None
    


def connect_proxmox(config: ProxmoxConfig) -> ProxmoxAPI:
    """
    Connect to Proxmox API using configuration
    
    Args:
        config: ProxmoxConfig instance
    
    Returns:
        ProxmoxAPI instance
    """
    host = config.get_proxmox_host()
    # Remove protocol from host if present
    if host.startswith('https://'):
        host = host[8:]
    elif host.startswith('http://'):
        host = host[7:]
    
    # Remove port if present for ProxmoxAPI (it adds it automatically)
    if ':' in host:
        host = host.split(':')[0]
    
    verify_ssl = config.get_verify_ssl()
    
    # Print prominent security warning if SSL verification is disabled
    if not verify_ssl:
        print("=" * 80, file=sys.stderr)
        print("⚠️  SECURITY WARNING: SSL VERIFICATION IS DISABLED ⚠️", file=sys.stderr)
        print("=" * 80, file=sys.stderr)
        print("You are connecting to Proxmox without verifying SSL certificates.", file=sys.stderr)
        print("This makes you vulnerable to Man-in-the-Middle (MITM) attacks.", file=sys.stderr)
        print("", file=sys.stderr)
        print("Only disable SSL verification if:", file=sys.stderr)
        print("  - You are in a trusted lab/development environment", file=sys.stderr)
        print("  - You understand the security risks", file=sys.stderr)
        print("  - You are using self-signed certificates", file=sys.stderr)
        print("", file=sys.stderr)
        print("For production environments, use proper SSL certificates and", file=sys.stderr)
        print("set verify_ssl = true in your proxmox.ini configuration.", file=sys.stderr)
        print("=" * 80, file=sys.stderr)
        print("", file=sys.stderr)
    
    timeout = config.get_timeout()
    auth_method, credentials = config.get_auth_method()
    
    try:
        if auth_method == 'token':
            proxmox = ProxmoxAPI(
                host,
                user=credentials['user'],
                token_name=credentials['token_name'],
                token_value=credentials['token_value'],
                verify_ssl=verify_ssl,
                timeout=timeout
            )
        else:  # password
            proxmox = ProxmoxAPI(
                host,
                user=credentials['user'],
                password=credentials['password'],
                verify_ssl=verify_ssl,
                timeout=timeout
            )
        
        # Test connection
        proxmox.version.get()
        return proxmox
    
    except Exception as e:
        raise ProxmoxConnectionError(f"Error connecting to Proxmox: {e}") from e


def select_best_node(proxmox: ProxmoxAPI, required_memory: int = 0, required_cores: int = 0) -> str:
    """
    Select the best node based on available resources
    
    Algorithm: Calculate score = (available_memory / total_memory + available_cpu / total_cpu) / 2
    Select node with highest score
    
    Args:
        proxmox: ProxmoxAPI instance
        required_memory: Required memory in MB
        required_cores: Required CPU cores
    
    Returns:
        Node name
    """
    nodes = proxmox.nodes.get()
    
    if not nodes:
        raise ProxmoxNodeError("No nodes found in Proxmox cluster")
    
    best_node = None
    best_score = -1
    
    for node in nodes:
        node_name = node['node']
        node_status = proxmox.nodes(node_name).status.get()
        
        # Skip offline nodes
        if node['status'] != 'online':
            continue
        
        total_memory = node_status['memory']['total']
        used_memory = node_status['memory']['used']
        available_memory = total_memory - used_memory
        
        total_cpu = node_status['cpuinfo']['cpus']
        cpu_usage = node_status['cpu']
        available_cpu = total_cpu * (1 - cpu_usage)
        
        # Check if node has enough resources
        if available_memory < required_memory * 1024 * 1024:  # Convert MB to bytes
            continue
        if available_cpu < required_cores:
            continue
        
        # Calculate score
        memory_score = available_memory / total_memory
        cpu_score = available_cpu / total_cpu
        score = (memory_score + cpu_score) / 2
        
        if score > best_score:
            best_score = score
            best_node = node_name
    
    if not best_node:
        raise ProxmoxNodeError("No suitable node found with enough resources")
    
    return best_node


def get_next_vmid(proxmox: ProxmoxAPI, vmid_min: int, vmid_max: int) -> int:
    """
    Find the next available VM ID in the specified range
    
    Args:
        proxmox: ProxmoxAPI instance
        vmid_min: Minimum VM ID
        vmid_max: Maximum VM ID
    
    Returns:
        Next available VM ID
    """
    # Get all VMs and containers
    all_vms = []
    for node in proxmox.nodes.get():
        node_name = node['node']
        all_vms.extend(proxmox.nodes(node_name).qemu.get())
        all_vms.extend(proxmox.nodes(node_name).lxc.get())
    
    used_vmids = {vm['vmid'] for vm in all_vms}
    
    for vmid in range(vmid_min, vmid_max + 1):
        if vmid not in used_vmids:
            return vmid
    
    raise ProxmoxVMIDError(f"No available VM ID in range {vmid_min}-{vmid_max}")


def encrypt_password(plain_password: str) -> str:
    """
    Encrypt a plaintext password using SHA-512 (same format as mkpasswd)
    
    Uses passlib for cross-platform compatibility (works on macOS, Linux, Windows)
    
    Args:
        plain_password: Plaintext password to encrypt
    
    Returns:
        Encrypted password hash in format: $6$rounds=4096$salt$hash
    
    Raises:
        ImportError: If passlib is not installed
    """
    try:
        from passlib.context import CryptContext
    except ImportError:
        raise ImportError(
            "passlib is required for password encryption. "
            "Install it with: pip install 'passlib[bcrypt]'"
        )
    
    # Create a crypt context for SHA-512 with 4096 rounds (same as mkpasswd default)
    crypt_context = CryptContext(schemes=['sha512_crypt'], sha512_crypt__rounds=4096)
    # Hash the password - this produces format: $6$rounds=4096$salt$hash
    return crypt_context.hash(plain_password)


def generate_cloud_init_config(
    username: str,
    ssh_keys: Optional[List[str]] = None,
    password: Optional[str] = None,
    additional_users: Optional[List[Dict]] = None,
    puppet_server: Optional[str] = None
) -> str:
    """
    Generate cloud-init user-data configuration
    
    Args:
        username: Primary user to create
        ssh_keys: List of SSH public keys
        password: Encrypted password hash for the user (must be in format $6$...)
        additional_users: List of additional user dicts
        puppet_server: Puppet server hostname for agent configuration
    
    Returns:
        cloud-init YAML configuration as string
    """
    config = {
        'users': [],
        'package_update': True,
        'package_upgrade': True,
        'packages': ['qemu-guest-agent']  # Install QEMU guest agent for Proxmox
    }
    
    # Note: Network configuration is handled separately in network-config file
    # The network key in user-data is not used by NoCloud datasource for network setup
    
    # Primary user
    primary_user = {
        'name': username,
        'sudo': 'ALL=(ALL) NOPASSWD:ALL',
        'shell': '/bin/bash',
        'groups': ['sudo', 'adm', 'users']
    }
    
    if ssh_keys:
        primary_user['ssh_authorized_keys'] = ssh_keys
    
    if password:
        # Use encrypted password (passwd field) instead of plain_text_passwd
        # Password should already be encrypted (SHA-512 format: $6$rounds=4096$salt$hash)
        primary_user['passwd'] = password
        primary_user['lock_passwd'] = False
    else:
        primary_user['lock_passwd'] = True
    
    config['users'].append(primary_user)
    
    # Additional users
    if additional_users:
        for user in additional_users:
            config['users'].append(user)
    
    # Initialize runcmd list if needed
    if 'runcmd' not in config:
        config['runcmd'] = []
    
    # Enable and start QEMU guest agent
    config['runcmd'].extend([
        'systemctl enable qemu-guest-agent',
        'systemctl start qemu-guest-agent'
    ])
    
    # Puppet configuration using cloud-init's native puppet module
    # See: https://cloudinit.readthedocs.io/en/latest/reference/yaml_examples/puppet.html
    if puppet_server:
        config['puppet'] = {
            'install': True,
            'install_type': 'aio',  # All-In-One installer (recommended)
            'collection': 'puppet7',  # Use puppet7 collection
            'cleanup': True,  # Remove installer packages after installation
            'exec': True,  # Run puppet agent after installation
            'conf': {
                'agent': {
                    'server': puppet_server,
                    'runinterval': '1h'
                }
            }
        }
    
    return "#cloud-config\n" + yaml.dump(config, default_flow_style=False)


def get_network_interface_for_os(os_name: str) -> str:
    """
    Get the network interface name for a given OS
    
    Args:
        os_name: OS name (e.g., 'ubuntu22', 'rocky8', etc.)
    
    Returns:
        Network interface name ('ens18' for Ubuntu, 'eth0' for Rocky Linux)
    """
    if os_name.startswith('ubuntu'):
        return 'ens18'
    elif os_name.startswith('rocky'):
        return 'eth0'
    else:
        # Default to ens18 for unknown OS types (most modern Linux distros use this)
        return 'ens18'


def generate_network_config(
    ip_address: Optional[str] = None,
    gateway: Optional[str] = None,
    dns_servers: Optional[List[str]] = None,
    interface: Optional[str] = None,
    os_name: Optional[str] = None
) -> str:
    """
    Generate cloud-init network-config file for static IP configuration
    
    Args:
        ip_address: IP address with CIDR notation (e.g., '192.168.1.100/24')
        gateway: Gateway IP address (if None, will try to derive from IP subnet)
        dns_servers: List of DNS server IP addresses
        interface: Network interface name (if None, will be determined from os_name)
        os_name: OS name (e.g., 'ubuntu22', 'rocky8') - used to determine interface if interface is None
    
    Returns:
        network-config YAML as string
    """
    # Determine interface name
    if interface is None:
        if os_name:
            interface = get_network_interface_for_os(os_name)
        else:
            # Default to ens18 if neither interface nor os_name is provided
            interface = 'ens18'
    network_config = {
        'version': 2,
        'ethernets': {
            interface: {
                'dhcp4': False
            }
        }
    }
    
    # Set IP address if provided
    if ip_address:
        network_config['ethernets'][interface]['addresses'] = [ip_address]
        
        # Derive gateway if not provided (assume .1 in subnet)
        if not gateway:
            try:
                ip_net = ipaddress.ip_network(ip_address, strict=False)
                gateway = str(ip_net.network_address + 1)
            except Exception:
                pass  # Keep gateway as None if derivation fails
    
    if gateway:
        network_config['ethernets'][interface]['gateway4'] = gateway
    
    # Set DNS servers
    if dns_servers:
        network_config['ethernets'][interface]['nameservers'] = {
            'addresses': dns_servers
        }
    
    return yaml.dump(network_config, default_flow_style=False)


def validate_os_name(os_name: str) -> bool:
    """Validate OS name is supported"""
    return os_name in IMAGES




def setup_logging(level: str = 'INFO', log_file: Optional[str] = None):
    """
    Configure logging for the application
    
    Args:
        level: Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
        log_file: Optional path to log file. If None, logs to stdout
    """
    log_level = getattr(logging, level.upper(), logging.INFO)
    
    # Remove existing handlers
    logger.handlers.clear()
    
    # Create formatter
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    
    # Console handler
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(log_level)
    console_handler.setFormatter(logging.Formatter('%(message)s'))  # Simple format for console
    logger.addHandler(console_handler)
    
    # File handler if specified
    if log_file:
        file_handler = logging.FileHandler(log_file)
        file_handler.setLevel(log_level)
        file_handler.setFormatter(formatter)  # Detailed format for file
        logger.addHandler(file_handler)
    
    logger.setLevel(log_level)


# NetBox integration functions moved to netbox_utils.py


def find_vm_by_name(proxmox, name: str) -> Optional[Dict]:
    """
    Find VM by name (returns first match)
    
    Args:
        proxmox: ProxmoxAPI instance
        name: VM name to search for
    
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
                    vm_name = vm.get('name', '')
                    if vm_name == name:
                        return {
                            'vmid': vm.get('vmid'),
                            'name': vm_name,
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


def find_vm_by_id(proxmox, vmid: int) -> Optional[Dict]:
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


def setup_default_firewall_rules(proxmox, node: str, vmid: int) -> bool:
    """
    Set up default firewall rules for a VM (ports 22, 80, 443, and ICMP)
    Configures firewall with default deny policy and allows only specified ports
    
    Args:
        proxmox: ProxmoxAPI instance
        node: Node name
        vmid: VM ID
    
    Returns:
        True if successful, False otherwise
    """
    try:
        # First, enable firewall and set default policy to DROP (deny by default)
        try:
            firewall_options = {
                'enable': 1,
                'policy_in': 'DROP',
                'policy_out': 'ACCEPT'  # Allow outbound by default
            }
            proxmox.nodes(node).qemu(vmid).firewall.options.put(**firewall_options)
            logger.info("→ Firewall enabled with default deny policy")
        except Exception as e:
            # Options might already be set, continue
            error_str = str(e).lower()
            if 'already' not in error_str and 'duplicate' not in error_str:
                logger.error(f"Failed to set firewall options: {e}")
                # Continue anyway - firewall might already be configured
        
        # Default rules: SSH (22), HTTP (80), HTTPS (443), and ICMP
        # Proxmox API uses: type (in/out), proto (tcp/udp/icmp), dport (destination port)
        default_rules = [
            {'action': 'ACCEPT', 'type': 'in', 'proto': 'tcp', 'dport': '22', 'enable': 1, 'comment': 'SSH'},
            {'action': 'ACCEPT', 'type': 'in', 'proto': 'tcp', 'dport': '80', 'enable': 1, 'comment': 'HTTP'},
            {'action': 'ACCEPT', 'type': 'in', 'proto': 'tcp', 'dport': '443', 'enable': 1, 'comment': 'HTTPS'},
            {'action': 'ACCEPT', 'type': 'in', 'proto': 'icmp', 'enable': 1, 'comment': 'ICMP'},
        ]
        
        for rule in default_rules:
            try:
                proxmox.nodes(node).qemu(vmid).firewall.rules.post(**rule)
            except Exception as e:
                # Rule might already exist, continue
                error_str = str(e).lower()
                if 'already exists' in error_str or 'duplicate' in error_str:
                    continue
                logger.error(f"Failed to add firewall rule {rule.get('comment', 'unknown')}: {e}")
                return False
        
        logger.info(f"✓ Default firewall rules configured for VM {vmid} (deny by default, allow 22/80/443/ICMP)")
        return True
    except Exception as e:
        logger.error(f"Failed to setup default firewall rules: {e}")
        return False


def add_firewall_rule(proxmox, node: str, vmid: int, port: Optional[int] = None, protocol: str = 'tcp', 
                     source_ip: Optional[str] = None, comment: Optional[str] = None) -> bool:
    """
    Add a firewall rule to a VM
    
    Args:
        proxmox: ProxmoxAPI instance
        node: Node name
        vmid: VM ID
        port: Port number (None for ICMP)
        protocol: Protocol ('tcp', 'udp', or 'icmp')
        source_ip: Optional source IP address restriction
        comment: Optional comment for the rule
    
    Returns:
        True if successful, False otherwise
    """
    try:
        # Proxmox API uses: type (in/out), proto (tcp/udp/icmp), dport (destination port)
        rule_params = {
            'action': 'ACCEPT',
            'type': 'in',
            'proto': protocol,
            'enable': 1
        }
        
        if protocol != 'icmp' and port is not None:
            rule_params['dport'] = str(port)
        
        if source_ip:
            rule_params['source'] = source_ip
        
        if comment:
            rule_params['comment'] = comment
        
        proxmox.nodes(node).qemu(vmid).firewall.rules.post(**rule_params)
        return True
    except Exception as e:
        logger.error(f"Failed to add firewall rule: {e}")
        return False


def delete_firewall_rule(proxmox, node: str, vmid: int, port: Optional[int] = None, protocol: str = 'tcp',
                        source_ip: Optional[str] = None) -> bool:
    """
    Delete a firewall rule from a VM
    
    Args:
        proxmox: ProxmoxAPI instance
        node: Node name
        vmid: VM ID
        port: Port number (None for ICMP)
        protocol: Protocol ('tcp', 'udp', or 'icmp')
        source_ip: Optional source IP address (only delete rule matching this IP)
    
    Returns:
        True if rule was deleted, False otherwise
    """
    try:
        # Get all firewall rules
        rules = proxmox.nodes(node).qemu(vmid).firewall.rules.get()
        
        if not isinstance(rules, list):
            rules = rules.get('data', []) if isinstance(rules, dict) else []
        
        deleted = False
        for rule in rules:
            rule_pos = rule.get('pos')
            rule_protocol = rule.get('proto', '').lower()
            rule_destport = rule.get('dport', '')
            rule_source = rule.get('source', '')
            
            # Match protocol
            if rule_protocol != protocol.lower():
                continue
            
            # For ICMP, don't check port
            if protocol.lower() == 'icmp':
                if source_ip and rule_source != source_ip:
                    continue
                # Delete ICMP rule
                try:
                    proxmox.nodes(node).qemu(vmid).firewall.rules(rule_pos).delete()
                    deleted = True
                    continue
                except Exception as e:
                    logger.error(f"Failed to delete ICMP rule: {e}")
                    continue
            
            # For TCP/UDP, check port
            if rule_destport:
                # Handle port ranges (e.g., "80-90" or "80")
                if '-' in rule_destport:
                    port_range = rule_destport.split('-')
                    if len(port_range) == 2:
                        try:
                            start_port = int(port_range[0])
                            end_port = int(port_range[1])
                            if not (start_port <= port <= end_port):
                                continue
                        except ValueError:
                            continue
                else:
                    try:
                        if int(rule_destport) != port:
                            continue
                    except ValueError:
                        continue
            else:
                continue
            
            # If source IP is specified, only delete if it matches
            if source_ip:
                if rule_source != source_ip:
                    continue
            
            # Delete the matching rule
            try:
                proxmox.nodes(node).qemu(vmid).firewall.rules(rule_pos).delete()
                deleted = True
            except Exception as e:
                logger.error(f"Failed to delete firewall rule: {e}")
                return False
        
        return deleted
    except Exception as e:
        logger.error(f"Failed to delete firewall rule: {e}")
        return False


def get_firewall_rules(proxmox, node: str, vmid: int) -> List[Dict]:
    """
    Get all firewall rules for a VM
    
    Args:
        proxmox: ProxmoxAPI instance
        node: Node name
        vmid: VM ID
    
    Returns:
        List of firewall rule dicts
    """
    try:
        rules = proxmox.nodes(node).qemu(vmid).firewall.rules.get()
        if isinstance(rules, dict) and 'data' in rules:
            return rules['data']
        elif isinstance(rules, list):
            return rules
        return []
    except Exception as e:
        logger.error(f"Failed to get firewall rules: {e}")
        return []



