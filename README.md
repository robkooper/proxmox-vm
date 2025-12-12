# Proxmox VM Management CLI

A modern CLI tool for managing virtual machines in Proxmox using Ubuntu cloud images. Create, delete, start, and stop VMs with automated user setup, SSH key injection, DNS management, firewall rules, and optional Puppet integration.

## Quick Start

1. **Install the package:**
   ```bash
   uv sync
   source .venv/bin/activate
   ```

2. **Configure Proxmox:**
   ```bash
   # Option 1: Project-specific config (current directory)
   cp proxmox.ini.example proxmox.ini
   
   # Option 2: User-wide config (recommended)
   mkdir -p ~/.config/proxmox
   cp proxmox.ini.example ~/.config/proxmox/proxmox.ini
   
   # Edit the config file with your Proxmox host and credentials
   ```

3. **Download Ubuntu images:**
   ```bash
   proxmox image create ubuntu24
   ```

4. **Create your first VM:**
   ```bash
   proxmox vm create test-vm -o ubuntu24 -u admin -k ~/.ssh/id_rsa.pub
   ```

For development setup, see [DEVELOPMENT.md](DEVELOPMENT.md).

## Features

- 🚀 Quick VM deployment from Ubuntu cloud images
- 👥 Automated user creation with SSH keys or encrypted passwords
- 🤖 Optional Puppet integration
- 🎯 Smart node selection based on available resources
- 🔧 Flexible configuration via INI file or command-line
- 🌐 DNS management via NetBox integration
- 🔥 Firewall rule management
- 📦 Image management (create, update, delete)

## Requirements

- Python 3.10 or higher
- `uv` package manager (install with: `curl -LsSf https://astral.sh/uv/install.sh | sh`)
- Proxmox VE 7.0+
- API token or user credentials
- Network access to Proxmox API (port 8006)
- (Optional) NetBox for DNS and IP management

## Installation

### Using uv (Recommended)

```bash
# Clone the repository
git clone <repository-url>
cd proxmox

# Install package and dependencies (creates .venv automatically)
uv sync

# Activate virtual environment
source .venv/bin/activate
```

The `uv sync` command will:
- Create a `.venv/` virtual environment
- Create/update `uv.lock` with pinned dependency versions
- Install all dependencies
- Install the package in editable mode

### Verify Installation

```bash
# Check if the command is available
which proxmox

# Test the CLI
proxmox --help
```

## Configuration

### Configuration File Locations

The CLI automatically searches for `proxmox.ini` in the following locations (in order):

1. **Current directory**: `./proxmox.ini` (for project-specific configs)
2. **XDG config directory**: `~/.config/proxmox/proxmox.ini` (for user-wide defaults)
3. **Home directory**: `~/.proxmox.ini` (fallback location)

You can also specify a custom path using the `--config` flag:
```bash
proxmox vm create test -o ubuntu24 -u admin -k ~/.ssh/id_rsa.pub --config /path/to/custom.ini
```

### 1. Create Configuration File

**For project-specific config** (recommended for development):
```bash
cp proxmox.ini.example proxmox.ini
```

**For user-wide config** (recommended for production):
```bash
mkdir -p ~/.config/proxmox
cp proxmox.ini.example ~/.config/proxmox/proxmox.ini
```

### 2. Edit Configuration

Edit your `proxmox.ini` file with your Proxmox details:

```ini
[proxmox]
# Proxmox API endpoint
host = https://your-proxmox-host:8006
verify_ssl = true
timeout = 30

# Authentication Method 1: API Token (recommended)
# Create a token in Proxmox: Datacenter -> Permissions -> API Tokens
# Format: user@realm!tokenid (e.g., root@pam!mytoken)
token_id = root@pam!mytoken
token_secret = your-secret-token

# Authentication Method 2: Username and Password
# Leave token_id and token_secret empty to use username/password
# user = root@pam
# password = your-password

[defaults]
storage = local-lvm
bridge = vmbr0
vmid_min = 100
vmid_max = 999
cores = 2
memory = 2048
disk_size = 20

[network]
# IP address assignment method: "dhcp", "netbox", or specific IP
ipaddress = dhcp
# DNS registration method: "none" or "netbox"
register = none
# DNS domain name (required if register = netbox)
domain = example.com
# DNS servers (space-separated)
dns_servers = 1.1.1.1 8.8.8.8

[netbox]  # Optional - for DNS and IP management
url = https://netbox.example.com
token = your-netbox-token
subnet = 192.168.1.0/24
tenant = your-tenant-slug
```

### 3. Create API Token (Recommended)

1. Log into Proxmox web interface
2. Go to **Datacenter** → **Permissions** → **API Tokens**
3. Click **Add**
4. Select user (e.g., `root@pam`)
5. Enter Token ID (e.g., `mytoken`)
6. Uncheck "Privilege Separation" for full permissions
7. Click **Add** and copy the token secret (shown only once!)

## Usage

### VM Management

**Create a VM:**
```bash
# Basic example
proxmox vm create webserver01 -o ubuntu24 -u admin -k ~/.ssh/id_rsa.pub

# With custom resources
proxmox vm create dbserver01 -o ubuntu22 -c 4 -m 8192 -b 100 -u admin -k ~/.ssh/id_rsa.pub

# With password authentication
proxmox vm create devvm01 -o ubuntu24 -u developer --plain-password

# With Puppet
proxmox vm create appserver01 -o ubuntu24 -u admin -k ~/.ssh/id_rsa.pub -p

# On specific node
proxmox vm create testvm01 -o ubuntu24 -u admin -k ~/.ssh/id_rsa.pub --node pve1

# Create without starting
proxmox vm create newvm01 -o ubuntu24 -u admin -k ~/.ssh/id_rsa.pub --no-start
```

**Delete a VM:**
```bash
# By name
proxmox vm delete webserver01

# By VM ID
proxmox vm delete 100

# Force delete (no confirmation)
proxmox vm delete webserver01 -f
```

**Start/Stop VMs:**
```bash
# Start VM
proxmox vm start webserver01
proxmox vm start 100  # Using VM ID

# Stop VM
proxmox vm stop webserver01
proxmox vm stop 100  # Using VM ID
```

### Image Management

**Create/Download images:**
```bash
# Create specific image (only if it doesn't exist)
proxmox image create ubuntu24

# Create all images
proxmox image create all
```

**Update images:**
```bash
# Update specific image (delete and re-download)
proxmox image update ubuntu24

# Update all images
proxmox image update all
```

**Delete images:**
```bash
# Delete specific image
proxmox image delete ubuntu22

# Delete all images
proxmox image delete all
```

### DNS Management

**Create DNS records:**
```bash
proxmox dns create myserver 192.168.1.100
```

**Delete DNS records:**
```bash
# By hostname
proxmox dns delete myserver

# By IP address
proxmox dns delete 192.168.1.100
```

### Firewall Management

**Create firewall rules:**
```bash
# Allow port 8080 from all sources
proxmox firewall create webserver 8080

# Allow port 3306 from specific IP
proxmox firewall create dbserver 3306 --ip 192.168.1.100

# Allow ICMP (no port specified)
proxmox firewall create webserver
```

**Delete firewall rules:**
```bash
# Delete port rule
proxmox firewall delete webserver 8080

# Delete port rule with specific source IP
proxmox firewall delete dbserver 3306 --ip 192.168.1.100

# Delete ICMP rule
proxmox firewall delete webserver
```

## Command Reference

### VM Commands

```bash
# Create VM
proxmox vm create <name> [options]
  -o, --os OS              OS: ubuntu22, ubuntu24, rocky8, rocky9, rocky10 (default: ubuntu24)
  -c, --cores CORES        CPU cores (default: from config)
  -m, --memory MB          Memory in MB (default: from config)
  -b, --bootsize GB        Disk size in GB (default: from config)
  -u, --username USER      Primary user (default: admin)
  -k, --keyfile FILE       SSH public key file
  --password HASH          Encrypted password hash (SHA-512 format)
  --plain-password         Prompt for password and encrypt it
  -p, --puppet             Enable puppet agent
  --node NODE              Target node (default: auto-select)
  --no-start               Don't start VM after creation
  -t, --tag TAG            Additional tag (can be specified multiple times)

# Delete VM
proxmox vm delete <name-or-id> [-f, --force]

# Start VM
proxmox vm start <name-or-id>

# Stop VM
proxmox vm stop <name-or-id>
```

### Image Commands

```bash
# Create image (only if doesn't exist)
proxmox image create <image-name-or-all>

# Update image (delete and re-download)
proxmox image update <image-name-or-all>

# Delete image
proxmox image delete <image-name-or-all>

# Available images: ubuntu22, ubuntu24, rocky8, rocky9, rocky10, or "all"
```

### DNS Commands

```bash
# Create DNS record
proxmox dns create <hostname> <ip-address>

# Delete DNS record
proxmox dns delete <hostname-or-ip>
```

### Firewall Commands

```bash
# Create firewall rule
proxmox firewall create <vm-name-or-id> [port] [--ip source-ip]

# Delete firewall rule
proxmox firewall delete <vm-name-or-id> [port] [--ip source-ip]
```

### Global Options

All commands support:
```bash
--config FILE            Config file path (default: searches ./proxmox.ini, ~/.config/proxmox/proxmox.ini, ~/.proxmox.ini)
```

## Examples

### Complete Workflow

```bash
# 1. Download Ubuntu 24.04 image
proxmox image create ubuntu24

# 2. Create a web server VM
proxmox vm create webserver -o ubuntu24 -c 4 -m 4096 -b 50 -u admin -k ~/.ssh/id_rsa.pub

# 3. Create DNS record (if NetBox configured)
proxmox dns create webserver 192.168.1.100

# 4. Add firewall rule for HTTP/HTTPS
proxmox firewall create webserver 80
proxmox firewall create webserver 443

# 5. Start the VM
proxmox vm start webserver
```

### Advanced VM Creation

```bash
# Create VM with Puppet, custom tags, and specific node
proxmox vm create appserver -o ubuntu24 -u admin -k ~/.ssh/id_rsa.pub \
  -p --puppet-server puppet.example.com \
  -t production -t web \
  --node pve1
```

## Known Limitations

### Disk Import Requires Manual Step

Due to Proxmox API limitations, disk attachment may require a manual step in rare cases. When creating a VM, if disk attachment fails, the CLI will provide exact commands to run on your Proxmox node.

## Troubleshooting

**Command not found?**
- Make sure you ran `uv sync` and activated the virtual environment: `source .venv/bin/activate`
- Verify installation: `which proxmox`

**Connection errors?**
- Verify `host` in your config file is correct (check which config file is being used)
- Check firewall allows port 8006
- Try `verify_ssl = false` for self-signed certificates

**Image not found?**
- Download it first: `proxmox image create ubuntu24`

**Permission errors?**
- API token needs: `VM.Allocate`, `VM.Config.Disk`, `Storage.Allocate`
- Or uncheck "Privilege Separation" when creating token

**Need more help?**
- Use `--help` flag: `proxmox --help` or `proxmox vm create --help`
- See [DEVELOPMENT.md](DEVELOPMENT.md) for development setup

## Security Notes

- 🔒 Store your config file securely (contains credentials)
- 🔒 Use API tokens instead of passwords
- 🔒 Use SSH keys instead of passwords for VM users
- 🔒 Passwords are encrypted before being sent to cloud-init
- 🔒 Never commit config files (`proxmox.ini`) to version control
- 🔒 Consider using `~/.config/proxmox/proxmox.ini` for user-wide config (better permissions)

## Project Structure

```
proxmox/
├── src/
│   └── proxmox/           # Package source code
│       ├── cli.py         # Main CLI entry point
│       ├── commands/      # Command implementations
│       └── ...
├── .venv/                 # Virtual environment (created by uv sync)
├── pyproject.toml         # Package configuration
├── uv.lock                # Locked dependency versions
├── proxmox.ini.example    # Configuration template
└── README.md              # This file
```

## Supported Operating Systems

- Ubuntu 22.04 LTS (Jammy)
- Ubuntu 24.04 LTS (Noble)
- Rocky Linux 8
- Rocky Linux 9
- Rocky Linux 10

## Development

For information on developing and contributing to this project, see [DEVELOPMENT.md](DEVELOPMENT.md).

## License

[Add your license here]
