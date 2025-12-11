# Proxmox VM Management Tools

Python scripts for managing virtual machines in Proxmox using Ubuntu cloud images. Create VMs with automated user setup, SSH key injection, and optional puppet integration.

## Quick Start

1. **Setup environment:**
   ```bash
   python3 -m venv venv
   source venv/bin/activate
   pip install -r requirements.txt
   ```

2. **Configure Proxmox:**
   ```bash
   cp proxmox.ini.example proxmox.ini
   # Edit proxmox.ini with your Proxmox host and credentials
   ```

3. **Download Ubuntu images:**
   ```bash
   ./manage-images.py --os ubuntu24
   ```

4. **Create your first VM:**
   ```bash
   ./create-vm.py -n test-vm -o ubuntu24 -u admin -k ~/.ssh/id_rsa.pub
   ```

For detailed instructions, see [QUICKSTART.md](QUICKSTART.md).

## Features

- 🚀 Quick VM deployment from Ubuntu cloud images
- 👥 Automated user creation with SSH keys or encrypted passwords
- 🤖 Optional Puppet integration
- 🎯 Smart node selection based on available resources
- 🔧 Flexible configuration via INI file or command-line

## Requirements

- Python 3.7+
- Proxmox VE 7.0+
- API token or user credentials
- Network access to Proxmox API (port 8006)

## Installation

### 1. Create Virtual Environment

```bash
python3 -m venv venv
source venv/bin/activate  # On Linux/macOS
```

### 2. Install Dependencies

```bash
pip install -r requirements.txt
```

### 3. Configure Proxmox

Copy the example configuration and edit it:

```bash
cp proxmox.ini.example proxmox.ini
```

Edit `proxmox.ini` with your Proxmox details:

```ini
[proxmox]
host = https://your-proxmox-host:8006
verify_ssl = false

[auth]
# Option 1: API Token (recommended)
token_id = root@pam!mytoken
token_secret = your-secret-token

# Option 2: Username/Password
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
```

### 4. Create API Token (Recommended)

1. Log into Proxmox web interface
2. Go to **Datacenter** → **Permissions** → **API Tokens**
3. Click **Add**
4. Select user (e.g., `root@pam`)
5. Enter Token ID (e.g., `mytoken`)
6. Uncheck "Privilege Separation" for full permissions
7. Click **Add** and copy the token secret (shown only once!)

## Usage

### Download Ubuntu Images

```bash
# Download all Ubuntu versions
./manage-images.py

# Download specific version
./manage-images.py --os ubuntu24
./manage-images.py --os ubuntu22

# List available images
./manage-images.py --list
```

### Create VMs

**Basic example:**
```bash
./create-vm.py -n webserver01 -o ubuntu24 -u admin -k ~/.ssh/id_rsa.pub
```

**With custom resources:**
```bash
./create-vm.py -n dbserver01 -o ubuntu22 -c 4 -m 8192 -b 100 -u admin -k ~/.ssh/id_rsa.pub
```

**With password authentication:**
```bash
# Encrypted password (recommended)
./create-vm.py -n devvm01 -o ubuntu24 -u developer --password '$6$rounds=4096$...'

# Or prompt for plaintext password (will be encrypted automatically)
./create-vm.py -n devvm01 -o ubuntu24 -u developer --plain-password
```

**With Puppet:**
```bash
./create-vm.py -n appserver01 -o ubuntu24 -u admin -k ~/.ssh/id_rsa.pub -p
```

**Other options:**
```bash
# Create on specific node
./create-vm.py -n testvm01 -o ubuntu24 -u admin -k ~/.ssh/id_rsa.pub --node pve1

# Create without starting
./create-vm.py -n newvm01 -o ubuntu24 -u admin -k ~/.ssh/id_rsa.pub --no-start
```

## Command Reference

### create-vm.py

```
Required:
  -n, --name NAME          VM name

Optional:
  -o, --os OS              OS: ubuntu22, ubuntu24 (default: ubuntu24)
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
  --config FILE            Config file (default: proxmox.ini)
```

### manage-images.py

```
  --list                   List available images
  --os OS                  OS: ubuntu22, ubuntu24 (default: all)
  --node NODE              Target node (default: auto-select)
  --config FILE            Config file (default: proxmox.ini)
```

## Known Limitations

### Disk Import Requires Manual Step

Due to Proxmox API limitations, disk attachment requires a manual step. When creating a VM, if disk attachment fails, run these commands on your Proxmox node:

```bash
qm disk import <vmid> <image-filename> <storage> --format qcow2
qm set <vmid> --scsi0 <storage>:vm-<vmid>-disk-0
```

The script will provide exact commands when needed.

## Troubleshooting

**Connection errors?**
- Verify `host` in `proxmox.ini` is correct
- Check firewall allows port 8006
- Try `verify_ssl = false` for self-signed certificates

**Image not found?**
- Download it first: `./manage-images.py --os ubuntu24`

**Permission errors?**
- API token needs: `VM.Allocate`, `VM.Config.Disk`, `Storage.Allocate`
- Or uncheck "Privilege Separation" when creating token

**Need more help?**
- See [QUICKSTART.md](QUICKSTART.md) for step-by-step guide
- Use `--help` flag: `./create-vm.py --help`

## Security Notes

- 🔒 Store `proxmox.ini` securely (contains credentials)
- 🔒 Use API tokens instead of passwords
- 🔒 Use SSH keys instead of passwords for VM users
- 🔒 Passwords are encrypted before being sent to cloud-init

## Files

- `create-vm.py` - VM creation script
- `manage-images.py` - Image download/management
- `proxmox_utils.py` - Shared utilities
- `proxmox.ini` - Configuration (create from example)
- `requirements.txt` - Python dependencies

## Support

- Ubuntu versions: 22.04 (Jammy), 24.04 (Noble)
- Note: Ubuntu 20.04 is EOL and not supported
