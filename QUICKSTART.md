# Quick Start Guide

Get up and running with Proxmox VM management in 5 minutes!

## Prerequisites

- Python 3.7+
- Proxmox API access (token or credentials)

## Setup (5 minutes)

### 1. Create Virtual Environment

```bash
python3 -m venv venv
source venv/bin/activate
```

### 2. Install Dependencies

```bash
pip install -r requirements.txt
```

### 3. Configure Proxmox

```bash
cp proxmox.ini.example proxmox.ini
nano proxmox.ini  # or use your preferred editor
```

Minimum configuration needed:
- `host` - Your Proxmox URL
- Either `token_id`/`token_secret` OR `user`/`password`
- `storage` - Your storage name (e.g., local-lvm)

### 4. Download Ubuntu Image

```bash
./manage-images.py --os ubuntu24
```

This downloads the Ubuntu 24.04 cloud image directly to your Proxmox storage.

### 5. Create Your First VM

```bash
./create-vm.py -n test-vm -o ubuntu24 -u admin -k ~/.ssh/id_rsa.pub
```

That's it! Your VM is now running.

## Next Steps

- Read the full [README.md](README.md) for advanced features
- Try creating VMs with different configurations
- Enable puppet with the `-p` flag
- Explore automatic node selection

## Common Commands

```bash
# List templates
./manage-images.py --list

# Create VM with 4 cores, 8GB RAM, 100GB disk
./create-vm.py -n web01 -o ubuntu24 -c 4 -m 8192 -b 100 -u admin -k ~/.ssh/id_rsa.pub

# Create VM with puppet
./create-vm.py -n app01 -o ubuntu24 -u admin -k ~/.ssh/id_rsa.pub -p

# Create VM on specific node
./create-vm.py -n db01 -o ubuntu22 -u admin -k ~/.ssh/id_rsa.pub --node pve1

# Create VM with password (prompts securely)
./create-vm.py -n dev01 -o ubuntu24 -u developer --plain-password
```

## Troubleshooting

**Can't connect to Proxmox?**
- Check `host` in proxmox.ini
- Set `verify_ssl = false` for self-signed certs
- Verify credentials/token are correct

**No image found?**
- Run: `./manage-images.py --os ubuntu24`

**Need help?**
- Check [README.md](README.md) for detailed documentation
- Use `--help` flag: `./create-vm.py --help`

## Getting API Token

1. Proxmox web UI → Datacenter → Permissions → API Tokens
2. Click "Add"
3. Select user: `root@pam`
4. Token ID: `automation` (or your choice)
5. Uncheck "Privilege Separation"
6. Copy the token secret (shown only once!)
7. Add to proxmox.ini:
   ```ini
   token_id = root@pam!automation
   token_secret = your-copied-secret
   ```


