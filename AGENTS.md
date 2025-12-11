# Critical Information for AI Agents

## ⚠️ VIRTUAL ENVIRONMENT - REQUIRED

**THIS PROJECT USES A VIRTUAL ENVIRONMENT. NEVER INSTALL PACKAGES SYSTEM-WIDE.**

### Virtual Environment Location
- **Path**: `venv/` (in the project root)
- **Python Version**: 3.14.2

### How to Use the Virtual Environment

**ALWAYS activate the virtual environment before running Python scripts or installing packages:**

```bash
# Activate the virtual environment
source venv/bin/activate

# Then run scripts or install packages
python3 create-vm.py
pip install <package>
```

### Installing Dependencies

**NEVER use `--break-system-packages` or install packages system-wide.**

To install dependencies:
```bash
source venv/bin/activate
pip install -r requirements.txt
```

### Running Scripts

**All Python scripts MUST be run with the virtual environment activated:**

```bash
source venv/bin/activate
python3 create-vm.py
python3 delete-vm.py
python3 manage-images.py
```

### Checking if Virtual Environment is Active

The prompt should show `(venv)` when active:
```bash
(venv) user@host:~/proxmox$ 
```

### If Virtual Environment Doesn't Exist

If `venv/` doesn't exist, create it:
```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

## Configuration Files

- **Main config**: `proxmox.ini` (contains credentials - DO NOT commit)
- **Example config**: `proxmox.ini.example` (safe to commit)

## Key Scripts

- `create-vm.py` - Create VMs with NetBox integration
- `delete-vm.py` - Delete VMs
- `manage-images.py` - Manage VM templates/images

## Dependencies

All dependencies are listed in `requirements.txt`. The virtual environment should have all packages installed.

**CRITICAL**: If a script fails with "ModuleNotFoundError", check that:
1. The virtual environment is activated (`source venv/bin/activate`)
2. The package is in `requirements.txt`
3. Dependencies are installed (`pip install -r requirements.txt`)
