# Critical Information for AI Agents

## ⚠️ PACKAGE MANAGEMENT - REQUIRED

**THIS PROJECT USES `uv` FOR PACKAGE MANAGEMENT. NEVER INSTALL PACKAGES SYSTEM-WIDE.**

### Package Manager
- **Tool**: `uv` (install with: `curl -LsSf https://astral.sh/uv/install.sh | sh`)
- **Virtual Environment**: `.venv/` (created automatically by `uv sync`)
- **Python Version**: 3.10 or higher

### Initial Setup

**ALWAYS use `uv sync` to set up the project:**

```bash
# This creates .venv/, installs dependencies, and installs the package in editable mode
uv sync

# Activate the virtual environment
source .venv/bin/activate
```

### Installing Dependencies

**NEVER use `--break-system-packages` or install packages system-wide.**

Dependencies are managed in `pyproject.toml`. To install/update:
```bash
# Install dependencies (creates .venv if needed)
uv sync

# Update all dependencies
uv sync --upgrade

# Update specific package
uv lock --upgrade-package <package-name>
uv sync
```

### Running the CLI

**The CLI is installed as a command when you run `uv sync`:**

```bash
# Activate virtual environment
source .venv/bin/activate

# Use the proxmox CLI
proxmox --help
proxmox vm create webserver -o ubuntu24 -u admin -k ~/.ssh/id_rsa.pub
```

### Checking if Virtual Environment is Active

The prompt should show `(.venv)` when active:
```bash
(.venv) user@host:~/proxmox$ 
```

### If Virtual Environment Doesn't Exist

Run `uv sync` - it will create `.venv/` automatically:
```bash
uv sync
source .venv/bin/activate
```

## Configuration Files

- **Main config**: `proxmox.ini` (contains credentials - DO NOT commit)
- **Example config**: `proxmox.ini.example` (safe to commit)
- **Config locations**: The CLI searches for `proxmox.ini` in:
  1. Current directory (`./proxmox.ini`)
  2. XDG config directory (`~/.config/proxmox/proxmox.ini`)
  3. Home directory (`~/.proxmox.ini`)

## Key Commands

The project uses a unified CLI (`proxmox`) with subcommands:
- `proxmox vm create/delete/start/stop` - VM management
- `proxmox image create/delete/update` - Image management
- `proxmox dns create/delete` - DNS management
- `proxmox firewall create/delete` - Firewall management

## Dependencies

All dependencies are listed in `pyproject.toml`. The virtual environment should have all packages installed via `uv sync`.

**CRITICAL**: If you get "ModuleNotFoundError", check that:
1. The virtual environment is activated (`source .venv/bin/activate`)
2. The package is in `pyproject.toml` under `[project.dependencies]`
3. Dependencies are installed (`uv sync`)
4. The package is installed in editable mode (`uv sync` does this automatically)

## Documentation Updates

**IMPORTANT**: When making changes to:
- Configuration file structure or options
- CLI commands or arguments
- Installation or setup procedures
- Feature additions or changes

**ALWAYS update the README.md** to reflect these changes. The README is the primary user-facing documentation and must stay current with the codebase.
