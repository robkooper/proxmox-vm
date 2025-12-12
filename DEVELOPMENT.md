# Development Guide

This guide explains how to set up and work on the Proxmox CLI project.

## Prerequisites

- Python 3.10 or higher
- `uv` package manager (install with: `curl -LsSf https://astral.sh/uv/install.sh | sh`)
- Access to a Proxmox server for testing
- `proxmox.ini` configuration file (copy from `proxmox.ini.example`)

## Initial Setup

### 1. Navigate to Project

```bash
cd proxmox  # or wherever you cloned the repository
```

### 2. Set Up Virtual Environment and Install

Using `uv sync` to create a virtual environment, lock dependencies, and install in editable mode:

```bash
# Sync creates .venv, installs all dependencies, and installs package in editable mode
uv sync

# Activate the virtual environment
source .venv/bin/activate
```

**What this does:**
- ✅ Creates `.venv/` virtual environment (in project root)
- ✅ Creates/updates `uv.lock` file with pinned dependency versions
- ✅ Installs all dependencies from `pyproject.toml` with exact versions
- ✅ Installs package in editable mode automatically
- ✅ Makes `proxmox` CLI command available

The package is installed in editable mode by default, meaning:
- Changes to source code are immediately available
- No need to reinstall after making changes
- The `proxmox` CLI command is available in your PATH

**Note:** The `uv.lock` file ensures reproducible builds by pinning exact dependency versions. This is committed to version control.

### 3. Verify Installation

```bash
# Check if the command is available
which proxmox

# Test the CLI
proxmox --help
```

## Development Workflow

### Making Changes

1. **Edit source files** in `src/proxmox/`:
   - `src/proxmox/cli.py` - Main CLI entry point
   - `src/proxmox/commands/` - Command implementations
   - `src/proxmox/proxmox_utils.py` - Core utilities
   - `src/proxmox/netbox_utils.py` - NetBox integration

2. **Test immediately** - No reinstall needed with editable install:
   ```bash
   proxmox --help
   proxmox vm create --help
   ```

3. **Run actual commands** (with proper configuration):
   ```bash
   proxmox vm create webserver -o ubuntu24 -u admin -k ~/.ssh/id_rsa.pub
   proxmox vm start webserver
   proxmox vm stop webserver
   ```

### Testing Commands

#### Test Help and Structure

```bash
# Main help
proxmox --help

# VM commands
proxmox vm --help
proxmox vm create --help
proxmox vm delete --help
proxmox vm start --help
proxmox vm stop --help

# DNS commands
proxmox dns --help
proxmox dns create --help
proxmox dns delete --help

# Firewall commands
proxmox firewall --help
proxmox firewall create --help
proxmox firewall delete --help

# Image commands
proxmox image --help
proxmox image create --help
proxmox image delete --help
proxmox image update --help
```

#### Test with Mock/Real Proxmox

```bash
# Make sure proxmox.ini is configured
cp proxmox.ini.example proxmox.ini
# Edit proxmox.ini with your credentials

# Test commands (will connect to real Proxmox)
proxmox vm list  # if implemented
proxmox image create ubuntu24
```

### Running Without Installation

If you prefer not to install, you can run the CLI directly:

```bash
# From project root
python -m proxmox.cli --help

# Or with explicit path
python src/proxmox/cli.py --help
```

However, editable install is recommended for easier testing.

## Project Structure

```
proxmox/
├── src/
│   └── proxmox/
│       ├── __init__.py
│       ├── cli.py              # Main CLI entry point
│       ├── proxmox_utils.py    # Core Proxmox utilities
│       ├── netbox_utils.py      # NetBox integration
│       ├── vm_create.py         # VM creation logic
│       ├── vm_delete.py         # VM deletion logic
│       └── commands/
│           ├── __init__.py
│           ├── vm.py            # VM command handlers
│           ├── dns.py           # DNS command handlers
│           ├── firewall.py      # Firewall command handlers
│           └── images.py        # Image command handlers
├── .venv/                       # Virtual environment (created by uv sync)
├── pyproject.toml               # Package configuration and dependencies
├── uv.lock                      # Locked dependency versions (created by uv lock/sync)
├── proxmox.ini.example          # Configuration template
└── DEVELOPMENT.md               # This file
```

## Adding New Commands

### 1. Create Command Handler

Create a new file in `src/proxmox/commands/` or add to existing one:

```python
# src/proxmox/commands/mycommand.py
def setup_mycommand_parser(parser):
    parser.add_argument('arg1', help='First argument')
    parser.add_argument('--flag', help='Optional flag')

def handle_mycommand(args):
    # Implementation here
    pass
```

### 2. Register in CLI

Edit `src/proxmox/cli.py`:

```python
from proxmox.commands import vm, dns, firewall, images, mycommand

# In main():
mycommand_parser = subparsers.add_parser('mycommand', help='My command')
mycommand_parser.add_argument('--config', default='proxmox.ini')
mycommand.setup_mycommand_parser(mycommand_parser)

# In command execution:
elif args.command == 'mycommand':
    mycommand.handle_mycommand(args)
```

### 3. Test Immediately

```bash
proxmox mycommand --help
proxmox mycommand arg1 --flag value
```

## Debugging

### Enable Verbose Logging

Edit `src/proxmox/proxmox_utils.py` to change logging level:

```python
logger.setLevel(logging.DEBUG)  # Instead of INFO
```

### Run with Python Debugger

```bash
python -m pdb -m proxmox.cli vm create webserver -o ubuntu24
```

### Check Import Issues

```bash
# Test imports
python -c "from proxmox.cli import main; print('OK')"
python -c "from proxmox.commands import vm; print('OK')"
```

## Updating Dependencies

### Add New Dependency

1. Edit `pyproject.toml`:
   ```toml
   dependencies = [
       "existing-package>=1.0.0",
       "new-package>=2.0.0",  # Add here
   ]
   ```

2. Update lock file and reinstall:
   ```bash
   uv lock
   uv sync
   ```

### Update Existing Dependencies

```bash
# Update all dependencies (updates uv.lock and reinstalls)
uv sync --upgrade

# Update specific package
uv lock --upgrade-package proxmoxer
uv sync
```

## Alternative: Manual Setup (Not Recommended)

If you need to use `uv pip install` directly instead of `uv sync`:

```bash
# Create venv
uv venv

# Install in editable mode
uv pip install -e .

# Activate
source venv/bin/activate
```

**Note:** This approach doesn't create a `uv.lock` file, so dependency versions won't be pinned. Use `uv sync` instead for reproducible builds.

## Troubleshooting

### Command Not Found

```bash
# Check if installed
which proxmox

# If not found, reinstall
uv sync

# Make sure venv is activated
source .venv/bin/activate

# Or check Python path
python -c "import sys; print('\n'.join(sys.path))"
```

### Import Errors

```bash
# Test imports
python -c "import proxmox; print(proxmox.__file__)"
python -c "from proxmox.cli import main; print('OK')"

# Check if src/ is in path
python -c "import sys; sys.path.insert(0, 'src'); from proxmox.cli import main"
```

### Changes Not Reflecting

- Make sure you ran `uv sync` (installs in editable mode by default)
- Check that you're editing files in `src/proxmox/`
- Make sure `.venv` is activated: `source .venv/bin/activate`
- Try resyncing: `uv sync --reinstall`

## Building for Distribution

When ready to distribute:

```bash
# Build wheel
uv build

# Or using standard tools
python -m build
```

## Code Style

- Follow PEP 8
- Use type hints where appropriate
- Add docstrings to functions and classes
- Keep functions focused and single-purpose

## Testing Checklist

Before committing changes:

- [ ] All help commands work: `proxmox <command> --help`
- [ ] No import errors
- [ ] Code follows project structure
- [ ] Dependencies updated in `pyproject.toml` if needed
- [ ] Tested with real Proxmox (if possible)

## Quick Reference

```bash
# Complete setup (first time)
uv sync
source .venv/bin/activate

# Daily development (activate venv if needed)
source .venv/bin/activate
proxmox --help

# Test specific command
proxmox vm create webserver -o ubuntu24 -u admin -k ~/.ssh/id_rsa.pub

# Update dependencies
uv sync --upgrade

# Run without install
python -m proxmox.cli --help

# Check installation
which proxmox
python -c "import proxmox; print(proxmox.__file__)"
```
