# Testing Interactive Mode for `secrets init`

## Preparation

```bash
# Clean existing database
rm -rf ~/.secrets/default ~/.secrets/config.yml

# Set password (to avoid having to type it twice)
export SECRETS_PASSWORD=123456
```

## Test: Interactive Init with All Confirmations

```bash
./bin/secrets init --verbose
```

**Expected prompts (in order):**

1. `Are you sure you want to execute this action? (Y/n)`
   - Press `Y` and Enter

2. `Do you want to create the database in the default location? (Y/n)`
   - Press `Y` and Enter

3. `Do you want to protect the database with a keyfile? (Y/n)`
   - Press `Y` and Enter

**Expected output:**
```
[DEBUG] Loading configuration...
[DEBUG] Password obtained from environment variable
[DEBUG] Configuration loaded successfully
[DEBUG] Created directory: /home/vscode/.secrets/default (mode: 700)
[INFO] Generating keyfile: /home/vscode/.secrets/default/secrets.key
[DEBUG] Generated keyfile: /home/vscode/.secrets/default/secrets.key
[INFO] Creating KeePass database: /home/vscode/.secrets/default/secrets.kdbx
[DEBUG] Created KeePass database: /home/vscode/.secrets/default/secrets.kdbx (root group: SECRETS_DEFAULT)
[INFO] Writing config file: /home/vscode/.secrets/config.yml
[INFO] ✓ Initialization completed successfully
[INFO]   Database: /home/vscode/.secrets/default/secrets.kdbx
[INFO]   Keyfile: /home/vscode/.secrets/default/secrets.key
[INFO]   Config: /home/vscode/.secrets/config.yml
```

## Test: Interactive Init - Decline Keyfile

```bash
rm -rf ~/.secrets/default ~/.secrets/config.yml
export SECRETS_PASSWORD=123456
./bin/secrets init --verbose
```

**Prompts:**
1. `Are you sure...?` → Press `Y`
2. `Default location?` → Press `Y`
3. `Protect with keyfile?` → Press `n`

**Expected behavior:**
- Should show warning: `[WARN] Keyfile protection recommended for security`
- Should create database **without** keyfile
- Config file should NOT have `keyfile` field

## Test: Interactive Init - Cancel Action

```bash
rm -rf ~/.secrets/default ~/.secrets/config.yml
export SECRETS_PASSWORD=123456
./bin/secrets init
```

**Prompts:**
1. `Are you sure...?` → Press `n`

**Expected behavior:**
- Should show: `[INFO] Operation cancelled by user`
- Should exit with code 0
- Should NOT create any files

## Test: Non-Interactive Mode (No Prompts)

```bash
rm -rf ~/.secrets/default ~/.secrets/config.yml
export SECRETS_PASSWORD=123456
./bin/secrets init --non-interactive --verbose
```

**Expected behavior:**
- **NO prompts** should appear
- Should directly create database with default settings
- Should complete successfully

## Verification Commands

After successful init:

```bash
# Check files created
ls -la ~/.secrets/
ls -la ~/.secrets/default/

# Check config content
cat ~/.secrets/config.yml

# Check permissions
stat -c '%a %n' ~/.secrets/config.yml
stat -c '%a %n' ~/.secrets/default/secrets.kdbx
stat -c '%a %n' ~/.secrets/default/secrets.key
```

Expected permissions:
- `config.yml`: 600
- `secrets.kdbx`: 600
- `secrets.key`: 600
- `default/` directory: 700
- `.secrets/` directory: 700
