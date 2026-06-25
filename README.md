# keepass-yaml-env

***version: 1.0.1***

[![CI](https://github.com/robxxt/keepass-yaml-env/actions/workflows/ci.yaml/badge.svg)](https://github.com/robxxt/keepass-yaml-env/actions/workflows/ci.yaml)
[![Dependency Security Scan](https://github.com/robxxt/keepass-yaml-env/actions/workflows/dependency_security.yaml/badge.svg)](https://github.com/robxxt/keepass-yaml-env/actions/workflows/dependency_security.yaml)
[![Publish to PyPI](https://github.com/robxxt/keepass-yaml-env/actions/workflows/publish.yaml/badge.svg)](https://github.com/robxxt/keepass-yaml-env/actions/workflows/publish.yaml)

Load KeePass secrets directly into your development environment at runtime — no plain-text `.env` files required.

`keepass-yaml-env` is a CLI wrapper that bridges your [KeePass](https://keepassxc.org/) (`.kdbx`) database and your application. It securely unlocks your database, extracts the secrets you specify in a YAML configuration file, and injects them directly into your program's environment variables in-memory. When your program closes, the secrets vanish. They are never written to disk.

---

## Features

| Feature | Description |
|---------|-------------|
| **Zero Plain-Text Secrets** | Completely replaces local `.env` files. |
| **Language Agnostic** | Works with Python, Node.js, Go, Rust, or any CLI tool. |
| **In-Memory Injection** | Secrets are passed to the child process and destroyed on exit. |
| **Path-Based Resolution** | Prevents collisions by fetching secrets via exact KeePass folder paths. |
| **CI/CD Ready** | Easy to integrate into automated testing pipelines. |
| **Secure by Default** | Secrets are injected via environment variables only — never exposed as command arguments. |
| **Opt-In Unsafe Args** | `--allow-unsafe-args` flag lets you expand `$VAR` in arguments when needed, with an explicit warning. |

---

## Installation

The recommended way to install `keepass-yaml-env` globally is using `pipx`. This installs the tool in an isolated environment but makes the command available everywhere on your system.

```bash
pipx install keepass-yaml-env
```

<!-- Alternatively, you can use:

```bash
uv tool install keepass-yaml-env
```

Or standard pip:

```bash
pip install keepass-yaml-env
``` -->

---

## Quick Start

Let's say you have a Python script (`app.py`) that needs a database password, but you don't want to hardcode it or put it in a `.env` file.

### Step 1: Set up your KeePass database

1. Open KeePassXC and create a database saved at `~/Documents/my_vault.kdbx`.
2. Inside the database, create an entry with the title **`local_postgres`**.
3. Set the **Username** to `admin` and the **Password** to `supersecret`.

Your KeePass entry should look like this:

```
Database
 └── local_postgres
       ├── Title:      local_postgres
       ├── UserName:   admin
       ├── Password:   supersecret
       ├── URL:        (optional)
       └── Notes:      (optional)
```

For nested entries inside groups, the path uses slashes:

```
Root
 └── Development
       └── local_postgres
```

In this case, the `entry_path` would be `Development/local_postgres`.

### Step 2: Create your mapping file (`secrets.yaml`)

Create a file named `secrets.yaml` in your project folder. This tells the tool where to find the database and which secrets map to which environment variables.

```yaml
keepass_db: "~/Documents/my_vault.kdbx"

secrets:
  - entry_path: "local_postgres"
    attribute: "Username"
    env_var: "DB_USER"

  - entry_path: "local_postgres"
    attribute: "Password"
    env_var: "DB_PASSWORD"
```

### Step 3: Run your application

Instead of running `python app.py`, wrap your command with `keepass-yaml-env`:

```bash
keepass-yaml-env -f secrets.yaml -- python app.py
```

**What happens next:**

1. You are prompted securely in the terminal for your KeePass master password.
2. The tool unlocks the database and finds the `local_postgres` entry.
3. It spawns `python app.py` with `DB_USER` and `DB_PASSWORD` injected into the environment.

---

## YAML Configuration Reference

The `secrets.yaml` file supports the following structure.

### Root level

| Key | Type | Required | Description |
|-----|------|----------|-------------|
| `keepass_db` | `string` | Yes | The file path to your `.kdbx` database. Supports `~` for home directory expansion. |
| `secrets` | `list` | Yes | A list of secret mapping objects (at least one). |

### Secret mapping object

| Key | Type | Required | Description |
|-----|------|----------|-------------|
| `entry_path` | `string` | Yes | The path to the entry in KeePass. For nested entries, use slashes (e.g., `Root/Development/DB_Credentials`). |
| `attribute` | `string` | Yes | The field to extract. Valid options: `Password`, `Username`, `URL`, `Notes`. |
| `env_var` | `string` | Yes | The exact name of the environment variable that will be injected into your application. |

---

## KeePass Entry Structure

The tool supports the standard KeePass entry fields. Below is how entries should be organized in your database:

### Single entry (root group)

```
Root Group
 └── local_postgres
       ├── Title:      local_postgres
       ├── UserName:   admin
       ├── Password:   supersecret
       ├── URL:        https://example.com
       └── Notes:      Development credentials
```

YAML mapping:

```yaml
entry_path: "local_postgres"
attribute: "Password"
env_var: "DB_PASSWORD"
```

### Entry inside a group

```
Root Group
 └── Development
       └── db_credentials
             ├── Title:      db_credentials
             ├── UserName:   dbadmin
             └── Password:   s3cret!
```

YAML mapping:

```yaml
entry_path: "Development/db_credentials"
attribute: "Password"
env_var: "DB_PASSWORD"
```

### Nested groups

```
Root Group
 └── Projects
       └── WebApp
             └── api_keys
                   ├── Title:      api_keys
                   ├── UserName:   (empty)
                   └── Notes:      sk-abc123def456
```

YAML mapping:

```yaml
entry_path: "Projects/WebApp/api_keys"
attribute: "Notes"
env_var: "API_KEY"
```

---

## Usage Examples

Because `keepass-yaml-env` acts as a POSIX-compliant wrapper, you can use it to run any terminal command.

### Run a Node.js server

```bash
keepass-yaml-env -f dev-secrets.yaml -- npm run start
```

### Run a Docker container with local secrets

```bash
keepass-yaml-env -f secrets.yaml -- docker compose up
```

### Print secrets to the terminal (for debugging)

```bash
keepass-yaml-env -f secrets.yaml --allow-unsafe-args -- env | grep DB_
```

> **Note:** Using `--allow-unsafe-args` flag will load the variables into the next process as arguments and therefore can be seen by other processes, which removes a layer of security and can compromise the credentials.

---

## Working with the Pipe (`--`) and Shell Expansion

The `--` separator is **required** before the command you want to execute. It tells `keepass-yaml-env` to stop parsing its own arguments and treat everything after it as the target command.

### Using `$` in shell commands

By default, `keepass-yaml-env` does **not** expand `$VAR` references in command arguments. They are passed through literally. To have the tool expand environment variables directly in your arguments, you must opt in with `--allow-unsafe-args`:

```bash
keepass-yaml-env -f secrets.yaml --allow-unsafe-args -- echo $DB_USER $DB_PASSWORD
```

Without `--allow-unsafe-args`, `$DB_USER` is passed as the literal string `$DB_USER` to the command — it is **not** replaced with the secret value.

### Using variables in scripts and Python files

When your command is a **script or Python file** (not a shell command), you do **not** need the `$` prefix. The tool expands variables internally and passes them to the child process as real environment variables:

```bash
keepass-yaml-env -f secrets.yaml -- python app.py
```

Inside `app.py`, access the variables directly:

```python
import os

db_user = os.environ["DB_USER"]
db_password = os.environ["DB_PASSWORD"]
```

No `$` or quoting is needed here — the variables are already set in the process environment.

---

## Security: Environment Injection vs. Argument Expansion

By default, `keepass-yaml-env` **only injects secrets as environment variables** into the child process. Secrets are never placed in command-line arguments, so they are invisible to other users via `ps aux` or `/proc/*/cmdline`.

If you need to expand `$VAR` placeholders directly in your command arguments (e.g., for tools that don't read environment variables), use the `--allow-unsafe-args` flag:

```bash
keepass-yaml-env -f secrets.yaml --allow-unsafe-args -- echo $DB_USER $DB_PASSWORD
```

<div class="callout-warn callout">
<p><strong>Warning:</strong> When <code>--allow-unsafe-args</code> is enabled, expanded secret values become visible in the process table (<code>ps aux</code>). Only use this flag in trusted, single-user environments.</p>
</div>

When `--allow-unsafe-args` is **not** set, any `$VAR` references in arguments are passed through literally (not expanded), and the tool relies entirely on environment variable injection:

```bash
keepass-yaml-env -f secrets.yaml -- python app.py
```

This is the **recommended** approach for most use cases.

---

## Missing Variables

If the command references a variable that was not found in your KeePass database, the tool **aborts immediately** with an error message listing the missing variables:

```
[-] Error: Command execution aborted. The following variables were not found in KeePass: DB_MISSING_VAR
```

This prevents your application from running with undefined secrets.

---

## Development and Contributing

If you want to contribute to the project or run the test suite locally, we use modern Python tooling via `pyproject.toml`.

1. Clone the repository from [GitHub](https://github.com/Robxxt/keepass-yaml-env)
2. Install dependencies using [Poetry](https://python-poetry.org/):

   ```bash
   poetry install --with dev
   ```

3. Run the linter:

   ```bash
   poetry run ruff check . --line-length 120
   ```

4. Run the test suite:

   ```bash
   poetry run pytest -v
   ```

---

**Please Note that it might take me some time to review your suggestions**
