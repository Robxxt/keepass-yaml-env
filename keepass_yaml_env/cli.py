import argparse
import getpass
import os
import re
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, List

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator
from pykeepass import PyKeePass
from pykeepass.exceptions import CredentialsError


class SecretEntry(BaseModel):
    """Pydantic model representing a single secret to extract."""

    # STRICT MODE: Throws an error if any undocumented keys are found in the YAML
    model_config = ConfigDict(extra="forbid")

    entry_path: str = Field(..., min_length=1, description="Path to the KeePass entry")
    env_var: str = Field(..., min_length=1, description="Target environment variable")
    attribute: str = Field(default="Password", description="Entry attribute to extract")


class KeepassConfig(BaseModel):
    """Pydantic model representing the root YAML configuration."""

    # STRICT MODE: Throws an error if any undocumented keys are found in the YAML
    model_config = ConfigDict(extra="forbid")

    keepass_db: Path = Field(..., description="Path to the KeePass .kdbx file")
    secrets: List[SecretEntry] = Field(..., min_length=1)

    @field_validator("keepass_db")
    @classmethod
    def check_keepass_db_exists(cls, v: Path) -> Path:
        """Fail fast if the database file doesn't exist before asking for passwords."""
        if not v.is_file():
            raise ValueError(f"[-] Database file not found at: {v}")
        return v


def load_and_validate_config(filepath: str) -> KeepassConfig:
    """Loads the YAML file and parses it through Pydantic."""
    config_path = Path(filepath)
    if not config_path.is_file():
        print(f"- [Error]: Configuration file not found: {filepath}", file=sys.stderr)
        sys.exit(1)

    with open(config_path, "r") as file:
        try:
            raw_config: Dict[str, Any] = yaml.safe_load(file)
        except yaml.YAMLError as e:
            print(f"[-] Error: Failed to parse YAML file: {e}", file=sys.stderr)
            sys.exit(1)

    if not isinstance(raw_config, dict):
        print("[-] Error: YAML file must contain a top-level mapping.", file=sys.stderr)
        sys.exit(1)

    try:
        return KeepassConfig(**raw_config)
    except ValidationError as e:
        print("[-] Error: Configuration validation failed:", file=sys.stderr)
        for error in e.errors():
            # Format Pydantic's error location nicely (e.g., secrets -> 0 -> env_var)
            loc = " -> ".join(str(loc) for loc in error["loc"])

            # Provide a cleaner message for extra forbidden fields
            if error["type"] == "extra_forbidden":
                print(
                    f"  - [{loc}]: Unknown field. This key is not allowed.",
                    file=sys.stderr,
                )
            else:
                print(f"  - [{loc}]: {error['msg']}", file=sys.stderr)
        sys.exit(1)


def main() -> None:
    parser = argparse.ArgumentParser(description="Inject KeePass secrets into a command's environment.")
    parser.add_argument(
        "-f",
        "--file",
        default="secrets.yaml",
        help="Path to the YAML configuration file.",
    )
    parser.add_argument(
        "command",
        nargs=argparse.REMAINDER,
        help="The command to run (e.g., -- echo $VAR1 $VAR2)",
    )
    args = parser.parse_args()
    command = args.command

    if command and command[0] == "--":
        command = command[1:]

    if not command:
        print(
            "[-] Error: No command provided. Usage: keepass-yaml-env -f " "secrets.yaml -- <command>",
            file=sys.stderr,
        )
        sys.exit(1)

    # 1. Load and Validate via Pydantic
    config = load_and_validate_config(args.file)

    # 2. Unlock Database
    print(f"Unlocking {config.keepass_db}...")
    password = getpass.getpass("KeePass Master Password: ")

    try:
        kp = PyKeePass(filename=str(config.keepass_db), password=password)
    except CredentialsError:
        print("[-] Error: Invalid KeePass password.", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"[-] Error: Failed to open KeePass database: {e}", file=sys.stderr)
        sys.exit(1)
    finally:
        del password

    injected_env = os.environ.copy()

    # 3. Extract Secrets
    for secret in config.secrets:
        path_parts = secret.entry_path.strip("/").split("/")
        entry = kp.find_entries(path=path_parts, first=True)

        if entry:
            attribute_name = secret.attribute.lower()
            secret_value = getattr(entry, attribute_name, None)

            if secret_value:
                injected_env[secret.env_var] = str(secret_value)
            else:
                print(
                    f"Warning: Attribute '{secret.attribute}' is empty for entry '{secret.entry_path}'.",
                    file=sys.stderr,
                )
        else:
            print(
                f"Warning: KeePass entry not found for path '{secret.entry_path}'.",
                file=sys.stderr,
            )

    # Update the parent environment temporarily so expandvars can access the new secrets.
    os.environ.update(injected_env)

    # Expand environment variables (e.g., $VAR1) directly in the command arguments
    expanded_command = [os.path.expandvars(arg) for arg in command]

    # Check for unexpanded environment variables (e.g., $VAR or ${VAR})
    # This regex captures standard bash-style variable names
    unexpanded_pattern = re.compile(r"\$([A-Za-z_][A-Za-z0-9_]*)|\$\{([A-Za-z_][A-Za-z0-9_]*)\}")
    missing_vars = set()

    for arg in expanded_command:
        for match in unexpanded_pattern.findall(arg):
            # match is a tuple like ('VAR', '') or ('', 'VAR') based on the regex group
            var_name = match[0] or match[1]
            missing_vars.add(var_name)

    if missing_vars:
        missing_list = ", ".join(sorted(missing_vars))
        print(
            f"[-] Error: Command execution aborted.\n"
            "    The following variables were not found in KeePass"
            f": {missing_list}",
            file=sys.stderr,
        )
        sys.exit(1)

    try:
        result = subprocess.run(expanded_command, env=injected_env)
        sys.exit(result.returncode)

    except FileNotFoundError:
        print(
            f"[-] Error: Could not find command '{expanded_command[0]}'.",
            file=sys.stderr,
        )
        sys.exit(1)
    except KeyboardInterrupt:
        sys.exit(130)


if __name__ == "__main__":
    main()
