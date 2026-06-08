import os
import sys
import yaml
import getpass
import argparse
import subprocess
from pykeepass import PyKeePass
from pykeepass.exceptions import CredentialsError

def main():
    parser = argparse.ArgumentParser(
        description="Inject KeePass secrets into a command's environment."
    )
    parser.add_argument(
        "-f", "--file", 
        default="secrets.yaml", 
        help="Path to the YAML configuration file."
    )
    parser.add_argument(
        "command", 
        nargs=argparse.REMAINDER, 
        help="The command to run (e.g., -- python main.py)"
    )
    
    args = parser.parse_args()
    
    command = args.command
    if command and command[0] == "--":
        command = command[1:]
        
    if not command:
        print("Error: No command provided. Usage: keepass-yaml-env -f secrets.yaml -- <command>")
        sys.exit(1)

    if not os.path.exists(args.file):
        print(f"Error: Configuration file not found: {args.file}")
        sys.exit(1)

    with open(args.file, 'r') as file:
        config = yaml.safe_load(file)

    kdbx_path = config.get('keepass_db')
    secrets_mapping = config.get('secrets', [])

    if not kdbx_path:
        print("Error: YAML file must contain a 'keepass_db' path.")
        sys.exit(1)

    print(f"Unlocking {kdbx_path}...")
    password = getpass.getpass("KeePass Master Password: ")

    try:
        kp = PyKeePass(filename=kdbx_path, password=password)
    except CredentialsError:
        print("Error: Invalid KeePass password.")
        sys.exit(1)
    except Exception as e:
        print(f"Error: Failed to open KeePass database: {e}")
        sys.exit(1)

    injected_env = os.environ.copy() 
    
    for secret in secrets_mapping:
        entry_path = secret.get('entry_path')
        attribute = secret.get('attribute', 'Password').lower()
        env_var = secret.get('env_var')

        if not all([entry_path, env_var]):
            continue

        path_parts = entry_path.strip("/").split("/")
        entry = kp.find_entries(path=path_parts, first=True)

        if entry:
            secret_value = getattr(entry, attribute, None)
            if secret_value:
                injected_env[env_var] = str(secret_value)

    try:
        result = subprocess.run(command, env=injected_env)
        
        sys.exit(result.returncode)
        
    except FileNotFoundError:
        print(f"Error: Could not find command '{command[0]}'.")
        sys.exit(1)
    except KeyboardInterrupt:
        sys.exit(130)

if __name__ == "__main__":
    main()
