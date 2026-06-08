import os
import sys
import yaml
import pytest
from unittest.mock import patch, MagicMock
from pykeepass import create_database

# Import your actual CLI function
from keepass_yaml_env.cli import main

@pytest.fixture
def isolated_env(tmp_path):
    """
    This fixture creates a completely isolated testing environment.
    It generates a temporary KeePass DB and a temporary YAML config.
    Everything here is destroyed automatically after the test finishes.
    """
    # 1. Create a dummy KeePass database dynamically
    kdbx_path = tmp_path / "test_db.kdbx"
    master_password = "testpassword123"
    
    kp = create_database(str(kdbx_path), password=master_password)
    group = kp.add_group(kp.root_group, 'TestGroup')
    # Add a fake entry (Title, Username, Password)
    kp.add_entry(group, 'db_secret', 'testuser', 'supersecret') 
    kp.save()

    # 2. Create a dummy YAML file pointing to the fake database
    yaml_path = tmp_path / "secrets.yaml"
    yaml_content = {
        "keepass_db": str(kdbx_path),
        "secrets": [
            {
                "entry_path": "TestGroup/db_secret",
                "attribute": "Password",
                "env_var": "TEST_DB_PASSWORD"
            },
            {
                "entry_path": "TestGroup/db_secret",
                "attribute": "Username",
                "env_var": "TEST_DB_USER"
            }
        ]
    }
    with open(yaml_path, 'w') as f:
        yaml.dump(yaml_content, f)

    # Return the paths so the test function can use them
    return {
        "yaml_path": str(yaml_path),
        "password": master_password
    }

def test_cli_injects_secrets(isolated_env):
    """
    Tests that the CLI correctly parses the YAML, opens the DB, 
    and passes the right variables to the subprocess environment.
    """
    # Simulate the user running: keepass-yaml-env -f temp_secrets.yaml -- echo "hello"
    test_args = ["keepass-yaml-env", "-f", isolated_env["yaml_path"], "--", "echo", "hello"]
    
    # We patch (mock) three things so the test runs silently and safely:
    # 1. sys.argv -> To pass our fake terminal arguments
    # 2. getpass.getpass -> To automatically type our fake master password
    # 3. subprocess.run -> To intercept the command before it actually runs
    with patch.object(sys, 'argv', test_args), \
         patch('getpass.getpass', return_value=isolated_env["password"]), \
         patch('subprocess.run') as mock_run:
         
        # Make the mocked subprocess return a successful exit code (0)
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_run.return_value = mock_result
        
        # Run the main CLI function. We expect it to trigger a SystemExit(0) when done.
        with pytest.raises(SystemExit) as excinfo:
            main()
            
        assert excinfo.value.code == 0
        
        # Verify the command was executed
        mock_run.assert_called_once()
        
        # Grab the environment dictionary that the CLI tried to pass to the subprocess
        _, kwargs = mock_run.call_args
        injected_env = kwargs.get('env')
        
        # THE FINAL ASSERTIONS: Did our secrets make it into the environment?
        assert injected_env is not None
        assert injected_env.get('TEST_DB_PASSWORD') == "supersecret"
        assert injected_env.get('TEST_DB_USER') == "testuser"