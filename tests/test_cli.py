import sys
from unittest.mock import MagicMock, patch

import pytest
import yaml
from pykeepass import create_database

# Import your actual CLI functions and models
from keepass_yaml_env.cli import KeepassConfig, load_and_validate_config, main


@pytest.fixture
def isolated_env(tmp_path):
    """
    Creates a completely isolated testing environment.
    Generates a temporary KeePass DB and a temporary YAML config.
    """
    # 1. Create a dummy KeePass database dynamically
    kdbx_path = tmp_path / "test_db.kdbx"
    master_password = "testpassword123"

    kp = create_database(str(kdbx_path), password=master_password)
    group = kp.add_group(kp.root_group, "TestGroup")
    # Add a fake entry (Title, Username, Password)
    kp.add_entry(group, "db_secret", "testuser", "supersecret")
    kp.save()

    # 2. Create a dummy YAML file pointing to the fake database
    yaml_path = tmp_path / "secrets.yaml"
    yaml_content = {
        "keepass_db": str(kdbx_path),
        "secrets": [
            {
                "entry_path": "TestGroup/db_secret",
                "attribute": "Password",
                "env_var": "TEST_DB_PASSWORD",
            },
            {
                "entry_path": "TestGroup/db_secret",
                "attribute": "Username",
                "env_var": "TEST_DB_USER",
            },
        ],
    }
    with open(yaml_path, "w") as f:
        yaml.dump(yaml_content, f)

    return {
        "yaml_path": str(yaml_path),
        "password": master_password,
        "db_path": str(kdbx_path),
    }


def test_cli_injects_secrets(isolated_env):
    """
    Tests that the CLI correctly parses the YAML, opens the DB,
    and passes the right variables to the subprocess environment.
    """
    test_args = [
        "keepass-yaml-env",
        "-f",
        isolated_env["yaml_path"],
        "--",
        "echo",
        "hello",
    ]

    with (
        patch.object(sys, "argv", test_args),
        patch(
            "keepass_yaml_env.cli.getpass.getpass",
            return_value=isolated_env["password"],
        ),
        patch("keepass_yaml_env.cli.subprocess.run") as mock_run,
    ):
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_run.return_value = mock_result

        with pytest.raises(SystemExit) as excinfo:
            main()

        assert excinfo.value.code == 0
        mock_run.assert_called_once()

        _, kwargs = mock_run.call_args
        injected_env = kwargs.get("env")

        assert injected_env is not None
        assert injected_env.get("TEST_DB_PASSWORD") == "supersecret"
        assert injected_env.get("TEST_DB_USER") == "testuser"


class TestValidateConfig:
    """
    Tests for YAML parsing and Pydantic validation via load_and_validate_config.
    """

    def _run_validation(self, tmp_path, config_data):
        """Helper to write a dict to yaml and run validation."""
        yaml_path = tmp_path / "test_config.yaml"
        with open(yaml_path, "w") as f:
            if isinstance(config_data, str):
                f.write(config_data)
            else:
                yaml.dump(config_data, f)

        return load_and_validate_config(str(yaml_path))

    def test_not_a_dict_raises(self, tmp_path):
        with pytest.raises(SystemExit) as excinfo:
            self._run_validation(tmp_path, "just a string")
        assert excinfo.value.code == 1

    def test_list_raises(self, tmp_path):
        with pytest.raises(SystemExit) as excinfo:
            self._run_validation(tmp_path, [1, 2, 3])
        assert excinfo.value.code == 1

    def test_missing_keepass_db(self, tmp_path):
        with pytest.raises(SystemExit) as excinfo:
            self._run_validation(tmp_path, {"secrets": []})
        assert excinfo.value.code == 1

    def test_keepass_db_not_a_string(self, tmp_path):
        with pytest.raises(SystemExit) as excinfo:
            self._run_validation(tmp_path, {"keepass_db": 42, "secrets": []})
        assert excinfo.value.code == 1

    def test_keepass_db_file_does_not_exist(self, tmp_path):
        """Fail fast if the KDBX file doesn't actually exist on disk."""
        with pytest.raises(SystemExit) as excinfo:
            self._run_validation(tmp_path, {"keepass_db": "/fake/path/db.kdbx", "secrets": []})
        assert excinfo.value.code == 1

    def test_missing_secrets(self, tmp_path):
        db_path = tmp_path / "dummy.kdbx"
        db_path.touch()
        with pytest.raises(SystemExit) as excinfo:
            self._run_validation(tmp_path, {"keepass_db": str(db_path)})
        assert excinfo.value.code == 1

    def test_secrets_not_a_list(self, tmp_path):
        db_path = tmp_path / "dummy.kdbx"
        db_path.touch()
        with pytest.raises(SystemExit) as excinfo:
            self._run_validation(tmp_path, {"keepass_db": str(db_path), "secrets": "bad"})
        assert excinfo.value.code == 1

    def test_secret_entry_not_a_dict(self, tmp_path):
        db_path = tmp_path / "dummy.kdbx"
        db_path.touch()
        with pytest.raises(SystemExit) as excinfo:
            self._run_validation(tmp_path, {"keepass_db": str(db_path), "secrets": ["not a dict"]})
        assert excinfo.value.code == 1

    def test_missing_entry_path(self, tmp_path):
        db_path = tmp_path / "dummy.kdbx"
        db_path.touch()
        with pytest.raises(SystemExit) as excinfo:
            self._run_validation(tmp_path, {"keepass_db": str(db_path), "secrets": [{"env_var": "FOO"}]})
        assert excinfo.value.code == 1

    def test_extra_key_raises_strict_mode(self, tmp_path):
        """Pydantic strictly forbids undocumented keys."""
        db_path = tmp_path / "dummy.kdbx"
        db_path.touch()
        with pytest.raises(SystemExit) as excinfo:
            self._run_validation(
                tmp_path,
                {
                    "keepass_db": str(db_path),
                    "secrets": [{"entry_path": "A", "env_var": "B", "unsupported_key": "C"}],
                },
            )
        assert excinfo.value.code == 1

    def test_valid_config_passes(self, tmp_path):
        db_path = tmp_path / "dummy.kdbx"
        db_path.touch()
        config = self._run_validation(
            tmp_path,
            {
                "keepass_db": str(db_path),
                "secrets": [
                    {
                        "entry_path": "Group/entry",
                        "env_var": "FOO",
                        "attribute": "Password",
                    },
                    {"entry_path": "Group/other", "env_var": "BAR"},
                ],
            },
        )
        assert isinstance(config, KeepassConfig)
        assert len(config.secrets) == 2


class TestExecutionAndRegex:
    """Tests targeting the unexpanded variable safety checks."""

    def test_unexpanded_vars_aborts_execution(self, isolated_env):
        """EDGE CASE: Script should abort if variables fail to expand."""

        test_args = [
            "keepass-yaml-env",
            "-f",
            isolated_env["yaml_path"],
            "--allow-unsafe-args",
            "--",
            "echo",
            "$TEST_DB_USER",  # Exists
            "$MISSING_VAR",  # Does NOT exist
        ]

        with (
            patch.object(sys, "argv", test_args),
            patch(
                "keepass_yaml_env.cli.getpass.getpass",
                return_value=isolated_env["password"],
            ),
            patch("keepass_yaml_env.cli.subprocess.run") as mock_run,
            patch("keepass_yaml_env.cli.sys.stderr", new_callable=MagicMock) as mock_stderr,
        ):
            with pytest.raises(SystemExit) as excinfo:
                main()

            # Expecting failure code 1
            assert excinfo.value.code == 1

            # Subprocess MUST NEVER be called if a variable didn't expand
            mock_run.assert_not_called()

            # Ensure the specific missing variable was logged to stderr
            error_output = "".join(call[0][0] for call in mock_stderr.write.call_args_list)
            assert "MISSING_VAR" in error_output
            assert "TEST_DB_USER" not in error_output  # Successfully expanded vars shouldn't be in the error
