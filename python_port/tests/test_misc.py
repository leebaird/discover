"""
Tests for the misc module.

This file contains tests for the misc module of the Discover Framework.
"""

import os
import pytest
from pathlib import Path
from modules import misc

def test_update_system_function_exists():
    """Test that the update_system function exists."""
    assert hasattr(misc, 'update_system')
    assert callable(misc.update_system)

def test_sensitive_detector_function_exists():
    """Test that the sensitive_detector function exists."""
    assert hasattr(misc, 'sensitive_detector')
    assert callable(misc.sensitive_detector)

def test_api_scanner_function_exists():
    """Test that the api_scanner function exists."""
    assert hasattr(misc, 'api_scanner')
    assert callable(misc.api_scanner)

def test_msf_web_api_function_exists():
    """Test that the msf_web_api function exists."""
    assert hasattr(misc, 'msf_web_api')
    assert callable(misc.msf_web_api)

def test_parse_xml_function_exists():
    """Test that the parse_xml function exists."""
    assert hasattr(misc, 'parse_xml')
    assert callable(misc.parse_xml)

def test_generate_payload_function_exists():
    """Test that the generate_payload function exists."""
    assert hasattr(misc, 'generate_payload')
    assert callable(misc.generate_payload)

def test_start_listener_function_exists():
    """Test that the start_listener function exists."""
    assert hasattr(misc, 'start_listener')
    assert callable(misc.start_listener)

def test_oauth_jwt_tester_function_exists():
    """Test that the oauth_jwt_tester function exists."""
    assert hasattr(misc, 'oauth_jwt_tester')
    assert callable(misc.oauth_jwt_tester)

def test_cloud_scanner_function_exists():
    """Test that the cloud_scanner function exists."""
    assert hasattr(misc, 'cloud_scanner')
    assert callable(misc.cloud_scanner)

def test_container_scanner_function_exists():
    """Test that the container_scanner function exists."""
    assert hasattr(misc, 'container_scanner')
    assert callable(misc.container_scanner)

def test_oauth_jwt_tester_menu_navigation(monkeypatch):
    """Test that oauth_jwt_tester handles menu navigation correctly."""
    # Mock input to return "3" (Previous menu)
    monkeypatch.setattr("builtins.input", lambda _: "3")

    # Mock print to capture output
    printed_messages = []
    monkeypatch.setattr("builtins.print", lambda *args: printed_messages.append(" ".join(map(str, args))))

    # Call the function
    misc.oauth_jwt_tester()

    # Check that the function printed the menu
    assert any("OAuth/JWT Security Tester" in msg for msg in printed_messages)
    assert any("1.  OAuth 2.0 Tests" in msg for msg in printed_messages)
    assert any("2.  JWT Tests" in msg for msg in printed_messages)
    assert any("3.  Previous menu" in msg for msg in printed_messages)

def test_cloud_scanner_menu_navigation(monkeypatch):
    """Test that cloud_scanner handles menu navigation correctly."""
    # Mock input to return "4" (Previous menu)
    monkeypatch.setattr("builtins.input", lambda _: "4")

    # Mock print to capture output
    printed_messages = []
    monkeypatch.setattr("builtins.print", lambda *args: printed_messages.append(" ".join(map(str, args))))

    # Call the function
    misc.cloud_scanner()

    # Check that the function printed the menu
    assert any("Cloud Security Scanner" in msg for msg in printed_messages)
    assert any("1.  AWS Security Tests" in msg for msg in printed_messages)
    assert any("2.  Azure Security Tests" in msg for msg in printed_messages)
    assert any("3.  Google Cloud Security Tests" in msg for msg in printed_messages)
    assert any("4.  Previous menu" in msg for msg in printed_messages)

def test_container_scanner_menu_navigation(monkeypatch):
    """Test that container_scanner handles menu navigation correctly."""
    # Mock input to return "5" (Previous menu)
    monkeypatch.setattr("builtins.input", lambda _: "5")

    # Mock print to capture output
    printed_messages = []
    monkeypatch.setattr("builtins.print", lambda *args: printed_messages.append(" ".join(map(str, args))))

    # Call the function
    misc.container_scanner()

    # Check that the function printed the menu
    assert any("Container Security Scanner" in msg for msg in printed_messages)
    assert any("1.  Docker Images" in msg for msg in printed_messages)
    assert any("2.  Docker Containers" in msg for msg in printed_messages)
    assert any("3.  Kubernetes Resources" in msg for msg in printed_messages)
    assert any("4.  All Container Resources" in msg for msg in printed_messages)
    assert any("5.  Previous menu" in msg for msg in printed_messages)

def test_oauth_jwt_tester_invalid_choice(monkeypatch):
    """Test that oauth_jwt_tester handles invalid choices correctly."""
    # Mock input to return an invalid choice and then "3" (Previous menu)
    inputs = iter(["invalid", "3"])
    monkeypatch.setattr("builtins.input", lambda _: next(inputs))

    # Mock oauth_jwt_tester to avoid recursion
    original_oauth_jwt_tester = misc.oauth_jwt_tester
    call_count = [0]

    def mock_oauth_jwt_tester():
        call_count[0] += 1
        if call_count[0] == 1:
            return original_oauth_jwt_tester()
        return None

    monkeypatch.setattr(misc, "oauth_jwt_tester", mock_oauth_jwt_tester)

    # Mock print to capture output
    printed_messages = []
    monkeypatch.setattr("builtins.print", lambda *args: printed_messages.append(" ".join(map(str, args))))

    # Call the function
    misc.oauth_jwt_tester()

    # Check that the function printed the error message
    assert any("Invalid choice or entry" in msg for msg in printed_messages)

def test_cloud_scanner_invalid_choice(monkeypatch):
    """Test that cloud_scanner handles invalid choices correctly."""
    # Mock input to return an invalid choice and then "4" (Previous menu)
    inputs = iter(["invalid", "4"])
    monkeypatch.setattr("builtins.input", lambda _: next(inputs))

    # Mock cloud_scanner to avoid recursion
    original_cloud_scanner = misc.cloud_scanner
    call_count = [0]

    def mock_cloud_scanner():
        call_count[0] += 1
        if call_count[0] == 1:
            return original_cloud_scanner()
        return None

    monkeypatch.setattr(misc, "cloud_scanner", mock_cloud_scanner)

    # Mock print to capture output
    printed_messages = []
    monkeypatch.setattr("builtins.print", lambda *args: printed_messages.append(" ".join(map(str, args))))

    # Call the function
    misc.cloud_scanner()

    # Check that the function printed the error message
    assert any("Invalid choice or entry" in msg for msg in printed_messages)

def test_container_scanner_invalid_choice(monkeypatch):
    """Test that container_scanner handles invalid choices correctly."""
    # Mock input to return an invalid choice and then "5" (Previous menu)
    inputs = iter(["invalid", "5"])
    monkeypatch.setattr("builtins.input", lambda _: next(inputs))

    # Mock container_scanner to avoid recursion
    original_container_scanner = misc.container_scanner
    call_count = [0]

    def mock_container_scanner():
        call_count[0] += 1
        if call_count[0] == 1:
            return original_container_scanner()
        return None

    monkeypatch.setattr(misc, "container_scanner", mock_container_scanner)

    # Mock print to capture output
    printed_messages = []
    monkeypatch.setattr("builtins.print", lambda *args: printed_messages.append(" ".join(map(str, args))))

    # Call the function
    misc.container_scanner()

    # Check that the function printed the error message
    assert any("Invalid choice or entry" in msg for msg in printed_messages)

def test_sensitive_detector_invalid_directory(monkeypatch):
    """Test that sensitive_detector checks for a valid directory."""
    # Mock input to return an invalid directory path
    monkeypatch.setattr("builtins.input", lambda _: "/path/to/nonexistent/directory")

    # Mock os.path.isdir to return False
    monkeypatch.setattr("os.path.isdir", lambda _: False)

    # Mock print to capture output
    printed_messages = []
    monkeypatch.setattr("builtins.print", lambda *args: printed_messages.append(" ".join(map(str, args))))

    # Call the function
    misc.sensitive_detector()

    # Check that the function printed the error message
    assert any("Invalid directory" in msg for msg in printed_messages)

def test_api_scanner_invalid_input(monkeypatch):
    """Test that api_scanner checks for valid input."""
    # Mock input to return an empty string
    monkeypatch.setattr("builtins.input", lambda _: "")

    # Mock print to capture output
    printed_messages = []
    monkeypatch.setattr("builtins.print", lambda *args: printed_messages.append(" ".join(map(str, args))))

    # Call the function
    misc.api_scanner()

    # Check that the function printed the error message
    assert any("Invalid target" in msg for msg in printed_messages)

def test_update_system_mocks(monkeypatch):
    """Test that update_system uses subprocess.run."""
    # Mock subprocess.run to track calls
    calls = []
    def mock_run(*args, **kwargs):
        # Record all arguments in the command
        for arg in args[0]:
            calls.append(arg)
        # Create a mock return value
        class MockCompletedProcess:
            def __init__(self):
                self.returncode = 0
                self.stdout = "Mock output"
                self.stderr = ""
        return MockCompletedProcess()

    monkeypatch.setattr("subprocess.run", mock_run)

    # Call the function
    misc.update_system()

    # Print the list of commands for debugging
    print("Commands called:", calls)

    # Check that the function called subprocess.run with sudo
    assert 'sudo' in calls

    # Check that the function attempted to update the system
    # The update_system function calls various commands, so we'll check for common ones
    assert any(cmd in ['apt', 'updatedb', 'update', 'upgrade', 'dist-upgrade', 'autoremove', 'autoclean'] for cmd in calls)
