"""
Tests for the recon module.

This file contains tests for the recon module of the Discover Framework.
"""

import os
import pytest
from pathlib import Path
from modules import recon

def test_passive_recon_function_exists():
    """Test that the passive_recon function exists."""
    assert hasattr(recon, 'passive_recon')
    assert callable(recon.passive_recon)

def test_find_registered_domains_function_exists():
    """Test that the find_registered_domains function exists."""
    assert hasattr(recon, 'find_registered_domains')
    assert callable(recon.find_registered_domains)

def test_person_recon_function_exists():
    """Test that the person_recon function exists."""
    assert hasattr(recon, 'person_recon')
    assert callable(recon.person_recon)

def test_passive_recon_root_check(monkeypatch):
    """Test that passive_recon checks if running as root."""
    # Mock os.geteuid to return 0 (root)
    monkeypatch.setattr("os.geteuid", lambda: 0)
    
    # Mock print to capture output
    printed_messages = []
    monkeypatch.setattr("builtins.print", lambda *args: printed_messages.append(" ".join(map(str, args))))
    
    # Call the function
    recon.passive_recon()
    
    # Check that the function printed the error message
    assert any("This script cannot be ran as root" in msg for msg in printed_messages)

def test_passive_recon_firefox_check(monkeypatch, mock_subprocess_run):
    """Test that passive_recon checks if Firefox is running."""
    # Mock os.geteuid to return 1000 (non-root)
    monkeypatch.setattr("os.geteuid", lambda: 1000)
    
    # Mock subprocess.run to simulate Firefox running
    def mock_run(*args, **kwargs):
        if args[0][0] == 'pgrep' and args[0][1] == 'firefox':
            class MockCompletedProcess:
                def __init__(self):
                    self.returncode = 0
                    self.stdout = b"1234\n"
            return MockCompletedProcess()
        return mock_subprocess_run(*args, **kwargs)
    
    monkeypatch.setattr("subprocess.run", mock_run)
    
    # Mock print to capture output
    printed_messages = []
    monkeypatch.setattr("builtins.print", lambda *args: printed_messages.append(" ".join(map(str, args))))
    
    # Call the function
    recon.passive_recon()
    
    # Check that the function printed the error message
    assert any("Close Firefox before running script" in msg for msg in printed_messages)

def test_find_registered_domains_invalid_file(monkeypatch):
    """Test that find_registered_domains checks for a valid file."""
    # Mock input to return an invalid file path
    monkeypatch.setattr("builtins.input", lambda _: "/path/to/nonexistent/file")
    
    # Mock os.path.isfile to return False
    monkeypatch.setattr("os.path.isfile", lambda _: False)
    
    # Mock print to capture output
    printed_messages = []
    monkeypatch.setattr("builtins.print", lambda *args: printed_messages.append(" ".join(map(str, args))))
    
    # Call the function
    recon.find_registered_domains()
    
    # Check that the function printed the error message
    assert any("Invalid choice or entry" in msg for msg in printed_messages)

def test_person_recon_invalid_input(monkeypatch):
    """Test that person_recon checks for valid input."""
    # Mock input to return empty strings
    inputs = iter(["", ""])
    monkeypatch.setattr("builtins.input", lambda _: next(inputs))
    
    # Mock print to capture output
    printed_messages = []
    monkeypatch.setattr("builtins.print", lambda *args: printed_messages.append(" ".join(map(str, args))))
    
    # Call the function
    recon.person_recon()
    
    # Check that the function printed the error message
    assert any("Invalid choice or entry" in msg for msg in printed_messages)