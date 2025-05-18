"""
Pytest configuration file for the Discover Framework.

This file contains fixtures and configuration for pytest.
"""

import os
import sys
import pytest
from pathlib import Path

# Add the parent directory to sys.path to allow importing modules
sys.path.insert(0, str(Path(__file__).parent.parent))

@pytest.fixture
def temp_dir(tmp_path):
    """
    Create a temporary directory for tests.
    
    Args:
        tmp_path: Pytest fixture that provides a temporary directory
        
    Returns:
        Path: Path to the temporary directory
    """
    return tmp_path

@pytest.fixture
def mock_subprocess_run(monkeypatch):
    """
    Mock subprocess.run to avoid executing actual commands during tests.
    
    Args:
        monkeypatch: Pytest fixture for patching
        
    Returns:
        None
    """
    class MockCompletedProcess:
        def __init__(self, returncode=0, stdout="", stderr=""):
            self.returncode = returncode
            self.stdout = stdout
            self.stderr = stderr
    
    def mock_run(*args, **kwargs):
        return MockCompletedProcess(stdout="Mock output")
    
    monkeypatch.setattr("subprocess.run", mock_run)
    
    # Also mock Popen for cases where it's used directly
    class MockPopen:
        def __init__(self, *args, **kwargs):
            self.returncode = 0
            
        def communicate(self, input=None):
            return (b"Mock stdout", b"Mock stderr")
            
        def wait(self):
            return 0
            
        def terminate(self):
            pass
    
    monkeypatch.setattr("subprocess.Popen", MockPopen)