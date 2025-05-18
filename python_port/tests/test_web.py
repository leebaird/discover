"""
Tests for the web module.

This file contains tests for the web module of the Discover Framework.
"""

import os
import pytest
from pathlib import Path
from modules import web

def test_direct_object_ref_function_exists():
    """Test that the direct_object_ref function exists."""
    assert hasattr(web, 'direct_object_ref')
    assert callable(web.direct_object_ref)

def test_multi_tabs_function_exists():
    """Test that the multi_tabs function exists."""
    assert hasattr(web, 'multi_tabs')
    assert callable(web.multi_tabs)

def test_nikto_scan_function_exists():
    """Test that the nikto_scan function exists."""
    assert hasattr(web, 'nikto_scan')
    assert callable(web.nikto_scan)

def test_ssl_check_function_exists():
    """Test that the ssl_check function exists."""
    assert hasattr(web, 'ssl_check')
    assert callable(web.ssl_check)

def test_direct_object_ref_invalid_file(monkeypatch):
    """Test that direct_object_ref checks for a valid file."""
    # Mock input to return an invalid file path
    monkeypatch.setattr("builtins.input", lambda _: "/path/to/nonexistent/file")
    
    # Mock os.path.isfile to return False
    monkeypatch.setattr("os.path.isfile", lambda _: False)
    
    # Mock print to capture output
    printed_messages = []
    monkeypatch.setattr("builtins.print", lambda *args: printed_messages.append(" ".join(map(str, args))))
    
    # Call the function
    web.direct_object_ref()
    
    # Check that the function printed the error message
    assert any("Invalid choice or entry" in msg for msg in printed_messages)

def test_multi_tabs_display_check(monkeypatch):
    """Test that multi_tabs checks for a display."""
    # Mock os.environ.get to return None for DISPLAY
    monkeypatch.setattr("os.environ.get", lambda key, default=None: None if key == 'DISPLAY' else default)
    
    # Mock print to capture output
    printed_messages = []
    monkeypatch.setattr("builtins.print", lambda *args: printed_messages.append(" ".join(map(str, args))))
    
    # Call the function
    web.multi_tabs()
    
    # Check that the function printed the error message
    assert any("This option must be ran locally" in msg for msg in printed_messages)

def test_multi_tabs_invalid_choice(monkeypatch):
    """Test that multi_tabs handles invalid choices."""
    # Mock os.environ.get to return a value for DISPLAY
    monkeypatch.setattr("os.environ.get", lambda key, default=None: "dummy" if key == 'DISPLAY' else default)
    
    # Mock input to return an invalid choice
    monkeypatch.setattr("builtins.input", lambda _: "invalid")
    
    # Mock print to capture output
    printed_messages = []
    monkeypatch.setattr("builtins.print", lambda *args: printed_messages.append(" ".join(map(str, args))))
    
    # Mock multi_tabs to avoid recursion
    original_multi_tabs = web.multi_tabs
    call_count = [0]
    
    def mock_multi_tabs():
        call_count[0] += 1
        if call_count[0] == 1:
            return original_multi_tabs()
        return None
    
    monkeypatch.setattr(web, "multi_tabs", mock_multi_tabs)
    
    # Call the function
    web.multi_tabs()
    
    # Check that the function printed the error message
    assert any("Invalid choice or entry" in msg for msg in printed_messages)

def test_nikto_scan_root_check(monkeypatch):
    """Test that nikto_scan checks if running as root."""
    # Mock os.geteuid to return 0 (root)
    monkeypatch.setattr("os.geteuid", lambda: 0)
    
    # Mock print to capture output
    printed_messages = []
    monkeypatch.setattr("builtins.print", lambda *args: printed_messages.append(" ".join(map(str, args))))
    
    # Call the function
    web.nikto_scan()
    
    # Check that the function printed the error message
    assert any("This option cannot be ran as root" in msg for msg in printed_messages)

def test_ssl_check_invalid_file(monkeypatch):
    """Test that ssl_check checks for a valid file."""
    # Mock input to return an invalid file path
    monkeypatch.setattr("builtins.input", lambda _: "/path/to/nonexistent/file")
    
    # Mock os.path.isfile to return False
    monkeypatch.setattr("os.path.isfile", lambda _: False)
    
    # Mock print to capture output
    printed_messages = []
    monkeypatch.setattr("builtins.print", lambda *args: printed_messages.append(" ".join(map(str, args))))
    
    # Call the function
    web.ssl_check()
    
    # Check that the function printed the error message
    assert any("Invalid choice or entry" in msg for msg in printed_messages)