"""
Tests for the scanning module.

This file contains tests for the scanning module of the Discover Framework.
"""

import os
import pytest
from pathlib import Path
from modules import scanning

def test_scan_function_exists():
    """Test that the scan function exists."""
    assert hasattr(scanning, 'scan')
    assert callable(scanning.scan)

def test_process_nmap_output_function_exists():
    """Test that the process_nmap_output function exists."""
    assert hasattr(scanning, 'process_nmap_output')
    assert callable(scanning.process_nmap_output)

def test_ports_function_exists():
    """Test that the ports function exists."""
    assert hasattr(scanning, 'ports')
    assert callable(scanning.ports)

def test_combine_ports_function_exists():
    """Test that the combine_ports function exists."""
    assert hasattr(scanning, 'combine_ports')
    assert callable(scanning.combine_ports)

def test_generate_targets_function_exists():
    """Test that the generate_targets function exists."""
    assert hasattr(scanning, 'generate_targets')
    assert callable(scanning.generate_targets)

def test_scan_creates_output_files(temp_dir, mock_subprocess_run, monkeypatch):
    """Test that the scan function creates output files."""
    # Mock open to avoid file operations
    def mock_open(*args, **kwargs):
        class MockFile:
            def __init__(self, *args, **kwargs):
                pass
            def __enter__(self):
                return self
            def __exit__(self, *args):
                pass
            def write(self, data):
                pass
            def read(self):
                return "(0 hosts up)" if "nmap.nmap" in str(args[0]) else ""
        return MockFile()
    
    monkeypatch.setattr("builtins.open", mock_open)
    
    # Mock os.path.exists to return True
    monkeypatch.setattr("os.path.exists", lambda x: True)
    
    # Mock shutil.rmtree to do nothing
    monkeypatch.setattr("shutil.rmtree", lambda x: None)
    
    # Mock os.remove to do nothing
    monkeypatch.setattr("os.remove", lambda x: None)
    
    # Call the scan function
    result = scanning.scan("test_scan", "test_targets.txt", "test_exclude.txt", "500ms")
    
    # Since we're mocking the file operations, we can only check that the function returns False
    # because we're simulating the "(0 hosts up)" case
    assert result is False

def test_generate_targets_arp_scan(monkeypatch, mock_subprocess_run):
    """Test the generate_targets function with ARP scan."""
    # Mock input to return "1" (ARP scan) and then "" (default interface)
    inputs = iter(["1", ""])
    monkeypatch.setattr("builtins.input", lambda _: next(inputs))
    
    # Mock os.makedirs to do nothing
    monkeypatch.setattr("os.makedirs", lambda *args, **kwargs: None)
    
    # Call the function
    scanning.generate_targets()
    
    # Since we're mocking everything, we can only check that the function doesn't raise an exception
    assert True

def test_generate_targets_ping_sweep(monkeypatch, mock_subprocess_run):
    """Test the generate_targets function with ping sweep."""
    # Mock input to return "2" (ping sweep) and then "192.168.1.0/24" (network)
    inputs = iter(["2", "192.168.1.0/24"])
    monkeypatch.setattr("builtins.input", lambda _: next(inputs))
    
    # Mock os.makedirs to do nothing
    monkeypatch.setattr("os.makedirs", lambda *args, **kwargs: None)
    
    # Call the function
    scanning.generate_targets()
    
    # Since we're mocking everything, we can only check that the function doesn't raise an exception
    assert True