# Discover Framework - Python Port

This is a Python port of the Discover Framework, originally written in Bash by Lee Baird (@discoverscripts).

## Overview

The Discover Framework is a collection of security testing tools for reconnaissance, scanning, enumeration, and malicious payload creation. This Python port maintains all the functionality of the original framework while improving maintainability, extensibility, and reducing the number of files.

## Features

- **Python 3.12 Features**: Utilizes the latest Python features for improved performance and code clarity:
  - Type hints throughout the code for better IDE support and code clarity
  - Structural pattern matching (match-case) for cleaner menu handling
  - Pathlib for more intuitive file path operations
  - Context managers for safer file operations
  - Exception handling with specific exception types
  - Improved docstrings with detailed parameter and return type documentation

- **Modular Architecture**: The framework is organized into modules for different types of functionality.
- **Consolidated Files**: Related functionality has been consolidated into fewer files.
- **Improved Error Handling**: Better error handling and reporting.
- **Cross-Platform Compatibility**: Designed to work on multiple platforms, not just Kali Linux.
- **Comprehensive Testing**: Includes unit tests for all modules and functions.

## Directory Structure

```
python_port/
├── discover.py           # Main entry point
├── modules/
│   ├── __init__.py       # Package initialization
│   ├── scanning.py       # Scanning functionality
│   ├── recon.py          # Reconnaissance functionality
│   ├── web.py            # Web testing functionality
│   └── misc.py           # Miscellaneous utilities
├── parsers/              # XML and other format parsers
│   ├── __init__.py       # Package initialization
│   ├── parse-burp.py     # Burp Suite XML parser
│   ├── parse-nessus.py   # Nessus XML parser
│   ├── parse-nexpose.py  # Nexpose XML parser
│   ├── parse-nmap.py     # Nmap XML parser
│   ├── parse-qualys.py   # Qualys XML parser
│   └── utfdictcsv.py     # UTF-8 CSV writer utility
├── tests/                # Unit tests
│   ├── conftest.py       # Pytest configuration
│   ├── test_scanning.py  # Tests for scanning module
│   ├── test_recon.py     # Tests for recon module
│   ├── test_web.py       # Tests for web module
│   └── test_misc.py      # Tests for misc module
├── pyproject.toml        # Project configuration and dependencies
└── README.md             # This file
```

## Installation

### Option 1: Install from Source

1. Clone the repository:
   ```
   git clone https://github.com/leebaird/discover.git
   cd discover/python_port
   ```

2. Install the package in development mode:
   ```
   pip install -e .
   ```

3. Install development dependencies (optional):
   ```
   pip install -e ".[dev]"
   ```

### Option 2: Install from PyPI (Not yet available)

```
pip install discover-framework
```

## Usage

1. If installed via pip, run the command:
   ```
   discover
   ```

2. Or run the script directly:
   ```
   python3 discover.py
   ```

3. Follow the on-screen menu to select the desired functionality.

## Modules

### Scanning Module

The scanning module provides functionality for scanning targets, including CIDR ranges, lists of targets, and single IPs or URLs. It includes:

- CIDR scanning
- List scanning
- Single IP/range/URL scanning
- Port enumeration
- Target generation

### Reconnaissance Module

The reconnaissance module provides functionality for gathering information about domains and people. It includes:

- Passive reconnaissance
- Finding registered domains
- Person reconnaissance

### Web Module

The web module provides functionality for web-related testing. It includes:

- Insecure direct object reference testing
- Opening multiple tabs in Firefox
- Nikto scanning
- SSL checking

### Miscellaneous Module

The miscellaneous module provides various utilities. It includes:

- XML parsing (Burp, Nessus, Nexpose, Nmap, Qualys)
- Malicious payload generation
- Metasploit listener setup
- System updates
- Sensitive information detection
- API security scanning
- OAuth/JWT security testing
- Cloud security scanning (AWS, Azure, GCP)
- Container security scanning (Docker, Kubernetes)
- MSF web and API security scanning

## Testing

The Python port includes comprehensive unit tests for all modules and functions. To run the tests:

```
cd python_port
pytest
```

## Project Configuration

The project uses a `pyproject.toml` file for configuration, following the modern Python packaging standards (PEP 518 and PEP 621). This file includes:

- Build system requirements (setuptools, wheel)
- Project metadata (name, version, description, authors, etc.)
- Dependencies (beautifulsoup4, lxml, html2text, ipaddress)
- Development dependencies (pytest, pytest-cov, black, isort, mypy)
- Tool-specific configurations (pytest, black, isort)

This approach provides a single configuration file for all aspects of the project, making it easier to maintain and extend.

## Requirements

- Python 3.12 or higher
- Various command-line tools (installed automatically by the update function)
- Python dependencies (installed automatically via pip)

## Python 3.12 Features Used

- **Type Hints**: All functions include type hints for parameters and return values, improving code readability and IDE support.
- **Structural Pattern Matching**: The `match-case` statement is used for cleaner menu handling and input processing.
- **Pathlib**: The `pathlib` module is used for more intuitive file path operations.
- **Context Managers**: Context managers (`with` statements) are used for safer file operations.
- **Exception Handling**: Specific exception types are caught and handled appropriately.
- **F-strings**: F-strings are used for more readable string formatting.
- **Walrus Operator**: The walrus operator (`:=`) is used where appropriate to simplify code.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Acknowledgments

- Lee Baird (@discoverscripts) - Original author of the Discover Framework
- Jay Townsend (@jay_townsend1) - Conversion from Backtrack to Kali
- Jason Ashton (@ninewires) - PTF compatibility, bug crusher, and bash ninja
- All other contributors to the original Discover Framework
