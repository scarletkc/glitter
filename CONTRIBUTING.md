# Contributing to Glitter

First off, thank you for considering contributing to Glitter! It's people like you that make Glitter such a great tool for secure peer-to-peer file transfers.

## Table of Contents

- [Contributing to Glitter](#contributing-to-glitter)
  - [Table of Contents](#table-of-contents)
  - [Code of Conduct](#code-of-conduct)
  - [How Can I Contribute?](#how-can-i-contribute)
    - [Reporting Bugs](#reporting-bugs)
    - [Suggesting Enhancements](#suggesting-enhancements)
    - [Your First Code Contribution](#your-first-code-contribution)
    - [Pull Requests](#pull-requests)
  - [Development Setup](#development-setup)
    - [Prerequisites](#prerequisites)
    - [Setup Steps](#setup-steps)
    - [Building](#building)
  - [Style Guidelines](#style-guidelines)
    - [Git Commit Messages](#git-commit-messages)
    - [Python Style Guide](#python-style-guide)
    - [Documentation Style Guide](#documentation-style-guide)
  - [Testing Guidelines](#testing-guidelines)
    - [Running Tests](#running-tests)
    - [Writing Tests](#writing-tests)
    - [Coverage Goals](#coverage-goals)
  - [Additional Notes](#additional-notes)
    - [Project Structure](#project-structure)
    - [Security Considerations](#security-considerations)
    - [Localization](#localization)
    - [Getting Help](#getting-help)
    - [Recognition](#recognition)

## Code of Conduct

This project and everyone participating in it is governed by a commitment to providing a welcoming and inclusive environment. By participating, you are expected to uphold this standard. Please be respectful and constructive in all interactions.

## How Can I Contribute?

### Reporting Bugs

Before creating bug reports, please check the existing issues to avoid duplicates. When you create a bug report, include as many details as possible:

**How to Submit a Good Bug Report:**

- **Use a clear and descriptive title** for the issue
- **Describe the exact steps to reproduce the problem** with as much detail as possible
- **Provide specific examples** to demonstrate the steps
- **Describe the behavior you observed** and what behavior you expected to see
- **Include screenshots or logs** if applicable
- **Specify your environment:**
  - OS (Windows, macOS, Linux distribution)
  - Python version
  - Glitter version
  - Installation method (pip, standalone binary, from source)

**Example:**
```markdown
**Environment:**
- OS: Ubuntu 22.04
- Python: 3.11.5
- Glitter: 1.0.0 (installed via pip)

**Steps to Reproduce:**
1. Run `glitter`
2. Select discovered peer
3. File transfer starts but hangs at 50%

**Expected:** File should transfer completely
**Actual:** Transfer hangs indefinitely
```

### Suggesting Enhancements

Enhancement suggestions are tracked as GitHub issues. When creating an enhancement suggestion:

- **Use a clear and descriptive title**
- **Provide a detailed description** of the proposed enhancement
- **Explain why this enhancement would be useful** to most users
- **List any similar features** in other tools if applicable
- **Provide examples** of how the feature would be used

### Your First Code Contribution

Unsure where to begin? Look for issues labeled:

- `good first issue` - Good for newcomers
- `help wanted` - Extra attention needed
- `documentation` - Documentation improvements

### Pull Requests

Follow these steps to submit a pull request:

1. **Fork the repository** and create your branch from `main`
2. **Make your changes** following the style guidelines
3. **Add tests** if you've added code that should be tested
4. **Update documentation** for user-visible changes
5. **Ensure the test suite passes** locally
6. **Submit a pull request** with a clear description

**Pull Request Guidelines:**

- Link to related issues using keywords (e.g., `Fixes #123`, `Closes #456`)
- Include a clear description of:
  - What the PR does
  - Why the change is needed
  - How it's been tested
- Provide before/after examples for CLI changes
- Update both English and Chinese localized messages in `glitter/language.py` if applicable
- Keep PRs focused - one feature/fix per PR when possible

**Example PR Description:**
```markdown
## Description
Adds device name support to the send command, allowing users to specify a friendly name for their device.

## Related Issue
Fixes #42

## Changes
- Added flag to send command
- Updated discovery protocol
- Updated UI to display 

## Testing
- Added unit tests 
- Tested manually on Windows and Linux
- Verified backward compatibility with older versions

## Screenshots
Before: 
After: 
```

## Development Setup

### Prerequisites

- Python 3.9 or higher
- pip
- Git

### Setup Steps

1. **Clone your fork:**
   ```bash
   git clone https://github.com/scarletkc/glitter.git
   cd glitter
   ```

2. **Create a virtual environment:**
   ```bash
   python -m venv .venv
   
   # On Windows
   .venv\Scripts\activate
   
   # On macOS/Linux
   source .venv/bin/activate
   ```

3. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   pip install -e .
   ```

4. **Verify installation:**
   ```bash
   glitter --version
   python -m pytest -q
   ```

### Building

- **Build distribution packages:**
  ```bash
  python -m build
  ```

- **Build standalone binary:**
  ```bash
  pyinstaller glitter.spec
  ```

## Style Guidelines

### Git Commit Messages

- Use imperative mood ("Add feature" not "Added feature")
- Keep subject line under 50 characters
- Separate subject from body with blank line
- Use body to explain what and why, not how

**Good:**
```
Add device name support in send command

Users can now specify a friendly device name that appears
during peer discovery. This improves UX when multiple
devices are available on the network.
```

**Bad:**
```
added some stuff to make device names work
```

### Python Style Guide

- Follow PEP 8 conventions
- Use 4-space indentation (no tabs)
- Maximum line length: 100 characters (flexible)
- Use type hints for function parameters and return values
- Write docstrings for modules, classes, and functions
- Use `snake_case` for functions and variables
- Use `PascalCase` for classes
- Use `UPPER_SNAKE_CASE` for constants
- Run `ruff check .` for lint and `black .` for formatting when touching Python files (recommended before submitting a PR)

**Example:**
```python
def calculate_transfer_rate(bytes_transferred: int, duration: float) -> float:
    """Calculate transfer rate in bytes per second.
    
    Args:
        bytes_transferred: Total bytes transferred
        duration: Time elapsed in seconds
        
    Returns:
        Transfer rate in bytes/second
        
    Raises:
        ValueError: If duration is zero or negative
    """
    if duration <= 0:
        raise ValueError("Duration must be positive")
    return bytes_transferred / duration
```

### Documentation Style Guide

- Use Markdown for all documentation
- Keep line length reasonable (80-100 characters)
- Use code blocks with language specifiers
- Include examples for CLI commands
- Update both `README.md` and relevant docs in `docs/`
- Update both English and Chinese documentation when applicable
- For user-visible strings, ensure both locales exist in `glitter/language.py` and use `get_message()` / `render_message()` in the code so the `TerminalUI` renders localized output consistently

## Testing Guidelines

### Running Tests

```bash
# Run all tests
python -m pytest

# Run with coverage
python -m pytest --cov=glitter

# Run specific test file
python -m pytest tests/unit/test_security_helpers.py

# Run tests matching pattern
python -m pytest -k "test_encrypt"
```

### Writing Tests

- Place unit tests in `tests/unit/`
- Place integration tests in `tests/integration/`
- Use descriptive test names: `test_<function>_<scenario>_<expected_result>`
- Keep tests isolated and deterministic
- Mock external dependencies (network, filesystem when appropriate)
- For socket-heavy tests (discovery/transfer), prefer loopback connections or fakes so they work in CI without special permissions; skip responsibly if the environment lacks required capabilities
- Aim for fast tests (< 1s per test)

**Example:**
```python
def test_encrypt_decrypt_roundtrip_preserves_data():
    """Test that encrypting and decrypting returns original data."""
    original = b"Hello, World!"
    key = generate_key()
    
    encrypted = encrypt(original, key)
    decrypted = decrypt(encrypted, key)
    
    assert decrypted == original
    assert encrypted != original  # Ensure it was actually encrypted
```

### Coverage Goals

- Aim for >50% code coverage
- Focus on critical paths (security, transfer, discovery)
- Don't sacrifice test quality for coverage percentage

## Additional Notes

### Project Structure

- Root directories of note:
  - `glitter/` — Source package (see key modules below)
  - `assets/` — Branding assets (logo, etc.)
  - `docs/` — Extended documentation
  - `.github/workflows/` — CI definitions (PyPI, binaries)
  - `build/` + `dist/` — Generated build artifacts (should be clean in commits)
  - `glitter.spec` — PyInstaller spec for standalone builds
- Key modules under `glitter/`:
  - `cli.py` — Command-line interface and argument parsing
  - `app.py` — Discovery/transfer orchestrator
  - `transfer.py` — File transfer logic with encryption
  - `security.py` — Cryptographic operations
  - `discovery.py` — Peer discovery via UDP
  - `trust.py` — Trust-on-first-use key management
  - `history.py` — Transfer history tracking (JSONL)
  - `language.py` — Internationalization (i18n)
  - `ui.py` — Terminal UI built on `rich`
  - `config.py` — Configuration management
  - `utils.py` — Miscellaneous utilities

### Security Considerations

- Never log or expose full cryptographic keys
- Use secure defaults for all cryptographic operations
- Validate all user inputs
- Be cautious with file paths (prevent path traversal)
- Document security implications of changes
- Persist configuration, trust store, and history only under `~/.glitter/`
- Default ports: UDP 45845 (discovery) and TCP 45846 (transfer); document any changes and consider firewall notes
- Use `GLITTER_DEBUG=1` for troubleshooting output, but never gate core logic on debug mode

### Localization

When adding user-visible messages:

1. Add the message key to `glitter/language.py`
2. Provide both English and Chinese translations
3. Use `get_message()` or `render_message()` to retrieve messages
4. Test with both locales

### Getting Help

- **Questions?** Open a GitHub Discussion or issue
- **Chat:** Check if the project has a Discord/Slack (if applicable)
- **Email:** Contact maintainers (see README)

### Recognition

Contributors will be acknowledged in release notes and the project README. Thank you for your contributions!

---

**Happy Contributing!**

If you have questions about the contribution process, feel free to ask by opening an issue.
