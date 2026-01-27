# Contributing to pyghidra-lite

Thank you for considering contributing to pyghidra-lite! This document provides guidelines for contributing to the project.

## How to Contribute

### Reporting Bugs

Found a bug? Please open an issue at:
https://github.com/zackees/pyghidra-lite/issues

Include:
- Python version
- Ghidra version
- Steps to reproduce
- Expected vs actual behavior
- Error messages/logs

### Suggesting Features

Feature requests are welcome! Please:
- Check existing issues first
- Describe the use case
- Explain why existing tools don't solve it
- Consider token efficiency implications

### Pull Requests

1. **Fork the repository**
2. **Create a feature branch**
   ```bash
   git checkout -b feature/your-feature-name
   ```

3. **Make your changes**
   - Follow existing code style (ruff enforced)
   - Add tests for new features
   - Update documentation

4. **Run quality checks**
   ```bash
   ruff check src/
   ruff format src/
   pytest tests/
   ```

5. **Commit with clear messages**
   ```bash
   git commit -m "Add feature: brief description

   Detailed explanation of what changed and why.
   Addresses #123"
   ```

6. **Push and create PR**
   ```bash
   git push origin feature/your-feature-name
   ```

## Development Setup

```bash
# Clone repository
git clone https://github.com/zackees/pyghidra-lite
cd pyghidra-lite

# Create virtual environment
uv venv
source .venv/bin/activate  # or .venv/Scripts/activate on Windows

# Install in development mode
uv pip install -e ".[dev]"

# Install Ghidra (required)
# Set GHIDRA_INSTALL_DIR environment variable
```

## Code Style

- **Python 3.11+** minimum
- **Type hints** encouraged
- **Ruff** for linting and formatting
- **Line length**: 100 characters
- **Docstrings**: Google style

## Testing

```bash
# Run all tests
pytest tests/

# Run specific test
pytest tests/test_server.py

# With coverage
pytest --cov=pyghidra_lite tests/
```

## Adding New Tools

When adding MCP tools:

1. **Token efficiency first**
   - Default to compact output
   - Make verbose output opt-in
   - Truncate large strings
   - Use `include_metadata=False` by default

2. **Follow naming conventions**
   - Verb-noun format: `list_functions`, `get_xrefs`
   - Format-specific prefix: `elf_`, `macho_`, `swift_`, `objc_`

3. **Document parameters**
   - Clear descriptions
   - Mention defaults
   - Explain token implications

4. **Add capability detection**
   - Update `detect_capabilities()` if needed
   - Add to `_available_tools()` list

## Documentation

- Update README.md for new features
- Add examples to MCP_RELEASE.md
- Update CHANGELOG.md
- Consider adding to docstrings

## Release Process

Maintainers only:

1. Update version in `pyproject.toml`
2. Update CHANGELOG.md
3. Create git tag: `git tag v0.x.0`
4. Push: `git push --tags`
5. Build: `python -m build`
6. Publish: `twine upload dist/*`

## Code of Conduct

- Be respectful and constructive
- Focus on the technical merits
- Welcome newcomers
- Help others learn

## Questions?

Open an issue or discussion at:
https://github.com/zackees/pyghidra-lite/issues

## License

By contributing, you agree that your contributions will be licensed under the MIT License.
