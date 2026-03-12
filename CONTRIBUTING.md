# Contributing to pyghidra-lite

Thank you for considering contributing to pyghidra-lite! This document provides guidelines for contributing to the project.

## How to Contribute

### Reporting Bugs

Found a bug? Please open an issue at:
https://github.com/johnzfitch/pyghidra-lite/issues

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
git clone https://github.com/johnzfitch/pyghidra-lite
cd pyghidra-lite

# Create virtual environment
uv venv
source .venv/bin/activate  # or .venv/Scripts/activate on Windows

# Install in development mode
uv sync --extra dev

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
uv run pytest tests/

# Run specific test
uv run pytest tests/test_server.py

# With coverage
uv run pytest --cov=pyghidra_lite tests/
```

## Adding New Tools

When adding MCP tools:

1. **Token efficiency first**
   - Default to compact output
   - Make verbose output opt-in
   - Truncate large strings
   - Use `include_metadata=False` by default

2. **Follow naming conventions**
   - Keep the public MCP surface consolidated: `load`, `delete`, `binaries`, `info`, `functions`, `code`, `xrefs`, `search`
   - Prefer adding capability-specific behavior behind constrained parameters instead of creating new public tool names

3. **Document parameters**
   - Clear descriptions
   - Mention defaults
   - Explain token implications
   - Publish enum/range constraints in the MCP input schema using type annotations so `tools/list` is precise

4. **Add capability detection**
   - Update `detect_capabilities()` if needed
   - Prefer exposing new behavior through existing `type`, `detail`, `what`, `direction`, or `mode` selectors when possible

5. **Follow MCP error conventions**
   - Let malformed request/schema failures be handled by MCP/FastMCP validation
   - Return semantic input validation and business-rule failures as tool execution errors (`isError: true`), not JSON-RPC `INVALID_PARAMS`

## Documentation

- Update README.md for new features
- Add examples to MCP_RELEASE.md
- Update CHANGELOG.md
- Consider adding to docstrings

## Release Process

Maintainers only:

1. Update version in `pyproject.toml` and `aur/PKGBUILD`
2. Update `CHANGELOG.md`
3. Commit and push to master
4. Create GitHub release: `gh release create v0.x.0`
5. PyPI publish happens automatically via GitHub Actions
6. Update AUR: `cd aur && makepkg --printsrcinfo > .SRCINFO && git push aur master`

## Code of Conduct

- Be respectful and constructive
- Focus on the technical merits
- Welcome newcomers
- Help others learn

## Questions?

Open an issue or discussion at:
https://github.com/johnzfitch/pyghidra-lite/issues

## License

By contributing, you agree that your contributions will be licensed under the MIT License.
