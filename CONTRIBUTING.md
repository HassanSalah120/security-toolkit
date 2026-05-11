# Contributing to PenTestToolkit

## Legal Notice

This toolkit is for **authorized security testing only**. By contributing, you agree that your contributions will be used solely for ethical, authorized security assessments.

## Getting Started

1. Fork the repository
2. Clone your fork
3. Install dependencies: `pip install -r tools/requirements.txt`
4. Create a feature branch: `git checkout -b feature/your-feature`

## Development Guidelines

### Code Style
- Follow PEP 8 where practical
- Use type hints for all function signatures
- Maximum line length: 120 characters
- Use descriptive variable names

### Testing
- All code must pass `python -m py_compile`
- Add tests for new functionality in `tests/`
- Run existing tests before submitting

### CLI Tools
- Use `argparse` for all CLI arguments
- Include `--help` documentation
- Add `--version` flag
- Support `--proxy` for traffic routing through tools like Burp Suite

### Security
- Never hardcode credentials or API keys
- Use `argparse` for secrets (don't read from env unless documented)
- Always handle exceptions gracefully (no bare `except:`)
- Respect rate limits - include delays between requests

### Commit Messages
Follow conventional commits:
- `feat:` new feature
- `fix:` bug fix
- `refactor:` code restructuring
- `docs:` documentation changes
- `test:` test additions/changes
- `chore:` maintenance tasks

## Pull Request Process
1. Update documentation if needed
2. Ensure all syntax checks pass
3. Update `tools/README.md` if adding new tools
4. Submit PR with clear description of changes

## Code of Conduct
- Be respectful and professional
- Focus on technical merit
- No unauthorized testing
