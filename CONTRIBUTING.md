# Contributing to SecurityMind

Thank you for your interest in contributing to SecurityMind! We welcome contributions from the community to help improve this AI-powered security agent. Whether it’s bug fixes, new features, documentation updates, or other enhancements, your help is appreciated.

## Code of Conduct

By participating in this project, you agree to abide by our [Code of Conduct](CODE_OF_CONDUCT.md). Please read it to understand the expectations for respectful and inclusive behavior.

## How to Contribute

### Reporting Bugs

If you find a bug, please open an issue on GitHub with the following details:

- A clear title and description of the bug.
- Steps to reproduce the issue.
- Expected vs. actual behavior.
- Environment details (e.g., Python version, OS, dependencies).
- Screenshots or logs if applicable.

Use the “Bug Report” issue template if available.

### Suggesting Features

For new features or enhancements:

- Open an issue with a descriptive title.
- Explain the problem it solves and why it’s useful.
- Provide mockups, examples, or references if possible.

Use the “Feature Request” issue template.

### Setting Up the Development Environment

1. Fork the repository on GitHub.
2. Clone your fork:
   
   ```
   git clone https://github.com/your-username/securitymind.git
   cd securitymind
   ```
3. Create a virtual environment:
   
   ```
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```
4. Install dependencies:
   
   ```
   pip install -r requirements.txt
   ```
5. Set up environment variables in a `.env` file (see README for details, e.g., `GOOGLE_API_KEY`).
6. Run tests (if available):
   
   ```
   pytest
   ```
7. Run the agent:
   
   ```
   adk web
   ```

### Code Style and Guidelines

- Follow PEP 8 for Python code.
- Use meaningful variable names and add docstrings to functions/tools.
- Ensure code is secure and handles errors gracefully (e.g., API failures).
- Add unit tests for new features/tools using pytest.
- Keep commits atomic and descriptive.

### Submitting Pull Requests

1. Create a branch for your changes:
   
   ```
   git checkout -b feature/your-feature-name
   ```
2. Make your changes and commit them.
3. Push to your fork:
   
   ```
   git push origin feature/your-feature-name
   ```
4. Open a pull request (PR) against the main branch.
- Provide a clear title and description.
- Reference related issues (e.g., “Fixes #123”).
- Ensure all tests pass and the code builds.

PRs will be reviewed by maintainers. We may request changes before merging.

### Documentation

Updates to README.md, CONTRIBUTING.md, or other docs are welcome via PRs. Ensure clarity and use Markdown formatting.

## License

By contributing, you agree that your contributions will be licensed under the [MIT License](LICENSE). You also grant the project maintainers the right to relicense if needed.

## Questions?

If you have questions, open an issue or contact the maintainer via GitHub.

Thank you for contributing to SecurityMind! 🚀