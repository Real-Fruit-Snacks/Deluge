# Contributing to Deluge 🛡️

First off, thank you for considering contributing to Deluge! It's people like you that make Deluge such a great tool for the security community.

Deluge is a transformation layer for Nmap and RustScan outputs, and we welcome contributions that improve its parsing capabilities, formatting, or overall user experience.

---

## 🚀 Setting Up Your Development Environment

To start contributing, you'll need to set up a local development environment.

### 1. Prerequisites
- **Python 3.8+**
- **Nmap 7.90+** (required for testing interactive mode)
- **Git**

### 2. Clone the Repository
```bash
git clone https://github.com/Real-Fruit-Snacks/Deluge.git
cd deluge
```

### 3. Create a Virtual Environment
We recommend using a virtual environment to keep dependencies isolated.

**Windows:**
```cmd
python -m venv venv
venv\Scripts\activate
```

**Linux/macOS:**
```bash
python3 -m venv venv
source venv/bin/activate
```

### 4. Install Dependencies
Install the project in editable mode with development dependencies:
```bash
pip install -e .
pip install -r requirements.txt
pip install pytest pytest-cov
```

---

## 🧪 Running Tests

We use `pytest` for our testing suite. Please ensure all tests pass before submitting a pull request.

```bash
# Run all tests
pytest

# Run with coverage report
pytest --cov=deluge

# Run specific test file
pytest tests/test_parsers.py
```

---

## 🎨 Code Style Guidelines

To maintain a clean and consistent codebase, please follow these guidelines:

- **PEP 8**: Follow standard Python coding conventions.
- **Type Hints**: Use Python type hints for all function signatures.
- **Pydantic**: Use Pydantic v2 models for data structures (see `deluge/core/models.py`).
- **Docstrings**: Provide clear docstrings for modules, classes, and functions.
- **Rich**: Use the `Rich` library for terminal output to maintain the project's visual style.

---

## 🏗️ Project Structure Overview

Understanding the directory structure will help you find where to make changes:

- `deluge/core/`: Core business logic (engine, models, exports, utils).
- `deluge/parsers/`: The parser suite. New parsers should be added here.
- `deluge/interface/`: Presentation layer (CLI handling and Rich formatting).
- `tests/`: Test suite using `pytest`.
- `samples/`: Sample scan files used for testing and development.

---

## 📥 How to Submit a Pull Request

1. **Fork** the repository on GitHub.
2. **Create a branch** for your changes: `git checkout -b feature/your-feature-name` or `fix/your-bug-fix`.
3. **Make your changes** and ensure they follow the code style guidelines.
4. **Add tests** for any new functionality or bug fixes.
5. **Run the test suite** to ensure everything is working correctly.
6. **Commit your changes**: `git commit -m 'Add some amazing feature'`.
7. **Push to your fork**: `git push origin feature/your-feature-name`.
8. **Open a Pull Request** against the `main` branch of the original repository.

---

## 🪲 Reporting Bugs & Requesting Features

We use GitHub Issues to track bugs and feature requests.

- **Report a Bug**: If you find a bug, please [open an issue](https://github.com/Real-Fruit-Snacks/Deluge/issues) using the "Bug Report" template.
- **Request a Feature**: Have an idea for a new feature? [Open an issue](https://github.com/Real-Fruit-Snacks/Deluge/issues) using the "Feature Request" template.

---

## 📜 License

By contributing to Deluge, you agree that your contributions will be licensed under the project's [MIT License](LICENSE).
