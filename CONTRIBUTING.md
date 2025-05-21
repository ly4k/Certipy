# 🤝 Contributing to Certipy

Thank you for your interest in contributing to **Certipy**! Whether you're reporting a bug, improving documentation, or submitting a pull request - your help is appreciated.

---

## 📋 Issues

Please use the appropriate issue template when opening a new issue:

- 🐞 **Bug Reports**: Include the version, OS, the exact command used (redacted if needed), error output, and any relevant `certipy find` info.
- 🙋 **Help Requests**: For general questions or clarification on usage, not tied to a specific error.
- ✨ **Feature Requests**: Describe the feature, your use case, and any alternatives or examples.

👉 Issue templates will guide you when you [open an issue](https://github.com/ly4k/Certipy/issues/new/choose).

---

## 🧑‍💻 Code Contributions

### 🧼 Code Style

Certipy uses:

- [`black`](https://black.readthedocs.io/) for code formatting
- [`isort`](https://pycqa.github.io/isort/) for import sorting (configured for black compatibility)
- [`pyright`](https://github.com/microsoft/pyright) for type checking
- [`flake8`](https://flake8.pycqa.org/en/latest/) for linting

### 🛠 Development Setup

```bash
# Setup virtual environment
python3 -m venv venv
source venv/bin/activate

# Install dev dependencies
pip install -e .
pip install black isort pyright flake8 pep8-naming
````

### 🔍 Code Quality Checks (before committing)

```bash
flake8 ./certipy && isort . && black . && pyright
```

---

## ✅ Submitting Pull Requests

1. Fork the repo and create a branch:
   `git checkout -b feature/my-feature-name`
2. Follow the coding standards above
3. Keep PRs small and focused
4. Include a brief description of **why** the change is useful
5. Link to any relevant issues (e.g., `Fixes #123`)
6. Run tests (if applicable)
7. Explain how to test the changes, setting up the environment, and any dependencies
8. Submit your PR for review!

---

## 📘 Contributing to the Wiki

You can help improve the documentation! To do so:

- Clone the wiki repo directly:

  ```bash
  git clone https://github.com/ly4k/Certipy.wiki.git
  ```

- Make your changes in `*.md` files (e.g., `ESC1.md`, `Home.md`)
- Submit a pull request or send a patch if you're not a collaborator
- Use Markdown preview tools (like VSCode or `grip`) to review your changes

> [!TIP]
> For private drafts, maintain a local folder or branch and sync it later to the public `.wiki.git`.

---

## 💬 Need Help?

Feel free to open a [Help Request](https://github.com/ly4k/Certipy/issues/new/choose) - just be clear about what you’re trying to accomplish and what you’ve tried.

---

Thanks again for supporting Certipy!

– [@ly4k](https://github.com/ly4k)
