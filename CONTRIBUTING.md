# Contributing to BlueTeam / Agentix

Thank you for your interest in contributing to the BlueTeam / Agentix platform! We welcome community contributions to help improve security agents, add integrations, and enhance our documentation.

Please review this document to understand our development workflow, coding standards, and repository guidelines.

---

## 🗺️ Code Contribution Workflow

We follow a standard GitHub Fork-and-Pull request model:

1. **Fork the Repository**: Create a personal copy of the repository on GitHub.
2. **Clone Locally**: Clone your fork to your workstation:
   ```bash
   git clone https://github.com/your-username/blueTeam.git
   cd blueTeam
   ```
3. **Create a Feature Branch**: Use a descriptive branch name prefixing the type of change:
   - `feat/new-mcp-tool`
   - `fix/path-traversal-validation`
   - `docs/setup-guide-update`
4. **Implement Your Changes**: Write clean, test-covered code.
5. **Run Local Checks**: Ensure linting, formatting, types, and tests pass (see [Code Quality Standards](#-code-quality-standards)).
6. **Commit with Conventional Commits**: Make clear, structured commits (see [Commit Conventions](#-commit-conventions)).
7. **Push & Open PR**: Push your branch to GitHub and create a Pull Request to the `main` branch of the upstream repository.

---

## 🎨 Code Quality Standards

We enforce strict automated checks on pull requests to maintain code health. Please run these locally before pushing:

### 1. Formatting and Linting (Ruff)
We use Ruff for linting and formatting. Run these commands from the root directory:
```bash
# Check for lint errors
uv run ruff check .

# Automatically apply safe fixes
uv run ruff check . --fix

# Verify format rules (Ruff format is compatible with Black)
uv run ruff format --check .
```

### 2. Static Type Checks (Mypy)
We use Mypy for static type checking across the Python packages. Ensure all functions have proper type hints:
```bash
uv run mypy src/Agentix src/TriageCore src/AgenticCommon
```

### 3. Unit and Integration Tests (Pytest)
Write tests for any new tools, agents, or client wrappers. To run all unit tests:
```bash
uv run pytest src/Agentix/tests src/TriageCore/tests
```

---

## 📝 Commit Conventions

We follow the [Conventional Commits](https://www.conventionalcommits.org/en/v1.0.0/) specification. This helps us generate clean changelogs and automate version numbers.

Commit message format:
`<type>(<scope>): <description>`

### Allowed Types:
- `feat`: A new feature or tool capability.
- `fix`: A bug fix (e.g. fixing an API query or exception handler).
- `docs`: Documentation updates only.
- `style`: Changes that do not affect the meaning of the code (formatting, white-space, missing semi-colons, etc.).
- `refactor`: A code change that neither fixes a bug nor adds a feature.
- `test`: Adding missing tests or correcting existing tests.
- `chore`: Updating build tasks, package dependencies, or CI config.

### Examples:
- `feat(tool): add Suricata alert query to TriageCore`
- `fix(core): resolve path traversal edge case in SessionWorkspace`
- `docs(readme): update quickstart command syntax`

---

## 🔍 Pull Request Checklist

Before submitting a Pull Request, ensure:
- [ ] All new files and directories are correctly placed.
- [ ] No private environment variables or `.env` files are tracked by Git.
- [ ] Ruff check, Ruff format, and Mypy verify with zero warnings.
- [ ] All unit tests pass successfully.
- [ ] You have added tests covering the new functionality.
- [ ] Commit messages follow the Conventional Commits syntax.
