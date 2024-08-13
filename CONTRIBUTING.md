# Contributing to Collaborative Circom

Thank you for considering contributing to Collaborative Circom! Your help is essential for keeping this project stable, secure, and up-to-date. Below are the guidelines for contributing, including how to report security vulnerabilities.

## How Can I Contribute?

If you find a security vulnerability, or are not sure whether it is a security vulnerability, _DO NOT OPEN A GITHUB ISSUE_. Read the section on how to handle [security vulnerabilities](#security-vulnerabilities).

### Reporting Bugs

If you find a bug, please [open an issue](https://github.com/TaceoLabs/collaborative-circom/issues) and provide as much detail as possible. Make sure to include:

- A clear and descriptive title.
- A detailed description of the problem, including any error messages.
- Steps to reproduce the issue.
- The expected and actual behavior.
- Environment details (operating system, Rust version, etc.).
  
### Suggesting Enhancements

If you have an idea for a new feature or an improvement to an existing feature, we’d love to hear from you! Please [open an issue](https://github.com/TaceoLabs/collaborative-circom/issues) and include:

- A clear and descriptive title.
- A detailed explanation of the proposed enhancement.
- Any relevant examples, code snippets, or use cases.

### Submitting Code Changes

Before you start working on a new feature or a bug fix, please check the open issues and confirm that the work is not already in progress. If it’s a significant change, it might be worth discussing your idea with the maintainers first.

#### Guidelines

We provide a `justfile` in the root directory to check for compliance for PRs. Please run

```bash
just check-pr
```

and verify that all checks succeed. Keep the following things in mind:

- **Follow Rust clippy**: We follow the guidelines from clippy.
- **Public API must be documented**: every exposed artifact must be documented.
- **Keep commits atomic**: Each commit should be a self-contained piece of work, with a clear commit message. The commit message should follow the guidelines for [conventional commit message](https://www.conventionalcommits.org/en/v1.0.0/).

### Writing Tests

Tests are essential for maintaining the reliability of the project. Please make sure that:

- All new features include unit/e2e tests.
- Bug fixes include regression tests to prevent future issues.
- The entire test suite passes before submitting your changes.

### Improving Documentation

Clear and comprehensive documentation helps others understand how to use and contribute to the project. You can contribute by:

- Fixing typos or improving explanations in existing documentation.
- Adding documentation for new features.
- Improving examples and tutorials.

## Security Vulnerabilities

If you find a security vulnerability, DO NOT open an issue on GitHub. Instead, please email the details to [TACEO](mailto:contact@taceo.io).

We take security vulnerabilities seriously and will respond promptly to address the issue.

## Pull Request Process

1. Fork the repository and create a new branch for your feature or bug fix:

    ```bash
    git checkout -b your-feature-branch
    ```

2. Make your changes in the feature branch.
3. Run the linter and test suite with:

    ```bash
    just check-pr
    ```

4. Commit your changes with a [clear and descriptive message](https://www.conventionalcommits.org/en/v1.0.0/).
5. Push to your fork and open a pull request against the main branch.
6. Your pull request will be reviewed, and feedback may be provided. Once approved, it will be merged into the main branch.

Thanks!
Your TACEO team ❤️
