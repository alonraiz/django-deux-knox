# GitHub Actions CI/CD

This directory contains GitHub Actions workflows for continuous integration and deployment.

## Workflows

### CI (`ci.yml`)
- **Triggers**: Push to `master`/`main`, Pull Requests
- **Python versions**: 3.9, 3.10, 3.11, 3.12, 3.13
- **Django versions**: 4.2, 5.0, 5.1, 5.2
- **Features**:
  - Run tests across Python/Django matrix
  - Code coverage reporting via Codecov
  - Code quality checks (flake8, black, isort)
  - Security scanning (bandit, safety)

## CI Status Badges

Add these badges to your main README:

```markdown
[![CI](https://github.com/your-org/django-deux-knox/actions/workflows/ci.yml/badge.svg)](https://github.com/your-org/django-deux-knox/actions/workflows/ci.yml)
[![codecov](https://codecov.io/gh/your-org/django-deux-knox/branch/main/graph/badge.svg)](https://codecov.io/gh/your-org/django-deux-knox)
[![Python 3.9+](https://img.shields.io/badge/python-3.9+-blue.svg)](https://www.python.org/downloads/)
[![Django 4.2+](https://img.shields.io/badge/django-4.2+-green.svg)](https://www.djangoproject.com/)
```

## Local Development

To run the same checks locally:

```bash
# Install development dependencies
pip install flake8 black isort coverage bandit safety

# Run tests with coverage
coverage run --source='deux' manage.py test --settings=test_proj.settings
coverage report

# Code quality checks
flake8 deux
black --check deux  # Use --diff to see changes
isort --check-only deux

# Security checks
bandit -r deux
safety check
```