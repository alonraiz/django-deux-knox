# Security Policy

## Supported Versions

We actively support the following versions of django-deux-knox:

| Version | Supported          |
| ------- | ------------------ |
| 1.2.x   | :white_check_mark: |
| < 1.2   | :x:                |

## Python and Django Support

| Python Version | Django Version | Supported          |
| -------------- | -------------- | ------------------ |
| 3.9+           | 4.2+           | :white_check_mark: |
| 3.8            | 4.2            | :warning: Limited  |
| < 3.8          | Any            | :x:                |

## Reporting a Vulnerability

We take security vulnerabilities seriously. If you discover a security vulnerability in django-deux-knox, please report it privately.

**Please do not report security vulnerabilities through public GitHub issues.**

Instead, please send an email to the project maintainers. Include as much of the following information as possible:

- Type of issue (e.g. buffer overflow, SQL injection, cross-site scripting, etc.)
- Full paths of source file(s) related to the manifestation of the issue
- The location of the affected source code (tag/branch/commit or direct URL)
- Any special configuration required to reproduce the issue
- Step-by-step instructions to reproduce the issue
- Proof-of-concept or exploit code (if possible)
- Impact of the issue, including how an attacker might exploit the issue

## Security Best Practices

When using django-deux-knox:

1. **Keep Dependencies Updated**: Regularly update Django, django-rest-framework, and other dependencies
2. **Secure Secret Keys**: Ensure your Django SECRET_KEY is kept secure and not exposed
3. **HTTPS Only**: Always use HTTPS in production for MFA token transmission
4. **Rate Limiting**: Implement rate limiting for MFA endpoints
5. **Backup Codes**: Store backup codes securely and rotate them regularly
6. **Monitoring**: Monitor failed authentication attempts

## Automated Security Scanning

This project uses:
- **Bandit**: Static security analysis for Python code
- **Safety**: Checks for known security vulnerabilities in dependencies
- **Dependabot**: Automated dependency updates

These tools run automatically on every pull request and push to the main branch.