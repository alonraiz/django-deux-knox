# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Development Commands

### Testing
```bash
# Run all tests
python manage.py test --settings=test_proj.settings

# Run specific test module
python manage.py test deux.oauth2.tests --settings=test_proj.settings

# Run single test class
python manage.py test deux.oauth2.tests.test_authentication.MFAOAuth2TokenTests --settings=test_proj.settings

# Run with coverage
coverage run --source='deux' manage.py test --settings=test_proj.settings
coverage report
coverage xml  # For CI/Codecov
```

### Code Quality
```bash
# Linting (critical errors will fail CI)
flake8 deux --count --select=E9,F63,F7,F82 --show-source --statistics
flake8 deux --count --exit-zero --max-complexity=10 --max-line-length=127 --statistics

# Formatting checks (informational in CI)
black --check --diff deux
isort --check-only --diff deux

# Security scanning
bandit -r deux
safety check
```

### Django Operations
```bash
# System checks
python manage.py check --settings=test_proj.settings

# Migrations
python manage.py migrate --settings=test_proj.settings
python manage.py makemigrations deux --settings=test_proj.settings

# Interactive shell for testing
python manage.py shell --settings=test_proj.settings
```

## Architecture Overview

Django-deux-knox is a multi-factor authentication library with three main authentication backends:

### Core Architecture Components

**1. Core MFA Module (`deux/`)**
- `models.py` - `MultiFactorAuth` model with one-to-one User relationship
- `services.py` - `MultiFactorChallenge` class handling code generation/verification
- `app_settings.py` - Centralized configuration with `DEUX` settings dictionary
- Uses django-otp for TOTP with 30-second time steps and ±1 drift tolerance

**2. AuthToken Module (`deux/authtoken/`)**
- Replaces DRF tokens with Knox tokens (secure, expiring)
- `MFAAuthTokenSerializer` extends DRF's serializer with MFA fields
- `ObtainMFAAuthToken` view handles username/password → MFA check → Knox token flow
- Returns either challenge requirement or Knox token with expiry

**3. OAuth2 Module (`deux/oauth2/`)**
- `MFARequestBackend` extends OAuth2 backend to extract MFA credentials from request
- `MFAOAuth2Validator` validates OAuth2 requests with MFA requirements
- `MFATokenView` provides OAuth2 token endpoint with MFA validation
- Custom exceptions: `ChallengeRequiredMessage`, `InvalidLoginError`

### MFA Flow Architecture

```
Authentication Request → Username/Password Validation → MFA Status Check
    ↓
[If MFA Enabled] → Challenge Generation → SMS/Email Delivery → Code Verification
    ↓
[Success] → Knox Token/OAuth2 Token | [Failure] → Error Response
```

### Key Integration Patterns

**Challenge System:**
- Supports SMS (Twilio), Email (Django), and backup codes
- Time-based codes with configurable TTL (default 300s)
- Constant-time comparison prevents timing attacks
- Backup codes automatically disable MFA when used

**Security Features:**
- Knox tokens use SHA512 hashing with configurable expiration
- OAuth2 client secrets are hashed (handle carefully in tests)
- Rate limiting hooks available for abuse prevention
- Secure random backup code generation

## Test Project Structure

The `test_proj/` directory contains a minimal Django project for testing:
- `settings.py` - Test configuration with SQLite, disabled OAuth2 secret hashing
- `urls.py` - URL patterns for all MFA endpoints
- Uses in-memory database for CI

## Critical OAuth2 Testing Note

In django-oauth-toolkit 3.0+, client secrets are automatically hashed when saved. Tests must capture the raw client secret before saving the Application model:

```python
# Correct pattern in tests
self.application = Application(...)
raw_client_secret = self.application.client_secret  # Capture before save
self.application.save()  # This hashes the secret
self.headers = self._get_basic_auth_header(self.application.client_id, raw_client_secret)
```

## Configuration Patterns

**Required Settings:**
```python
DEUX = {
    "TWILIO_ACCOUNT_SID": "...",      # Required for SMS
    "TWILIO_AUTH_TOKEN": "...",       # Required for SMS
    "TWILIO_SMS_POOL_SID": "...",     # Optional
}
```

**Test-Specific Settings:**
```python
OAUTH2_PROVIDER = {
    'HASH_CLIENT_SECRET': False,  # Only for testing
}
```

## Dependencies and Compatibility

- **Python 3.9+** with Django 4.2-5.2 support matrix
- **Core**: django-rest-knox, django-otp, twilio
- **OAuth2**: django-oauth-toolkit 3.0+
- **Testing**: unittest.mock (not external mock package)
- **Note**: `six` library removed - uses native Python 3 strings/text types

## URL Structure

```
/mfa/                    # Core MFA management
/mfa/sms/request/        # SMS challenge request
/mfa/sms/verify/         # SMS code verification  
/mfa/recovery/           # Backup code management
/mfa/authtoken/login/    # Knox token authentication with MFA
/mfa/oauth2/token/       # OAuth2 token endpoint with MFA
```

## Common Development Gotchas

1. **URL Patterns**: Use `re_path` not `url` (deprecated in Django 4.0+)
2. **Translations**: Use `gettext_lazy` not `ugettext_lazy` (removed in Django 4.0+)
3. **Mock Imports**: Use `unittest.mock` not external `mock` package
4. **Password Hashers**: Avoid SHA1/MD5 hashers (removed for security)
5. **OAuth2 Secrets**: Handle client secret hashing in tests properly
6. **Middleware**: Use `MIDDLEWARE` not `MIDDLEWARE_CLASSES`