# Django Deux Knox

[![CI](https://github.com/aloncortex/django-deux-knox/actions/workflows/ci.yml/badge.svg)](https://github.com/aloncortex/django-deux-knox/actions/workflows/ci.yml)
[![codecov](https://codecov.io/gh/aloncortex/django-deux-knox/branch/master/graph/badge.svg)](https://codecov.io/gh/aloncortex/django-deux-knox)
[![Python 3.9+](https://img.shields.io/badge/python-3.9+-blue.svg)](https://www.python.org/downloads/)
[![Django 4.2+](https://img.shields.io/badge/django-4.2+-green.svg)](https://www.djangoproject.com/)
[![PyPI](https://img.shields.io/pypi/v/deux.svg)](https://pypi.org/project/deux/)
[![License](https://img.shields.io/badge/license-BSD-blue.svg)](LICENSE)

A secure and flexible multi-factor authentication (MFA) library for Django Rest Framework, enhanced with Knox token authentication.

## About

This is an enhanced fork of [robinhood/deux](https://github.com/robinhood/deux) that replaces DRF tokens with [django-rest-knox](https://github.com/James1345/django-rest-knox) tokens for improved security and functionality.

## Features

- 🔐 **Multi-Factor Authentication** - SMS-based second factor authentication
- 🛡️ **Knox Token Integration** - Secure, expiring tokens instead of permanent DRF tokens
- 📱 **SMS Challenges** - Twilio integration for SMS delivery
- 🔄 **Backup Codes** - Recovery codes when SMS is unavailable
- 🔌 **OAuth2 Support** - Custom OAuth2 backend with MFA validation
- 🧪 **Well Tested** - 99% test coverage across all components
- 🚀 **Modern Django** - Full compatibility with Django 5.2 and Python 3.13

## Compatibility

| Python Version | Django Version | Status |
|---------------|----------------|--------|
| 3.9           | 4.2            | ✅ Supported |
| 3.10          | 4.2, 5.0, 5.1, 5.2 | ✅ Supported |
| 3.11          | 4.2, 5.0, 5.1, 5.2 | ✅ Supported |
| 3.12          | 4.2, 5.0, 5.1, 5.2 | ✅ Supported |
| 3.13          | 4.2, 5.0, 5.1, 5.2 | ✅ Supported |

## Installation

```bash
pip install deux
```

## Quick Start

### 1. Add to Django Settings

```python
INSTALLED_APPS = [
    # ... your apps
    'rest_framework',
    'knox',
    'oauth2_provider',  # If using OAuth2
    'deux',
]

# Deux Configuration
DEUX = {
    "TWILIO_ACCOUNT_SID": "your_twilio_account_sid",
    "TWILIO_AUTH_TOKEN": "your_twilio_auth_token", 
    "TWILIO_SMS_POOL_SID": "your_sms_pool_sid",  # Optional
}

# Knox Token Settings
REST_KNOX = {
    'SECURE_HASH_ALGORITHM': 'cryptography.hazmat.primitives.hashes.SHA512',
    'AUTH_TOKEN_CHARACTER_LENGTH': 64,
    'TOKEN_TTL': timedelta(hours=10),
    'USER_SERIALIZER': 'knox.serializers.UserSerializer',
    'TOKEN_LIMIT_PER_USER': None,
    'AUTO_REFRESH': False,
}
```

### 2. Include URLs

```python
from django.urls import path, include

urlpatterns = [
    # ... your URLs
    path('auth/', include('knox.urls')),
    path('mfa/', include('deux.urls')),
    path('mfa/authtoken/', include('deux.authtoken.urls')),
    path('mfa/oauth2/', include('deux.oauth2.urls')),  # If using OAuth2
]
```

### 3. Run Migrations

```bash
python manage.py migrate
```

## Usage Examples

### Enable MFA for a User

```python
from deux.models import MultiFactorAuth
from deux.constants import SMS
from django.contrib.auth.models import User

user = User.objects.get(username='testuser')
mfa = MultiFactorAuth.objects.create(user=user)
mfa.phone_number = '+1234567890'
mfa.enable(SMS)
mfa.save()
```

### API Endpoints

#### Request SMS Challenge
```http
PUT /mfa/sms/request/
Authorization: Token your_knox_token
Content-Type: application/json

{
    "phone_number": "+1234567890"
}
```

#### Verify SMS Code
```http
PUT /mfa/sms/verify/
Authorization: Token your_knox_token
Content-Type: application/json

{
    "mfa_code": "123456"
}
```

#### Get Backup Code
```http
GET /mfa/recovery/
Authorization: Token your_knox_token
```

### OAuth2 with MFA

```python
# Token request with MFA
POST /mfa/oauth2/token/
Content-Type: application/x-www-form-urlencoded
Authorization: Basic base64(client_id:client_secret)

grant_type=password&username=user&password=pass&mfa_code=123456
```

## Development

### Setup Development Environment

```bash
# Clone the repository
git clone https://github.com/aloncortex/django-deux-knox.git
cd django-deux-knox

# Create virtual environment
python -m venv .venv
source .venv/bin/activate  # Linux/Mac
# or
.venv\Scripts\activate  # Windows

# Install dependencies
pip install -r requirements/default.txt
pip install -r requirements/test.txt

# Run migrations
python manage.py migrate --settings=test_proj.settings

# Run tests
python manage.py test --settings=test_proj.settings
```

### Code Quality

```bash
# Run linting
flake8 deux

# Check formatting  
black --check deux
isort --check-only deux

# Run security checks
bandit -r deux
safety check

# Generate coverage report
coverage run --source='deux' manage.py test --settings=test_proj.settings
coverage report
```

## Configuration

### Required Settings

```python
DEUX = {
    "TWILIO_ACCOUNT_SID": "your_account_sid",      # Required for SMS
    "TWILIO_AUTH_TOKEN": "your_auth_token",        # Required for SMS
    "TWILIO_SMS_POOL_SID": "your_sms_pool_sid",    # Optional
}
```

### Optional Settings

```python
DEUX = {
    # ... required settings above
    "MFA_MODEL": "deux.models.MultiFactorAuth",    # Custom MFA model
    "BACKUP_CODE_DIGITS": 12,                      # Backup code length
    "MFA_CODE_DIGITS": 6,                          # SMS code length
    "MFA_CODE_TTL": 300,                           # Code expiry (seconds)
}
```

### OAuth2 Provider Settings

```python
OAUTH2_PROVIDER = {
    'HASH_CLIENT_SECRET': False,  # For testing only
    # ... other OAuth2 settings
}
```

## Security Considerations

- 🔒 **Always use HTTPS** in production for token transmission
- 🔑 **Secure your Twilio credentials** and Django SECRET_KEY
- 📱 **Implement rate limiting** on MFA endpoints to prevent abuse
- 🔄 **Rotate backup codes** regularly
- 📊 **Monitor failed authentication attempts**
- 🛡️ **Keep dependencies updated** (Dependabot enabled)

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Make your changes
4. Add tests for new functionality
5. Ensure all tests pass (`python manage.py test --settings=test_proj.settings`)
6. Run code quality checks (`flake8 deux`)
7. Commit your changes (`git commit -m 'Add amazing feature'`)
8. Push to the branch (`git push origin feature/amazing-feature`)
9. Open a Pull Request

### Development Guidelines

- Write tests for all new features and bug fixes
- Follow PEP 8 style guidelines (enforced by flake8)
- Update documentation for any API changes
- Maintain backwards compatibility when possible
- Add appropriate logging for debugging

## License

This project is licensed under the BSD 3-Clause License - see the [LICENSE](LICENSE) file for details.

## Credits

- **Original Project**: [robinhood/deux](https://github.com/robinhood/deux) by Robinhood Markets
- **Knox Integration**: Enhanced with [django-rest-knox](https://github.com/James1345/django-rest-knox)
- **Contributors**: See [GitHub contributors](https://github.com/aloncortex/django-deux-knox/graphs/contributors)

## Changelog

### v1.2.0 (Latest)
- ✅ Added Python 3.13 support
- ✅ Added Django 5.2 support
- ✅ Updated all dependencies for modern compatibility
- ✅ Fixed OAuth2 client secret hashing issues
- ✅ Added comprehensive GitHub Actions CI/CD
- ✅ Improved test coverage to 99%
- ✅ Enhanced security with automated vulnerability scanning

### Previous Versions
See [CHANGELOG](Changelog) for full version history.

## Support

- 📚 **Documentation**: [Full documentation](docs/)
- 🐛 **Bug Reports**: [GitHub Issues](https://github.com/aloncortex/django-deux-knox/issues)
- 💬 **Discussions**: [GitHub Discussions](https://github.com/aloncortex/django-deux-knox/discussions)
- 🔒 **Security Issues**: See [SECURITY.md](.github/SECURITY.md)