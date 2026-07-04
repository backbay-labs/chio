"""Minimal Django settings for chio-django tests."""

SECRET_KEY = "chio-django-test-key"
DEBUG = True
INSTALLED_APPS = [
    "django.contrib.contenttypes",
]
MIDDLEWARE = []
ROOT_URLCONF = "tests.urls"
DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.sqlite3",
        "NAME": ":memory:",
    }
}
DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"

# Chio settings for tests
CHIO_SIDECAR_URL = "http://127.0.0.1:9090"
CHIO_EXCLUDE_PATHS = ["/health"]
CHIO_EXCLUDE_METHODS = ["OPTIONS"]
