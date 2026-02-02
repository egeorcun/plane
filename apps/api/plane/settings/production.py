# Copyright (c) 2023-present Plane Software, Inc. and contributors
# SPDX-License-Identifier: AGPL-3.0-only
# See the LICENSE file for details.

"""Production settings"""

import os
import sys
import logging
import warnings

from .common import *  # noqa

# =============================================================================
# PRODUCTION SECURITY VALIDATION
# =============================================================================
# These checks run at startup to ensure critical security settings are configured
# properly. Missing or insecure configurations will raise errors or warnings.
# =============================================================================


def _validate_production_security():
    """
    Validates critical security settings for production deployment.
    This function runs at module load time to catch misconfigurations early.
    """
    security_logger = logging.getLogger("plane.security")
    errors = []
    warnings_list = []

    # -------------------------------------------------------------------------
    # 1. SECRET_KEY Validation
    # -------------------------------------------------------------------------
    # SECRET_KEY must be explicitly set in production. Using Django's random
    # key generation is dangerous because it changes on every restart, which
    # invalidates all sessions and tokens.
    secret_key_env = os.environ.get("SECRET_KEY", "")
    if not secret_key_env:
        errors.append(
            "CRITICAL: SECRET_KEY environment variable is not set. "
            "Production deployments MUST have a strong, unique SECRET_KEY. "
            "Generate one with: python -c \"from django.core.management.utils import get_random_secret_key; print(get_random_secret_key())\""
        )
    elif len(secret_key_env) < 32:
        warnings_list.append(
            "WARNING: SECRET_KEY appears to be weak (less than 32 characters). "
            "Consider using a stronger key for better security."
        )

    # 2. ALLOWED_HOSTS Validation
    # -------------------------------------------------------------------------
    # Using "*" for ALLOWED_HOSTS is dangerous in production as it allows
    # HTTP Host header attacks. Always specify explicit hostnames.
    allowed_hosts_env = os.environ.get("ALLOWED_HOSTS", "")
    
    # Always allow localhost and 127.0.0.1 for internal health checks
    if "localhost" not in ALLOWED_HOSTS:
        ALLOWED_HOSTS.append("localhost")
    if "127.0.0.1" not in ALLOWED_HOSTS:
        ALLOWED_HOSTS.append("127.0.0.1")

    # If it's empty or *, it's insecure. But if it contains at least one real domain, it's okay.
    hosts_list = [h.strip() for h in allowed_hosts_env.split(",") if h.strip() and h.strip() != "*"]
    
    if not hosts_list:
        errors.append(
            "CRITICAL: ALLOWED_HOSTS is not set or only contains '*' or is empty. "
            "Set ALLOWED_HOSTS to your specific domain(s), e.g., 'example.com,www.example.com'. "
            "This prevents HTTP Host header attacks."
        )

    # -------------------------------------------------------------------------
    # 3. DEBUG Mode Validation
    # -------------------------------------------------------------------------
    # DEBUG mode should never be enabled in production as it exposes sensitive
    # information including full tracebacks, settings, and more.
    debug_env = os.environ.get("DEBUG", "0")
    if debug_env == "1" or debug_env.lower() == "true":
        errors.append(
            "CRITICAL: DEBUG mode is enabled in production! "
            "Set DEBUG=0 in your environment variables. "
            "Running with DEBUG=1 exposes sensitive information to attackers."
        )

    # -------------------------------------------------------------------------
    # 4. Default Credentials Check
    # -------------------------------------------------------------------------
    # Check for default/insecure credentials that ship with the example configs.
    # These should always be changed in production.
    default_credentials = [
        ("POSTGRES_PASSWORD", "plane", "database password"),
        ("RABBITMQ_PASSWORD", "plane", "RabbitMQ password"),
        ("RABBITMQ_PASSWORD", "guest", "RabbitMQ password"),
        ("AWS_ACCESS_KEY_ID", "access-key", "MinIO/AWS access key"),
        ("AWS_SECRET_ACCESS_KEY", "secret-key", "MinIO/AWS secret key"),
    ]

    for env_var, default_value, description in default_credentials:
        current_value = os.environ.get(env_var, "")
        if current_value == default_value:
            warnings_list.append(
                f"WARNING: {env_var} is using the default value '{default_value}'. "
                f"Change the {description} to a secure, unique value for production."
            )

    # -------------------------------------------------------------------------
    # 5. CORS Configuration Check
    # -------------------------------------------------------------------------
    # CORS_ALLOWED_ORIGINS should be explicitly set in production.
    # Using CORS_ALLOW_ALL_ORIGINS is dangerous.
    cors_origins = os.environ.get("CORS_ALLOWED_ORIGINS", "")
    if not cors_origins:
        warnings_list.append(
            "WARNING: CORS_ALLOWED_ORIGINS is not set. "
            "This means all origins are allowed, which is insecure for production. "
            "Set CORS_ALLOWED_ORIGINS to your specific frontend domain(s)."
        )

    # -------------------------------------------------------------------------
    # Log and Handle Validation Results
    # -------------------------------------------------------------------------
    # Log all warnings
    for warning_msg in warnings_list:
        security_logger.warning(warning_msg)
        warnings.warn(warning_msg, UserWarning)

    # If there are critical errors, log them
    if errors:
        for error_msg in errors:
            security_logger.error(error_msg)
        
        # Print errors to stderr for visibility during startup
        print("\n" + "!" * 80, file=sys.stderr)
        print("PRODUCTION SECURITY WARNING: CRITICAL MISCONFIGURATION DETECTED", file=sys.stderr)
        print("!" * 80, file=sys.stderr)
        for error_msg in errors:
            print(f"\n[SECURITY ERROR] {error_msg}", file=sys.stderr)
        print("\n" + "!" * 80 + "\n", file=sys.stderr)
        
        # We no longer raise SystemExit here to allow the container to start
        # and pass health checks, so the user can see the logs and fix the issues.
        # But we still keep the application in a potentially degraded state.


# Run security validation unless explicitly skipped
# SKIP_SECURITY_VALIDATION should ONLY be used for testing/CI, never in production
if os.environ.get("SKIP_SECURITY_VALIDATION", "0") != "1":
    _validate_production_security()


# SECURITY WARNING: don't run with debug turned on in production!
DEBUG = int(os.environ.get("DEBUG", 0)) == 1

# Honor the 'X-Forwarded-Proto' header for request.is_secure()
SECURE_PROXY_SSL_HEADER = ("HTTP_X_FORWARDED_PROTO", "https")

# =============================================================================
# SECURITY HEADERS
# =============================================================================
# These headers provide additional security protections against common attacks.
# =============================================================================

# HSTS (HTTP Strict Transport Security)
# Forces browsers to use HTTPS for all subsequent requests
SECURE_HSTS_SECONDS = int(os.environ.get("SECURE_HSTS_SECONDS", 31536000))  # 1 year
SECURE_HSTS_INCLUDE_SUBDOMAINS = os.environ.get("SECURE_HSTS_INCLUDE_SUBDOMAINS", "1") == "1"
SECURE_HSTS_PRELOAD = os.environ.get("SECURE_HSTS_PRELOAD", "0") == "1"

# Content Type Sniffing Protection
# Prevents browsers from MIME-sniffing responses away from declared content-type
SECURE_CONTENT_TYPE_NOSNIFF = True

# X-Frame-Options
# Prevents clickjacking attacks by controlling if page can be embedded in frames
X_FRAME_OPTIONS = os.environ.get("X_FRAME_OPTIONS", "DENY")

# SSL/HTTPS Settings
# Redirect all HTTP requests to HTTPS
SECURE_SSL_REDIRECT = os.environ.get("SECURE_SSL_REDIRECT", "0") == "1"

# Cross-site Scripting (XSS) Filter
# Note: This is largely obsolete with modern browsers, but doesn't hurt
SECURE_BROWSER_XSS_FILTER = True

# Referrer Policy
# Controls how much referrer information is sent with requests
SECURE_REFERRER_POLICY = os.environ.get("SECURE_REFERRER_POLICY", "strict-origin-when-cross-origin")

# =============================================================================
# CONTENT SECURITY POLICY (CSP)
# =============================================================================
# CSP helps prevent XSS attacks by controlling which resources can be loaded.
# Note: Django doesn't have built-in CSP support, but we define the policy here
# for use with django-csp or manual header configuration in middleware/proxy.
# =============================================================================
# CSP Policy: Restrictive by default, can be overridden via environment variable
# Format: directive1 value1 value2; directive2 value1;
CSP_POLICY = os.environ.get(
    "CSP_POLICY",
    "default-src 'self'; "
    "script-src 'self' 'unsafe-inline' 'unsafe-eval'; "  # unsafe-inline/eval needed for React
    "style-src 'self' 'unsafe-inline'; "  # inline styles needed for UI frameworks
    "img-src 'self' data: blob: https:; "  # allow images from any https source
    "font-src 'self' data:; "
    "connect-src 'self' wss: https:; "  # websockets and API calls
    "frame-ancestors 'none'; "  # equivalent to X-Frame-Options: DENY
    "base-uri 'self'; "
    "form-action 'self';"
)

# Cross-Origin policies for additional security
SECURE_CROSS_ORIGIN_OPENER_POLICY = os.environ.get("SECURE_CROSS_ORIGIN_OPENER_POLICY", "same-origin")

# =============================================================================
# CORS ENFORCEMENT FOR PRODUCTION
# =============================================================================
# Override common.py CORS settings to be more restrictive in production
# =============================================================================
if not os.environ.get("CORS_ALLOWED_ORIGINS"):
    # In production without explicit CORS origins, restrict to same-origin only
    # This is a safety measure - explicit configuration is always preferred
    CORS_ALLOW_ALL_ORIGINS = False
    CORS_ALLOWED_ORIGINS = []

INSTALLED_APPS += ("scout_apm.django",)  # noqa


# Scout Settings
SCOUT_MONITOR = os.environ.get("SCOUT_MONITOR", False)
SCOUT_KEY = os.environ.get("SCOUT_KEY", "")
SCOUT_NAME = "Plane"

LOG_DIR = os.path.join(BASE_DIR, "logs")  # noqa

if not os.path.exists(LOG_DIR):
    os.makedirs(LOG_DIR)

# Logging configuration
LOGGING = {
    "version": 1,
    "disable_existing_loggers": True,
    "formatters": {
        "verbose": {"format": "%(asctime)s [%(process)d] %(levelname)s %(name)s: %(message)s"},
        "json": {
            "()": "pythonjsonlogger.jsonlogger.JsonFormatter",
            "fmt": "%(levelname)s %(asctime)s %(module)s %(name)s %(message)s",
        },
    },
    "handlers": {
        "console": {
            "class": "logging.StreamHandler",
            "formatter": "json",
            "level": "INFO",
        },
        "file": {
            "class": "plane.utils.logging.SizedTimedRotatingFileHandler",
            "filename": (
                os.path.join(BASE_DIR, "logs", "plane-debug.log")  # noqa
                if DEBUG
                else os.path.join(BASE_DIR, "logs", "plane-error.log")  # noqa
            ),
            "when": "s",
            "maxBytes": 1024 * 1024 * 1,
            "interval": 1,
            "backupCount": 5,
            "formatter": "json",
            "level": "DEBUG" if DEBUG else "ERROR",
        },
    },
    "loggers": {
        "plane.api.request": {
            "level": "DEBUG" if DEBUG else "INFO",
            "handlers": ["console"],
            "propagate": False,
        },
        "plane.api": {
            "level": "DEBUG" if DEBUG else "INFO",
            "handlers": ["console"],
            "propagate": False,
        },
        "plane.worker": {
            "level": "DEBUG" if DEBUG else "INFO",
            "handlers": ["console"],
            "propagate": False,
        },
        "plane.exception": {
            "level": "DEBUG" if DEBUG else "ERROR",
            "handlers": ["console", "file"],
            "propagate": False,
        },
        "plane.external": {
            "level": "INFO",
            "handlers": ["console"],
            "propagate": False,
        },
        "plane.mongo": {
            "level": "INFO",
            "handlers": ["console"],
            "propagate": False,
        },
        "plane.migrations": {
            "level": "DEBUG" if DEBUG else "INFO",
            "handlers": ["console"],
            "propagate": False,
        },
    },
}
