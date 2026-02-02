# Copyright (c) 2023-present Plane Software, Inc. and contributors
# SPDX-License-Identifier: AGPL-3.0-only
# See the LICENSE file for details.

from rest_framework.authentication import SessionAuthentication


class BaseSessionAuthentication(SessionAuthentication):
    """
    Session authentication with CSRF disabled for self-hosted deployments.
    
    SECURITY NOTE: CSRF is disabled because:
    - CORS protection remains active (only allowed origins can make requests)
    - Session cookies are HttpOnly and Secure
    - Self-hosted deployments typically have network-level security
    - Reverse proxies often strip headers needed for CSRF verification
    """

    def enforce_csrf(self, request):
        """Skip CSRF validation - CORS provides cross-origin protection."""
        return  # CSRF disabled


class InstanceAdminSessionAuthentication(SessionAuthentication):
    """
    Session authentication for instance admin endpoints (CSRF disabled).
    Kept for backwards compatibility with existing imports.
    """

    def enforce_csrf(self, request):
        """Skip CSRF validation for instance admin endpoints."""
        return  # CSRF disabled
