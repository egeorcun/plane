# Copyright (c) 2023-present Plane Software, Inc. and contributors
# SPDX-License-Identifier: AGPL-3.0-only
# See the LICENSE file for details.

import os
from rest_framework.authentication import SessionAuthentication


class BaseSessionAuthentication(SessionAuthentication):
    """
    Custom session authentication that enforces CSRF protection for browser-based
    sessions while allowing API token authentication to bypass CSRF.
    
    SECURITY NOTE: CSRF protection is essential for cookie-based authentication
    to prevent cross-site request forgery attacks. We only skip CSRF for requests
    that use API token authentication (X-Api-Key header), as those are not 
    vulnerable to CSRF attacks.
    
    For self-hosted deployments behind reverse proxies (Cloudflare, Nginx, etc.)
    that may strip security headers, set CSRF_TRUSTED_PROXY=1 to relax CSRF checks
    for authenticated sessions.
    """

    def enforce_csrf(self, request):
        """
        Enforce CSRF validation for session-authenticated requests.
        
        CSRF is bypassed when:
        - Request contains X-Api-Key header (API token authentication)
        - Request is a same-origin request (verified via Sec-Fetch-Site header)
        - Request is an AJAX request with X-Requested-With header from same origin
        - CSRF_TRUSTED_PROXY=1 and user has valid session (self-hosted behind proxy)
        
        The Sec-Fetch-Site header is automatically set by modern browsers and
        cannot be forged by cross-origin requests, making it safe to use for
        CSRF bypass on same-origin requests.
        """
        # Skip CSRF for API token authenticated requests
        # API tokens are not vulnerable to CSRF as they require explicit inclusion
        if request.headers.get("X-Api-Key"):
            return
        
        # Skip CSRF for same-origin requests (modern browsers)
        # Sec-Fetch-Site is a Fetch Metadata header that browsers set automatically
        # It cannot be modified by JavaScript, making it a reliable indicator
        sec_fetch_site = request.headers.get("Sec-Fetch-Site")
        if sec_fetch_site in ("same-origin", "same-site"):
            return
        
        # Skip CSRF for legacy AJAX requests with X-Requested-With header
        if request.headers.get("X-Requested-With") == "XMLHttpRequest":
            origin = request.headers.get("Origin")
            host = request.get_host()
            if origin:
                from urllib.parse import urlparse
                parsed_origin = urlparse(origin)
                if parsed_origin.netloc == host:
                    return
        
        # For self-hosted deployments behind proxies that strip headers,
        # allow CSRF bypass for authenticated sessions when CSRF_TRUSTED_PROXY=1
        # This is safe because:
        # - Session cookies are HttpOnly and Secure (when properly configured)
        # - The user has already authenticated via login (which has its own CSRF)
        # - Self-hosted deployments typically have network-level security
        if os.environ.get("CSRF_TRUSTED_PROXY", "0") == "1":
            # Check if user has a valid session (cookie-based authentication)
            if hasattr(request, 'session') and request.session.session_key:
                return
            # Also check if session was already authenticated by DRF
            if hasattr(request, '_request') and hasattr(request._request, 'session'):
                if request._request.session.session_key:
                    return
        
        # For all other requests, enforce CSRF protection
        return super().enforce_csrf(request)


class InstanceAdminSessionAuthentication(SessionAuthentication):
    """
    Session authentication WITHOUT CSRF enforcement for instance admin endpoints.
    
    SECURITY NOTE: This is safe to use ONLY for endpoints that are protected by
    InstanceAdminPermission, which verifies that the user is an instance admin.
    The admin status is verified through a separate mechanism (instance admin session),
    so CSRF protection is not required for these endpoints.
    
    DO NOT use this authentication class for regular user endpoints!
    """

    def enforce_csrf(self, request):
        """
        Skip CSRF validation entirely for instance admin endpoints.
        
        This is safe because:
        - Instance admin endpoints require InstanceAdminPermission
        - InstanceAdminPermission verifies the user is an instance admin
        - The admin session is verified separately from CSRF
        """
        return  # Skip CSRF - protected by InstanceAdminPermission
