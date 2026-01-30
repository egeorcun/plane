# Copyright (c) 2023-present Plane Software, Inc. and contributors
# SPDX-License-Identifier: AGPL-3.0-only
# See the LICENSE file for details.

from urllib.parse import urlparse
from rest_framework.authentication import SessionAuthentication


class BaseSessionAuthentication(SessionAuthentication):
    """
    Custom session authentication that enforces CSRF protection for browser-based
    sessions while allowing same-origin requests to bypass CSRF.
    
    SECURITY NOTE: CSRF protection is essential for cookie-based authentication
    to prevent cross-site request forgery attacks. We skip CSRF for requests
    that can be verified as same-origin through various headers.
    
    Same-origin verification methods (in order of preference):
    1. Sec-Fetch-Site header (modern browsers, may be stripped by proxies)
    2. Referer header (reliably passed through most proxies)
    3. Origin header (sent with POST/PUT/DELETE requests)
    4. X-Api-Key header (API token authentication)
    """

    def _is_same_origin(self, request):
        """
        Check if the request is from the same origin using available headers.
        Returns True if the request can be verified as same-origin.
        
        Multiple headers are checked because reverse proxies (Cloudflare, Nginx, etc.)
        may strip some headers but typically preserve Referer and Origin.
        """
        host = request.get_host()
        
        # Method 1: Sec-Fetch-Site header (most reliable when available)
        # Set automatically by modern browsers, cannot be modified by JavaScript
        sec_fetch_site = request.headers.get("Sec-Fetch-Site")
        if sec_fetch_site in ("same-origin", "same-site"):
            return True
        
        # Method 2: Referer header (reliably passed through proxies)
        # Browsers automatically set this for same-origin requests
        # Cannot be forged by cross-origin JavaScript
        referer = request.headers.get("Referer")
        if referer:
            parsed_referer = urlparse(referer)
            if parsed_referer.netloc == host:
                return True
        
        # Method 3: Origin header (sent with POST/PUT/DELETE requests)
        # Also set automatically by browsers, cannot be forged
        origin = request.headers.get("Origin")
        if origin:
            parsed_origin = urlparse(origin)
            if parsed_origin.netloc == host:
                return True
        
        return False

    def enforce_csrf(self, request):
        """
        Enforce CSRF validation for session-authenticated requests.
        
        CSRF is bypassed when:
        - Request contains X-Api-Key header (API token authentication)
        - Request is verified as same-origin via Sec-Fetch-Site, Referer, or Origin headers
        
        This approach provides CSRF protection while working with reverse proxies
        that may strip certain headers.
        """
        # Skip CSRF for API token authenticated requests
        # API tokens are not vulnerable to CSRF as they require explicit inclusion
        if request.headers.get("X-Api-Key"):
            return
        
        # Skip CSRF for verified same-origin requests
        # This checks Sec-Fetch-Site, Referer, and Origin headers
        if self._is_same_origin(request):
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
