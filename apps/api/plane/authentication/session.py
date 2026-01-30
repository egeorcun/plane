# Copyright (c) 2023-present Plane Software, Inc. and contributors
# SPDX-License-Identifier: AGPL-3.0-only
# See the LICENSE file for details.

from rest_framework.authentication import SessionAuthentication


class BaseSessionAuthentication(SessionAuthentication):
    """
    Custom session authentication that enforces CSRF protection for browser-based
    sessions while allowing API token authentication to bypass CSRF.
    
    SECURITY NOTE: CSRF protection is essential for cookie-based authentication
    to prevent cross-site request forgery attacks. We only skip CSRF for requests
    that use API token authentication (X-Api-Key header), as those are not 
    vulnerable to CSRF attacks.
    """

    def enforce_csrf(self, request):
        """
        Enforce CSRF validation for session-authenticated requests.
        
        CSRF is bypassed only when:
        - Request contains X-Api-Key header (API token authentication)
        - Request is an AJAX request with proper headers
        
        All other session-based requests require CSRF validation.
        """
        # Skip CSRF for API token authenticated requests
        # API tokens are not vulnerable to CSRF as they require explicit inclusion
        if request.headers.get("X-Api-Key"):
            return
        
        # Skip CSRF for requests that explicitly indicate they're not browser-based
        # This is safe because CSRF attacks rely on browser-initiated requests
        if request.headers.get("X-Requested-With") == "XMLHttpRequest":
            # Additional check: ensure it's from a same-origin request
            origin = request.headers.get("Origin")
            host = request.get_host()
            if origin:
                from urllib.parse import urlparse
                parsed_origin = urlparse(origin)
                # Allow if origin matches the host
                if parsed_origin.netloc == host:
                    return
        
        # For all other requests, enforce CSRF protection
        # This includes browser-initiated requests with session cookies
        return super().enforce_csrf(request)
