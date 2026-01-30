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
        - Request is a same-origin request (verified via Sec-Fetch-Site header)
        - Request is an AJAX request with X-Requested-With header
        
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
        
        # For all other requests, enforce CSRF protection
        return super().enforce_csrf(request)
