# Copyright (c) 2023-present Plane Software, Inc. and contributors
# SPDX-License-Identifier: AGPL-3.0-only
# See the LICENSE file for details.

"""
Security Headers Middleware

This middleware adds additional security headers to all responses.
While Django handles some security headers via settings (HSTS, X-Frame-Options, etc.),
this middleware adds headers that Django doesn't natively support, like CSP.

SECURITY NOTE: These headers provide defense-in-depth against various attacks:
- CSP: Prevents XSS by controlling resource loading
- Permissions-Policy: Disables browser features that could be exploited
- Cross-Origin policies: Isolates the application from other origins
"""

from django.conf import settings


class SecurityHeadersMiddleware:
    """
    Middleware to add security headers to HTTP responses.
    
    Headers added:
    - Content-Security-Policy (CSP): Controls which resources can be loaded
    - Permissions-Policy: Disables unnecessary browser features
    - Cross-Origin-Embedder-Policy: Controls cross-origin resource embedding
    - Cross-Origin-Resource-Policy: Controls who can load this resource
    
    These complement Django's built-in security headers (HSTS, X-Frame-Options, etc.)
    """

    def __init__(self, get_response):
        self.get_response = get_response
        
        # Cache CSP policy from settings (computed once at startup)
        self.csp_policy = getattr(settings, "CSP_POLICY", None)
        
        # Cross-Origin Opener Policy from settings
        self.coop_policy = getattr(settings, "SECURE_CROSS_ORIGIN_OPENER_POLICY", "same-origin")
        
        # Permissions-Policy: Disable potentially dangerous browser features
        # This restricts access to browser APIs that could be exploited
        self.permissions_policy = (
            "accelerometer=(), "
            "camera=(), "
            "geolocation=(), "
            "gyroscope=(), "
            "magnetometer=(), "
            "microphone=(), "
            "payment=(), "
            "usb=()"
        )

    def __call__(self, request):
        response = self.get_response(request)
        
        # Add Content-Security-Policy header if configured
        # CSP is one of the most effective defenses against XSS attacks
        if self.csp_policy:
            response["Content-Security-Policy"] = self.csp_policy
        
        # Add Permissions-Policy header (formerly Feature-Policy)
        # Disables browser features we don't need, reducing attack surface
        response["Permissions-Policy"] = self.permissions_policy
        
        # Add Cross-Origin-Opener-Policy header
        # Isolates the browsing context from cross-origin documents
        if self.coop_policy:
            response["Cross-Origin-Opener-Policy"] = self.coop_policy
        
        # Add Cross-Origin-Resource-Policy header
        # Prevents other origins from reading this resource (for non-CORS requests)
        response["Cross-Origin-Resource-Policy"] = "same-origin"
        
        return response
