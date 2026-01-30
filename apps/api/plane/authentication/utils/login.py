# Copyright (c) 2023-present Plane Software, Inc. and contributors
# SPDX-License-Identifier: AGPL-3.0-only
# See the LICENSE file for details.

# Django imports
from django.contrib.auth import login
from django.conf import settings

# Module imports
from plane.utils.host import base_host
from plane.utils.ip_address import get_client_ip


def user_login(request, user, is_app=False, is_admin=False, is_space=False):
    """
    Handles user login with proper session security measures.
    
    SECURITY: This function implements session fixation protection by
    regenerating the session ID before logging in the user. This prevents
    an attacker from fixing a session ID before authentication and then
    hijacking it after the user logs in.
    """
    # ==========================================================================
    # SESSION FIXATION PROTECTION
    # ==========================================================================
    # Regenerate session ID to prevent session fixation attacks.
    # This must happen BEFORE login() to ensure any pre-existing session ID
    # cannot be used to hijack the authenticated session.
    # 
    # flush() clears the session data AND creates a new session ID.
    # We preserve any necessary pre-login data (like OAuth state) and restore
    # it after the flush if needed.
    # ==========================================================================
    
    # Preserve any data that needs to survive session regeneration
    preserved_data = {}
    keys_to_preserve = ['next_path', 'host']  # Add any other keys that need preservation
    for key in keys_to_preserve:
        if key in request.session:
            preserved_data[key] = request.session[key]
    
    # Regenerate session ID - this is critical for session fixation prevention
    # cycle_key() changes the session key while preserving session data
    if hasattr(request.session, 'cycle_key'):
        request.session.cycle_key()
    else:
        # Fallback: manually regenerate session
        request.session.flush()
        # Restore preserved data
        for key, value in preserved_data.items():
            request.session[key] = value
    
    # Now perform the actual login
    login(request=request, user=user)

    # If is admin cookie set the custom age
    if is_admin:
        request.session.set_expiry(settings.ADMIN_SESSION_COOKIE_AGE)

    # Store device information for audit/security purposes
    device_info = {
        "user_agent": request.META.get("HTTP_USER_AGENT", ""),
        "ip_address": get_client_ip(request=request),
        "domain": base_host(request=request, is_app=is_app, is_admin=is_admin, is_space=is_space),
    }
    request.session["device_info"] = device_info
    request.session.save()
    return
