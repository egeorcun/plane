# Copyright (c) 2023-present Plane Software, Inc. and contributors
# SPDX-License-Identifier: AGPL-3.0-only
# See the LICENSE file for details.

# Python imports
import logging
import time

# Django imports
from django.http import HttpRequest
from django.utils import timezone

# Third party imports
from rest_framework.request import Request

# Module imports
from plane.utils.ip_address import get_client_ip
from plane.utils.exception_logger import log_exception
from plane.bgtasks.logger_task import process_logs

api_logger = logging.getLogger("plane.api.request")


class RequestLoggerMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def _should_log_route(self, request: Request | HttpRequest) -> bool:
        """
        Determines whether a route should be logged based on the request and status code.
        """
        # Don't log health checks
        if request.path == "/" and request.method == "GET":
            return False
        return True

    def __call__(self, request):
        # get the start time
        start_time = time.time()

        # Get the response
        response = self.get_response(request)

        # calculate the duration
        duration = time.time() - start_time

        # Check if logging is required
        log_true = self._should_log_route(request=request)

        # If logging is not required, return the response
        if not log_true:
            return response

        user_id = (
            request.user.id if getattr(request, "user") and getattr(request.user, "is_authenticated", False) else None
        )

        user_agent = request.META.get("HTTP_USER_AGENT", "")

        # Log the request information
        api_logger.info(
            f"{request.method} {request.get_full_path()} {response.status_code}",
            extra={
                "path": request.path,
                "method": request.method,
                "status_code": response.status_code,
                "duration_ms": int(duration * 1000),
                "remote_addr": get_client_ip(request),
                "user_agent": user_agent,
                "user_id": user_id,
            },
        )

        # return the response
        return response


class APITokenLogMiddleware:
    """
    Middleware to log External API requests to MongoDB or PostgreSQL.
    """

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        request_body = request.body
        response = self.get_response(request)
        self.process_request(request, response, request_body)
        return response

    def _safe_decode_body(self, content):
        """
        Safely decodes request/response body content, handling binary data.
        Returns None if content is None, or a string representation of the content.
        """
        # If the content is None, return None
        if content is None:
            return None

        # If the content is an empty bytes object, return None
        if content == b"":
            return None

        # Check if content is binary by looking for common binary file signatures
        if content.startswith(b"\x89PNG") or content.startswith(b"\xff\xd8\xff") or content.startswith(b"%PDF"):
            return "[Binary Content]"

        try:
            return content.decode("utf-8")
        except UnicodeDecodeError:
            return "[Could not decode content]"

    def _mask_sensitive_data(self, data):
        """
        Mask sensitive data in strings to prevent credential leakage in logs.
        
        SECURITY: This function redacts sensitive information like:
        - API keys
        - Authorization headers
        - Passwords
        - Tokens
        - Secrets
        """
        if data is None:
            return None
        
        if not isinstance(data, str):
            return data
        
        # Patterns to mask (case-insensitive)
        sensitive_patterns = [
            # API keys and tokens
            (r'(X-Api-Key["\']?\s*[:=]\s*["\']?)([^"\'\s,}]+)', r'\1[REDACTED]'),
            (r'(api[_-]?key["\']?\s*[:=]\s*["\']?)([^"\'\s,}]+)', r'\1[REDACTED]'),
            (r'(token["\']?\s*[:=]\s*["\']?)([^"\'\s,}]+)', r'\1[REDACTED]'),
            (r'(bearer\s+)(\S+)', r'\1[REDACTED]'),
            # Authorization header
            (r'(Authorization["\']?\s*[:=]\s*["\']?)([^"\'\s,}]+)', r'\1[REDACTED]'),
            # Passwords and secrets
            (r'(password["\']?\s*[:=]\s*["\']?)([^"\'\s,}]+)', r'\1[REDACTED]'),
            (r'(secret["\']?\s*[:=]\s*["\']?)([^"\'\s,}]+)', r'\1[REDACTED]'),
            # Cookie values (but keep names)
            (r'(Cookie["\']?\s*[:=]\s*["\']?)([^"\'\n]+)', r'\1[REDACTED]'),
            (r'(Set-Cookie["\']?\s*[:=]\s*["\']?)([^"\'\n]+)', r'\1[REDACTED]'),
        ]
        
        import re
        masked_data = data
        for pattern, replacement in sensitive_patterns:
            masked_data = re.sub(pattern, replacement, masked_data, flags=re.IGNORECASE)
        
        return masked_data

    def _mask_api_key(self, api_key):
        """
        Mask an API key for logging, showing only a prefix for identification.
        
        SECURITY: Never log full API keys. Show only first 8 characters for debugging.
        """
        if not api_key or len(api_key) < 12:
            return "[REDACTED]"
        return f"{api_key[:8]}...{api_key[-4:]}"

    def process_request(self, request, response, request_body):
        api_key_header = "X-Api-Key"
        api_key = request.headers.get(api_key_header)

        # If the API key is not present, return
        if not api_key:
            return

        try:
            # SECURITY: Mask sensitive data in headers and body before logging
            masked_headers = self._mask_sensitive_data(str(request.headers))
            masked_body = self._mask_sensitive_data(self._safe_decode_body(request_body)) if request_body else None
            masked_response = self._mask_sensitive_data(self._safe_decode_body(response.content)) if response.content else None
            
            log_data = {
                # SECURITY: Only log masked/partial API key for identification
                "token_identifier": self._mask_api_key(api_key),
                "path": request.path,
                "method": request.method,
                "query_params": request.META.get("QUERY_STRING", ""),
                # SECURITY: Log masked headers to prevent credential leakage
                "headers": masked_headers,
                # SECURITY: Mask sensitive data in request/response bodies
                "body": masked_body,
                "response_body": masked_response,
                "response_code": response.status_code,
                "ip_address": get_client_ip(request=request),
                "user_agent": request.META.get("HTTP_USER_AGENT", None),
            }
            user_id = (
                str(request.user.id)
                if getattr(request, "user") and getattr(request.user, "is_authenticated", False)
                else None
            )
            # Additional fields for MongoDB
            mongo_log = {
                **log_data,
                "created_at": timezone.now(),
                "updated_at": timezone.now(),
                "created_by": user_id,
                "updated_by": user_id,
            }

            process_logs.delay(log_data=log_data, mongo_log=mongo_log)

        except Exception as e:
            log_exception(e)

        return None
