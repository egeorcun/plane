# Copyright (c) 2023-present Plane Software, Inc. and contributors
# SPDX-License-Identifier: AGPL-3.0-only
# See the LICENSE file for details.

# Python imports
import socket
import ipaddress
from urllib.parse import urlparse

# Third party imports
from rest_framework import serializers

# Module imports
from .base import DynamicBaseSerializer
from plane.db.models import Webhook, WebhookLog
from plane.db.models.webhook import validate_domain, validate_schema


def is_ip_blocked(ip_obj):
    """
    Check if an IP address should be blocked for SSRF protection.
    
    SECURITY: This function prevents Server-Side Request Forgery (SSRF) attacks
    by blocking requests to internal/private network addresses.
    
    Blocked IP ranges:
    - Loopback (127.0.0.0/8, ::1)
    - Private networks (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16)
    - Link-local (169.254.0.0/16, fe80::/10)
    - Reserved/Documentation ranges
    - Multicast addresses
    - Cloud metadata endpoints (169.254.169.254)
    
    Args:
        ip_obj: An ipaddress.ip_address object
        
    Returns:
        bool: True if the IP should be blocked, False otherwise
    """
    # Check common dangerous IP properties
    if ip_obj.is_loopback:
        return True
    if ip_obj.is_private:
        return True
    if ip_obj.is_reserved:
        return True
    if ip_obj.is_multicast:
        return True
    if ip_obj.is_link_local:
        return True
    
    # Explicitly block cloud metadata endpoints
    # AWS, GCP, Azure all use 169.254.169.254 for instance metadata
    cloud_metadata_ips = [
        "169.254.169.254",  # AWS/GCP/Azure metadata
        "fd00:ec2::254",    # AWS IPv6 metadata
    ]
    if str(ip_obj) in cloud_metadata_ips:
        return True
    
    # Block documentation/test ranges
    try:
        # IPv4 documentation ranges
        if ip_obj.version == 4:
            doc_ranges = [
                ipaddress.ip_network("192.0.2.0/24"),     # TEST-NET-1
                ipaddress.ip_network("198.51.100.0/24"), # TEST-NET-2  
                ipaddress.ip_network("203.0.113.0/24"),  # TEST-NET-3
            ]
            for net in doc_ranges:
                if ip_obj in net:
                    return True
    except Exception:
        pass
    
    return False


def validate_webhook_url(url, request=None):
    """
    Validate a webhook URL for SSRF vulnerabilities.
    
    SECURITY: This function performs comprehensive SSRF protection:
    1. Resolves hostname to all IP addresses
    2. Checks each resolved IP against blocked ranges
    3. Validates against disallowed domains
    
    Args:
        url: The webhook URL to validate
        request: The HTTP request object (optional, for context)
        
    Raises:
        serializers.ValidationError: If the URL fails validation
    """
    # Extract the hostname from the URL
    hostname = urlparse(url).hostname
    if not hostname:
        raise serializers.ValidationError({"url": "Invalid URL: No hostname found."})

    # Resolve the hostname to IP addresses
    # SECURITY: We must check ALL resolved IPs, not just the first one
    # DNS can return multiple IPs, and an attacker could use DNS rebinding
    try:
        ip_addresses = socket.getaddrinfo(hostname, None)
    except socket.gaierror:
        raise serializers.ValidationError({"url": "Hostname could not be resolved."})

    if not ip_addresses:
        raise serializers.ValidationError({"url": "No IP addresses found for the hostname."})

    # Check ALL resolved IP addresses for SSRF vulnerabilities
    for addr in ip_addresses:
        try:
            ip = ipaddress.ip_address(addr[4][0])
            if is_ip_blocked(ip):
                raise serializers.ValidationError({
                    "url": "URL resolves to a blocked IP address. "
                           "Private, loopback, and reserved IP ranges are not allowed."
                })
        except ValueError:
            # If we can't parse the IP, skip it
            continue

    # Additional validation for disallowed domains
    disallowed_domains = ["plane.so"]  # Add your disallowed domains here
    if request:
        request_host = request.get_host().split(":")[0]  # Remove port if present
        disallowed_domains.append(request_host)

    # Check if hostname is a subdomain or exact match of any disallowed domain
    if any(hostname == domain or hostname.endswith("." + domain) for domain in disallowed_domains):
        raise serializers.ValidationError({"url": "URL domain or its subdomain is not allowed."})


class WebhookSerializer(DynamicBaseSerializer):
    url = serializers.URLField(validators=[validate_schema, validate_domain])

    def create(self, validated_data):
        url = validated_data.get("url", None)
        request = self.context.get("request")
        
        # Comprehensive SSRF validation
        validate_webhook_url(url, request)

        return Webhook.objects.create(**validated_data)

    def update(self, instance, validated_data):
        url = validated_data.get("url", None)
        if url:
            request = self.context.get("request")
            
            # Comprehensive SSRF validation
            validate_webhook_url(url, request)

        return super().update(instance, validated_data)

    class Meta:
        model = Webhook
        fields = "__all__"
        read_only_fields = ["workspace", "secret_key", "deleted_at"]


class WebhookLogSerializer(DynamicBaseSerializer):
    class Meta:
        model = WebhookLog
        fields = "__all__"
        read_only_fields = ["workspace", "webhook"]
