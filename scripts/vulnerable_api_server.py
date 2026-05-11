#!/usr/bin/env python3
# Copyright (c) 2026 PenTestToolkit
# SPDX-License-Identifier: MIT
"""
Mock Vulnerable API Server
Mimics the Insomnia Gaming Egypt promo code endpoint vulnerability
"""

from flask import Flask, jsonify, make_response
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import random

app = Flask(__name__)

# Rate limiter - 180 requests per minute (matching the reported x-ratelimit-limit: 180)
limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["180 per minute"]
)

# Simulated database of valid promo codes per event
VALID_PROMO_CODES = {
    1: ["SPRING2024", "GAMER50", "WELCOME10", "NIGHTOWL", "EGYPTGAMING",
        # Structured pattern codes matching user's observation
        "3DS6-8ZSG-1SEZ", "3DS6-3TQ9-D59C", "3DS6-ABCD-1234", "3DS6-TEST-9999"],
    2: ["SUMMER25", "LANPARTY", "INSOMNIA2024",
        # Event 2 uses different prefix
        "4EG7-XXXX-YYYY", "4EG7-AAAA-BBBB"],
    3: ["TOURNAMENT", "PROPLAYER", "VICTORY"]
}

EVENT_DETAILS = {
    1: {"name": "Spring Gaming Tournament", "date": "2024-05-15"},
    2: {"name": "Summer LAN Party", "date": "2024-07-20"},
    3: {"name": "Pro Championship", "date": "2024-09-10"}
}

@app.route('/api/public/events/<int:event_id>/promo-codes/<code>', methods=['GET'])
@limiter.limit("180 per minute")  # Same rate limit as reported
def validate_promo_code(event_id, code):
    """
    VULNERABLE ENDPOINT
    - No authentication required
    - GET request (easily cacheable/logged)
    - Returns different responses for valid vs invalid codes
    - Allows enumeration attacks
    """
    # Simulate response headers like OpenResty/NGINX
    headers = {
        'Server': 'openresty/1.21.4.1',
        'X-Powered-By': 'PHP/8.3.2',
        'X-RateLimit-Limit': '180',
        'X-RateLimit-Remaining': str(random.randint(50, 179)),
        'Content-Type': 'application/json'
    }

    # Check if event exists
    if event_id not in EVENT_DETAILS:
        response = make_response(jsonify({
            "error": "Event not found",
            "code": 404
        }), 404)
        for key, value in headers.items():
            response.headers[key] = value
        return response

    # Check promo code - THIS IS THE VULNERABILITY
    # Different responses leak information about code validity
    valid_codes = VALID_PROMO_CODES.get(event_id, [])

    if code.upper() in valid_codes:
        # Valid code - returns detailed info (information leak!)
        response_data = {
            "valid": True,
            "code": code.upper(),
            "event_id": event_id,
            "discount_type": "percentage",
            "discount_value": 10,
            "max_uses": 100,
            "uses_remaining": random.randint(10, 90),
            "expires_at": "2024-12-31T23:59:59Z",
            "event": EVENT_DETAILS[event_id]
        }
        status_code = 200
    else:
        # Invalid code - different response structure (information leak!)
        response_data = {
            "valid": False,
            "code": code.upper(),
            "event_id": event_id,
            "error": "Invalid or expired promo code",
            "error_code": "PROMO_CODE_INVALID"
        }
        status_code = 200  # Still 200 OK but with valid: false

    response = make_response(jsonify(response_data), status_code)
    for key, value in headers.items():
        response.headers[key] = value

    return response

@app.route('/api/public/events', methods=['GET'])
def list_events():
    """List all public events - helps attackers find event IDs to enumerate"""
    return jsonify({
        "events": [
            {"id": 1, **EVENT_DETAILS[1]},
            {"id": 2, **EVENT_DETAILS[2]},
            {"id": 3, **EVENT_DETAILS[3]}
        ]
    })

@app.errorhandler(429)
def ratelimit_handler(e):
    """Rate limit exceeded response"""
    return jsonify({
        "error": "Too many requests",
        "message": "Rate limit exceeded. Try again later.",
        "retry_after": 60
    }), 429

if __name__ == '__main__':
    print("=" * 60)
    print("VULNERABLE API SERVER - SIMULATION")
    print("=" * 60)
    print("\nEndpoints:")
    print("  GET /api/public/events              - List all events")
    print("  GET /api/public/events/{id}/promo-codes/{code}  - VULNERABLE: Validate promo code")
    print("\nValid promo codes for event 1: SPRING2024, GAMER50, WELCOME10, NIGHTOWL, EGYPTGAMING")
    print("Rate limit: 180 requests/minute")
    print("=" * 60)
    app.run(host='127.0.0.1', port=8080, debug=False)
