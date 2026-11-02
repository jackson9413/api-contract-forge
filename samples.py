"""Built-in sample contracts for API Contract Forge."""

import json

STRONG_BRIEF = """Orders API v1 - public partner API (version 1.4.0)
Base URL: https://api.example.com/v1
Authentication: OAuth 2.0 bearer token required on every endpoint. Scopes: orders:read, orders:write.
Errors: all errors return JSON with the body {"error": {"code": "invalid_request", "message": "human readable", "request_id": "req_123"}} and an X-Request-Id header. Error codes are stable and machine readable.
Rate limits: 1000 requests per minute per API key. Exceeding the limit returns 429 with a Retry-After header.
Pagination: list endpoints use cursor pagination with limit (integer, default 25, max 100) and cursor (string, optional).
Versioning: the API version is in the path prefix /v1. Additive changes are backward compatible, removals ship in /v2. Deprecated endpoints announce a sunset date at least 90 days ahead.

POST /v1/orders
Creates an order. Body fields: customer_id (string, required), items (array, required), currency (string, required), note (string, optional). Returns 201 with the created order and a Location header. The Idempotency-Key header is supported so retries are safe. Requires scope orders:write.

GET /v1/orders
Lists orders for the authenticated customer. Query params: limit (integer, default 25, max 100), cursor (string, optional), status (string, optional), sort (string, optional). Returns 200 with {"data": [], "next_cursor": "abc", "has_more": true}. Requires scope orders:read. 400 for a malformed filter, 401 without a token, 403 without the scope.

GET /v1/orders/{order_id}
Returns a single order. Path params: order_id (string, required). Returns 200 with the order object. 404 when the order does not exist. 401 without a valid token. Requires scope orders:read.

PATCH /v1/orders/{order_id}
Updates the status of an order. Body fields: status (string, required), reason (string, optional). Requires an If-Match header carrying the current ETag. Returns 200 with the updated order. 404 when missing, 409 on a conflicting transition, 422 when the status value is not allowed. Requires scope orders:write.

DELETE /v1/orders/{order_id}
Cancels an order. Returns 204 with no body. 404 when the order does not exist. Requires scope orders:write.
"""

MESSY_BRIEF = """Payments API

POST /payments
Create a payment. Body: amount, currency, card_number, api_key. Returns 200 with {payment_id, card_number, api_key, createdAt}.

GET /payments
List payments. Returns 200 with {data}.

GET /payments/{paymentId}
Get one payment. Returns 200.

POST /payments/{paymentId}/refund
Refund a payment. Returns 200.

DELETE /payments/{paymentId}
Delete a payment. Returns 200.
"""

WEBHOOK_BRIEF = """Partner Events API v1
Base URL: https://events.example.com/v1
Authentication: bearer token required on every endpoint. Scopes: events:read, events:write.
Webhooks: we POST each event to your endpoint. Event types are order_created, order_paid and order_cancelled. Failed deliveries are retried for 24 hours.
Versioning: the version lives in the path prefix /v1. Deprecated endpoints announce a sunset date at least 90 days ahead. Additive changes stay backward compatible.

GET /v1/events
Lists events. Query params: limit (integer, default 50, max 200), cursor (string, optional). Returns 200 with {"data": [], "next_cursor": "x"}. Requires scope events:read. 401 without a token, 429 when the caller is rate limited, 500 on an unexpected error. A Retry-After header is returned with 429.

POST /v1/subscriptions
Creates a subscription. Body fields: endpoint_url (string, required), event_types (array, required). Returns 201 with the subscription and a Location header. Requires scope events:write. 409 if the endpoint already exists, 422 for an invalid event type.
"""

OPENAPI_SAMPLE = {
    "openapi": "3.0.3",
    "info": {"title": "Payments API", "version": "2026-01-01"},
    "servers": [
        {"url": "https://api.payments.example.com/v2"},
        {"url": "http://staging.payments.example.com/v2"},
    ],
    "security": [{"bearerAuth": ["charges:read"]}],
    "paths": {
        "/charges": {
            "get": {
                "summary": "List charges",
                "operationId": "listCharges",
                "parameters": [
                    {"name": "limit", "in": "query",
                     "schema": {"type": "integer", "default": 25}},
                    {"name": "status", "in": "query", "schema": {"type": "string"}},
                ],
                "responses": {
                    "200": {"description": "A page of charges",
                            "content": {"application/json": {"schema": {
                                "type": "object",
                                "properties": {"data": {"type": "array", "items": {
                                    "$ref": "#/components/schemas/Charge"}}}}}}},
                    "400": {"description": "Invalid filter"},
                    "500": {"description": "Unexpected error"},
                },
            },
            "post": {
                "summary": "Create a charge",
                "operationId": "createCharge",
                "requestBody": {"required": True, "content": {"application/json": {
                    "schema": {"$ref": "#/components/schemas/CreateCharge"}}}},
                "responses": {
                    "200": {"description": "The charge",
                            "content": {"application/json": {
                                "schema": {"$ref": "#/components/schemas/Charge"}}}},
                    "400": {"description": "Invalid request"},
                    "500": {"description": "Unexpected error"},
                },
            },
        },
        "/charges/{chargeId}": {
            "get": {
                "summary": "Fetch a charge",
                "parameters": [{"name": "chargeId", "in": "path", "required": True,
                                "schema": {"type": "string"}}],
                "responses": {
                    "200": {"description": "The charge",
                            "content": {"application/json": {
                                "schema": {"$ref": "#/components/schemas/Charge"}}}},
                    "404": {"description": "Not found"},
                },
            },
            "patch": {
                "parameters": [{"name": "chargeId", "in": "path", "required": True,
                                "schema": {"type": "string"}}],
                "requestBody": {"content": {"application/json": {"schema": {
                    "type": "object",
                    "properties": {"status": {"type": "string"}}}}}},
                "responses": {
                    "200": {"description": "The updated charge"},
                    "404": {"description": "Not found"},
                },
            },
        },
        "/refunds/{refund_id}": {
            "post": {
                "summary": "Create a refund",
                "operationId": "create_refund",
                "requestBody": {"content": {"application/json": {"schema": {
                    "type": "object",
                    "properties": {"amount": {"type": "number"}}}}}},
                "responses": {
                    "200": {"description": "The refund"},
                    "404": {"description": "Not found"},
                },
            },
        },
    },
    "components": {
        "securitySchemes": {"bearerAuth": {"type": "http", "scheme": "bearer"}},
        "schemas": {
            "Charge": {
                "type": "object",
                "properties": {
                    "id": {"type": "string"},
                    "amount": {"type": "number"},
                    "currency": {"type": "string"},
                    "created_at": {"type": "string"},
                    "status": {"type": "string",
                               "enum": ["pending", "settled", "failed"]},
                },
            },
            "CreateCharge": {
                "type": "object",
                "required": ["amount", "currency"],
                "properties": {
                    "amount": {"type": "number"},
                    "currency": {"type": "string"},
                    "card_number": {"type": "string"},
                    "metadata": {"type": "object"},
                },
            },
        },
    },
}

SAMPLES = [
    {
        "id": "orders-brief",
        "title": "Orders API (written brief)",
        "description": "A well-run partner API written in prose: shared error contract, "
                       "cursor pagination, idempotent creates, scoped OAuth.",
        "mode": "brief",
        "content": STRONG_BRIEF,
    },
    {
        "id": "payments-messy",
        "title": "Payments API (rough brief)",
        "description": "A typical first draft: no auth, no errors, no pagination, "
                       "secrets in the payload, mixed casing.",
        "mode": "brief",
        "content": MESSY_BRIEF,
    },
    {
        "id": "payments-openapi",
        "title": "Payments API (OpenAPI 3 JSON)",
        "description": "A structured OpenAPI document with the usual gaps: no 401 or 403, "
                       "an unbounded page size, a missing path parameter, an http server.",
        "mode": "openapi",
        "content": json.dumps(OPENAPI_SAMPLE, indent=2),
    },
    {
        "id": "events-webhook",
        "title": "Partner Events API (webhook delivery)",
        "description": "An event delivery contract with no signature scheme and no "
                       "delivery id, so consumers cannot dedupe or verify payloads.",
        "mode": "brief",
        "content": WEBHOOK_BRIEF,
    },
]

SAMPLE_BY_ID = {s["id"]: s for s in SAMPLES}
