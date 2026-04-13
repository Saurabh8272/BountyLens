"""
BountyLens — Test Case Checklist Engine
========================================
Comprehensive security test case database with:
- OWASP API Security Top 10 (2023) mapped checklists
- HackerOne / Bugcrowd / Hacktify bounty report patterns
- BOLA / BFLA specific deep-dive tests
- Custom checklist support
- Auto-selection based on endpoint parameter analysis
- Three views: per-endpoint, per-parameter, per-vulnerability-class

Each test case has:
- Unique ID, title, description
- OWASP category mapping
- Source (OWASP, HackerOne, Bugcrowd, Custom)
- Severity (critical, high, medium, low, info)
- Auto-select triggers (what param/header patterns activate it)
- Enabled flag (user can toggle on/off)
- Status tracking (pending, pass, fail, na, skipped)
"""

# ──────────────────────────────────────────────
# OWASP API Security Top 10 (2023) Categories
# ──────────────────────────────────────────────

OWASP_CATEGORIES = {
    "API1": {"name": "Broken Object Level Authorization (BOLA)", "severity": "critical"},
    "API2": {"name": "Broken Authentication", "severity": "critical"},
    "API3": {"name": "Broken Object Property Level Authorization", "severity": "high"},
    "API4": {"name": "Unrestricted Resource Consumption", "severity": "medium"},
    "API5": {"name": "Broken Function Level Authorization (BFLA)", "severity": "critical"},
    "API6": {"name": "Unrestricted Access to Sensitive Business Flows", "severity": "high"},
    "API7": {"name": "Server Side Request Forgery (SSRF)", "severity": "high"},
    "API8": {"name": "Security Misconfiguration", "severity": "medium"},
    "API9": {"name": "Improper Inventory Management", "severity": "medium"},
    "API10": {"name": "Unsafe Consumption of APIs", "severity": "medium"},
}

# ──────────────────────────────────────────────
# Master Checklist Database
# ──────────────────────────────────────────────
# Each entry defines:
#   - triggers: dict of conditions that auto-select this test
#     - param_names: list of substrings to match against param names
#     - header_names: list of header names to match
#     - methods: list of HTTP methods
#     - url_patterns: list of substrings to match in URL
#     - has_body: bool
#     - content_types: list of content-type substrings
#     - always: bool (always include)
#   - If ANY trigger group matches, the test is auto-selected

MASTER_CHECKLIST = [
    # ═══════════════════════════════════════════
    # API1: BOLA — Broken Object Level Authorization
    # ═══════════════════════════════════════════
    {
        "id": "BOLA-001",
        "title": "IDOR — Sequential ID enumeration",
        "description": (
            "Replace numeric IDs in URL path or parameters with other values (id+1, id-1, 0, 1, 99999). "
            "Verify the API returns 403/404 and not another user's data. "
            "HackerOne #xxxxx pattern: attacker changed /api/users/123 to /api/users/124 and accessed victim's profile."
        ),
        "owasp": "API1",
        "source": "HackerOne BOLA pattern",
        "severity": "critical",
        "category": "BOLA",
        "triggers": {"param_names": ["id", "uid", "user_id", "userid", "account_id", "accountid", "order_id", "orderid", "profile_id"]},
        "payloads": ["Change ID to another user's ID", "Try ID=0", "Try negative IDs", "Try very large IDs"],
    },
    {
        "id": "BOLA-002",
        "title": "IDOR — UUID/GUID prediction",
        "description": (
            "If the API uses UUIDs, check if they are v1 (time-based, predictable) or v4 (random). "
            "v1 UUIDs can be predicted. Try extracting timestamp from UUID and generating adjacent ones. "
            "Bugcrowd pattern: leaked UUID in response headers enabled accessing other accounts."
        ),
        "owasp": "API1",
        "source": "Bugcrowd BOLA pattern",
        "severity": "critical",
        "category": "BOLA",
        "triggers": {"param_names": ["uuid", "guid", "ref", "reference", "token"]},
        "payloads": ["Check UUID version", "Generate adjacent v1 UUIDs", "Check for UUID leak in responses"],
    },
    {
        "id": "BOLA-003",
        "title": "IDOR — Horizontal privilege escalation via object reference",
        "description": (
            "Access another user's resource by changing object reference in: URL path, query param, "
            "request body, or cookie. Test with two accounts (attacker & victim). "
            "Common in: /users/{id}/orders, /accounts/{id}/settings, /files/{id}/download"
        ),
        "owasp": "API1",
        "source": "HackerOne/Bugcrowd BOLA pattern",
        "severity": "critical",
        "category": "BOLA",
        "triggers": {"url_patterns": ["/users/", "/accounts/", "/profile", "/orders/", "/files/", "/documents/", "/settings"]},
        "payloads": ["Swap user IDs between two test accounts", "Access victim's sub-resources"],
    },
    {
        "id": "BOLA-004",
        "title": "IDOR — Vertical privilege escalation via admin object access",
        "description": (
            "Try accessing admin-level objects with a regular user token. "
            "E.g., GET /api/admin/users/1 with regular user's JWT. "
            "Check if authorization checks are per-object, not just per-endpoint."
        ),
        "owasp": "API1",
        "source": "HackerOne BOLA pattern",
        "severity": "critical",
        "category": "BOLA",
        "triggers": {"url_patterns": ["admin", "manage", "internal", "staff", "superuser", "backoffice"]},
        "payloads": ["Access admin resources with regular user token", "Enumerate admin object IDs"],
    },
    {
        "id": "BOLA-005",
        "title": "IDOR — Parameter pollution to bypass authorization",
        "description": (
            "Send the same parameter multiple times with different values: ?user_id=123&user_id=456. "
            "Some frameworks use the first value for auth check but the last for data retrieval. "
            "Also try: JSON arrays, nested objects, query + body param conflict."
        ),
        "owasp": "API1",
        "source": "Hacktify BOLA pattern",
        "severity": "high",
        "category": "BOLA",
        "triggers": {"param_names": ["id", "user_id", "account", "org_id"]},
        "payloads": ["Duplicate param with two values", "JSON array of IDs", "Param in query + body"],
    },
    {
        "id": "BOLA-006",
        "title": "IDOR — Wildcard / glob access",
        "description": (
            "Try wildcard values: *, all, null, undefined, 0, -1, '', [] in ID parameters. "
            "Some APIs return all records when given special values. "
            "Bugcrowd report: sending user_id=* returned all users' data."
        ),
        "owasp": "API1",
        "source": "Bugcrowd BOLA pattern",
        "severity": "high",
        "category": "BOLA",
        "triggers": {"param_names": ["id", "user_id", "account_id", "org_id", "team_id"]},
        "payloads": ["id=*", "id=all", "id=null", "id=undefined", "id=0", "id=[]"],
    },

    # ═══════════════════════════════════════════
    # API2: Broken Authentication
    # ═══════════════════════════════════════════
    {
        "id": "AUTH-001",
        "title": "Missing authentication — remove auth header entirely",
        "description": (
            "Remove the Authorization/Cookie/X-API-Key header completely. "
            "Verify the API returns 401, not 200 with data. "
            "Many APIs check auth only on some endpoints."
        ),
        "owasp": "API2",
        "source": "OWASP API2",
        "severity": "critical",
        "category": "Authentication",
        "triggers": {"header_names": ["authorization", "x-api-key", "token", "cookie", "x-auth-token", "api-key"]},
        "payloads": ["Remove header entirely", "Send empty value", "Send header name only"],
    },
    {
        "id": "AUTH-002",
        "title": "Broken authentication — expired/invalid JWT",
        "description": (
            "Send expired JWT, JWT with modified claims, JWT with 'none' algorithm, "
            "JWT signed with weak key. Tools: jwt.io, jwt_tool. "
            "HackerOne pattern: alg=none bypass allowed full admin access."
        ),
        "owasp": "API2",
        "source": "HackerOne auth bypass pattern",
        "severity": "critical",
        "category": "Authentication",
        "triggers": {"header_names": ["authorization"]},
        "payloads": ["alg=none JWT", "Expired JWT", "Modified sub/role claim", "HMAC/RSA confusion", "Empty JWT"],
    },
    {
        "id": "AUTH-003",
        "title": "Broken authentication — token from different user",
        "description": (
            "Use User A's token to access User B's endpoint/resource. "
            "Tests whether the API validates token ownership per resource."
        ),
        "owasp": "API2",
        "source": "Bugcrowd auth pattern",
        "severity": "critical",
        "category": "Authentication",
        "triggers": {"header_names": ["authorization", "cookie", "x-auth-token"]},
        "payloads": ["Swap tokens between two test accounts", "Use old/revoked token"],
    },
    {
        "id": "AUTH-004",
        "title": "Brute force — no rate limiting on login/auth",
        "description": (
            "Send 100+ login attempts with different passwords. Check for: rate limiting, "
            "account lockout, CAPTCHA, exponential backoff. "
            "Bugcrowd pattern: no rate limit on /login allowed credential stuffing."
        ),
        "owasp": "API2",
        "source": "Bugcrowd rate limit pattern",
        "severity": "high",
        "category": "Authentication",
        "triggers": {"url_patterns": ["login", "signin", "auth", "authenticate", "token", "oauth"]},
        "payloads": ["100 rapid requests", "Credential stuffing wordlist", "Check response time consistency"],
    },
    {
        "id": "AUTH-005",
        "title": "Password reset token weakness",
        "description": (
            "Test password reset flow: is token predictable? Does it expire? "
            "Can it be reused? Is it tied to the user? "
            "HackerOne: predictable reset tokens allowed account takeover."
        ),
        "owasp": "API2",
        "source": "HackerOne auth pattern",
        "severity": "high",
        "category": "Authentication",
        "triggers": {"url_patterns": ["reset", "forgot", "password", "recover"]},
        "payloads": ["Check token entropy", "Reuse expired token", "Use token for different user"],
    },
    {
        "id": "AUTH-006",
        "title": "API key exposure in client-side code",
        "description": (
            "Check if API keys are hardcoded in JavaScript, mobile app bundles, or public repos. "
            "Search response headers for leaked tokens/keys."
        ),
        "owasp": "API2",
        "source": "OWASP API2",
        "severity": "medium",
        "category": "Authentication",
        "triggers": {"header_names": ["x-api-key", "api-key"]},
        "payloads": ["Check JS source for key", "Search GitHub for leaked keys", "Check response headers"],
    },

    # ═══════════════════════════════════════════
    # API3: Broken Object Property Level Authorization
    # ═══════════════════════════════════════════
    {
        "id": "BOPLA-001",
        "title": "Mass assignment — inject extra fields in request body",
        "description": (
            "Add unauthorized fields to the request body: role, is_admin, verified, status, "
            "balance, price, discount, permissions, privilege_level. "
            "HackerOne: adding 'role=admin' to profile update granted admin access."
        ),
        "owasp": "API3",
        "source": "HackerOne mass assignment pattern",
        "severity": "high",
        "category": "Mass Assignment",
        "triggers": {"methods": ["POST", "PUT", "PATCH"], "has_body": True},
        "payloads": ["role=admin", "is_admin=true", "verified=true", "price=0", "discount=100", "permissions=*"],
    },
    {
        "id": "BOPLA-002",
        "title": "Excessive data exposure — check response for sensitive fields",
        "description": (
            "Examine API response for fields that shouldn't be exposed: "
            "password_hash, ssn, credit_card, internal_id, other users' data, "
            "debug info, stack traces, internal IPs."
        ),
        "owasp": "API3",
        "source": "OWASP API3",
        "severity": "high",
        "category": "Data Exposure",
        "triggers": {"always": True},
        "payloads": ["Check response for password/hash fields", "Check for PII leakage", "Check verbose error responses"],
    },
    {
        "id": "BOPLA-003",
        "title": "Property filtering bypass — nested object injection",
        "description": (
            "If the API filters top-level properties, try nested: "
            '{"user": {"role": "admin"}}, {"__proto__": {"isAdmin": true}}. '
            "Also try dot notation: user.role=admin in form data."
        ),
        "owasp": "API3",
        "source": "Hacktify mass assignment pattern",
        "severity": "high",
        "category": "Mass Assignment",
        "triggers": {"methods": ["POST", "PUT", "PATCH"], "content_types": ["json"]},
        "payloads": ["Nested JSON injection", "Prototype pollution", "Dot notation override"],
    },

    # ═══════════════════════════════════════════
    # API4: Unrestricted Resource Consumption
    # ═══════════════════════════════════════════
    {
        "id": "RATE-001",
        "title": "Rate limiting — missing or insufficient",
        "description": (
            "Send 50-200 requests in rapid succession. Check for 429 responses. "
            "Test from same IP, different IPs, different auth tokens. "
            "Check for per-user vs per-IP limits."
        ),
        "owasp": "API4",
        "source": "Bugcrowd rate limit pattern",
        "severity": "medium",
        "category": "Rate Limiting",
        "triggers": {"methods": ["POST", "PUT", "DELETE"]},
        "payloads": ["50 rapid requests", "100 rapid requests", "Rotate User-Agent headers"],
    },
    {
        "id": "RATE-002",
        "title": "Resource exhaustion — large payload DoS",
        "description": (
            "Send extremely large JSON body (10MB+), deeply nested JSON (1000+ levels), "
            "very long string values, huge arrays. Check for timeout or crash."
        ),
        "owasp": "API4",
        "source": "OWASP API4",
        "severity": "medium",
        "category": "Rate Limiting",
        "triggers": {"methods": ["POST", "PUT", "PATCH"], "has_body": True},
        "payloads": ["10MB JSON body", "1000-level nested JSON", "Array with 100k elements"],
    },
    {
        "id": "RATE-003",
        "title": "Pagination abuse — retrieve all records",
        "description": (
            "Set page_size/limit/per_page to very high values (999999). "
            "Or iterate through all pages to dump entire database. "
            "Check if max limit is enforced server-side."
        ),
        "owasp": "API4",
        "source": "Bugcrowd pagination pattern",
        "severity": "medium",
        "category": "Rate Limiting",
        "triggers": {"param_names": ["page", "limit", "per_page", "page_size", "offset", "count", "size"]},
        "payloads": ["limit=999999", "per_page=100000", "offset=-1", "Iterate all pages"],
    },

    # ═══════════════════════════════════════════
    # API5: BFLA — Broken Function Level Authorization
    # ═══════════════════════════════════════════
    {
        "id": "BFLA-001",
        "title": "BFLA — Access admin endpoint with regular user",
        "description": (
            "Attempt to access admin/management endpoints using a regular user's auth token. "
            "Common admin paths: /admin, /manage, /internal, /debug, /config, /system. "
            "HackerOne: regular user could access /api/admin/users and delete accounts."
        ),
        "owasp": "API5",
        "source": "HackerOne BFLA pattern",
        "severity": "critical",
        "category": "BFLA",
        "triggers": {"url_patterns": ["admin", "manage", "internal", "debug", "config", "system", "backoffice", "staff"]},
        "payloads": ["Regular user token on admin endpoint", "No auth on admin endpoint"],
    },
    {
        "id": "BFLA-002",
        "title": "BFLA — HTTP method tampering",
        "description": (
            "Change HTTP method to discover hidden functionality: GET→POST, POST→PUT, "
            "PUT→DELETE, any→OPTIONS, any→PATCH. "
            "Some APIs only check auth for specific methods."
        ),
        "owasp": "API5",
        "source": "Bugcrowd BFLA pattern",
        "severity": "high",
        "category": "BFLA",
        "triggers": {"always": True},
        "payloads": ["Try all HTTP methods", "HEAD request for auth check bypass", "OPTIONS to discover allowed methods"],
    },
    {
        "id": "BFLA-003",
        "title": "BFLA — Privilege escalation via role parameter",
        "description": (
            "If the API has role-based endpoints, try accessing higher-privilege functions: "
            "regular user → moderator functions, moderator → admin functions. "
            "Test both direct URL access and parameter manipulation."
        ),
        "owasp": "API5",
        "source": "HackerOne BFLA pattern",
        "severity": "critical",
        "category": "BFLA",
        "triggers": {"param_names": ["role", "privilege", "permission", "access_level", "is_admin", "admin", "group"]},
        "payloads": ["Set role=admin", "Set is_admin=true", "Set access_level=superadmin"],
    },
    {
        "id": "BFLA-004",
        "title": "BFLA — Cross-tenant access",
        "description": (
            "In multi-tenant apps, try accessing another tenant/organization's resources. "
            "Change org_id, tenant_id, company_id in headers, params, or JWT claims. "
            "Bugcrowd: tenant ID in subdomain was not validated against auth token."
        ),
        "owasp": "API5",
        "source": "Bugcrowd BFLA pattern",
        "severity": "critical",
        "category": "BFLA",
        "triggers": {"param_names": ["org_id", "tenant_id", "company_id", "workspace_id", "team_id", "org", "tenant"]},
        "payloads": ["Change tenant ID to another org", "Remove tenant header", "JWT tenant claim tampering"],
    },

    # ═══════════════════════════════════════════
    # API6: Unrestricted Access to Sensitive Business Flows
    # ═══════════════════════════════════════════
    {
        "id": "BIZ-001",
        "title": "Business logic — bypass payment/pricing",
        "description": (
            "Manipulate price, amount, quantity, discount in purchase/payment flows. "
            "Try: negative amounts, zero price, extremely large discounts, "
            "modifying currency, race condition on checkout."
        ),
        "owasp": "API6",
        "source": "HackerOne business logic pattern",
        "severity": "critical",
        "category": "Business Logic",
        "triggers": {"param_names": ["price", "amount", "total", "cost", "quantity", "qty", "discount", "coupon", "currency"]},
        "payloads": ["price=0", "amount=-1", "discount=100", "quantity=999999", "currency swap"],
    },
    {
        "id": "BIZ-002",
        "title": "Business logic — skip workflow steps",
        "description": (
            "Try accessing later steps in a multi-step flow without completing earlier ones: "
            "skip verification, skip payment, skip approval. "
            "Directly call the final step's API endpoint."
        ),
        "owasp": "API6",
        "source": "Bugcrowd business logic pattern",
        "severity": "high",
        "category": "Business Logic",
        "triggers": {"url_patterns": ["checkout", "payment", "confirm", "verify", "approve", "submit", "complete", "finalize"]},
        "payloads": ["Skip to final step", "Replay previous step's response", "Modify step/state parameter"],
    },
    {
        "id": "BIZ-003",
        "title": "Business logic — coupon/referral abuse",
        "description": (
            "Apply same coupon multiple times, use expired coupons, "
            "self-referral, referral loop between two accounts. "
            "HackerOne: coupon code could be applied unlimited times."
        ),
        "owasp": "API6",
        "source": "HackerOne business logic pattern",
        "severity": "medium",
        "category": "Business Logic",
        "triggers": {"param_names": ["coupon", "promo", "referral", "voucher", "code", "gift"]},
        "payloads": ["Reuse coupon", "Self-referral", "Expired coupon", "Brute force coupon codes"],
    },

    # ═══════════════════════════════════════════
    # API7: Server Side Request Forgery (SSRF)
    # ═══════════════════════════════════════════
    {
        "id": "SSRF-001",
        "title": "SSRF — internal network access via URL parameter",
        "description": (
            "Inject internal URLs in URL/callback/webhook parameters: "
            "http://127.0.0.1, http://localhost, http://169.254.169.254 (AWS metadata), "
            "http://[::1], http://0.0.0.0, file:///etc/passwd"
        ),
        "owasp": "API7",
        "source": "HackerOne SSRF pattern",
        "severity": "high",
        "category": "SSRF",
        "triggers": {"param_names": ["url", "link", "href", "src", "redirect", "callback", "webhook", "target", "host", "endpoint", "proxy", "fetch", "load", "uri", "path", "destination", "return_url", "redirect_uri", "next"]},
        "payloads": ["http://127.0.0.1", "http://169.254.169.254/latest/meta-data/", "http://[::1]", "file:///etc/passwd"],
    },
    {
        "id": "SSRF-002",
        "title": "SSRF — bypass via DNS rebinding / redirects",
        "description": (
            "If basic SSRF is blocked, try: DNS rebinding (point domain to 127.0.0.1), "
            "open redirect chains, URL shorteners, IPv6 mapping, "
            "decimal IP (2130706433 = 127.0.0.1), octal IP."
        ),
        "owasp": "API7",
        "source": "Bugcrowd SSRF bypass pattern",
        "severity": "high",
        "category": "SSRF",
        "triggers": {"param_names": ["url", "link", "redirect", "callback", "webhook", "target", "fetch"]},
        "payloads": ["DNS rebinding domain", "Decimal IP", "Octal IP", "IPv6 mapped", "Double URL encoding"],
    },

    # ═══════════════════════════════════════════
    # API8: Security Misconfiguration
    # ═══════════════════════════════════════════
    {
        "id": "MISC-001",
        "title": "CORS misconfiguration — wildcard or reflected origin",
        "description": (
            "Send request with Origin: https://evil.com header. "
            "Check if Access-Control-Allow-Origin reflects it or is set to *. "
            "Check if credentials are allowed with wildcard origin."
        ),
        "owasp": "API8",
        "source": "OWASP API8",
        "severity": "medium",
        "category": "Misconfiguration",
        "triggers": {"always": True},
        "payloads": ["Origin: https://evil.com", "Origin: null", "Origin: https://target.com.evil.com"],
    },
    {
        "id": "MISC-002",
        "title": "Verbose error messages — information disclosure",
        "description": (
            "Send malformed requests to trigger error responses. "
            "Check for: stack traces, internal paths, database names, "
            "framework versions, debug info."
        ),
        "owasp": "API8",
        "source": "OWASP API8",
        "severity": "low",
        "category": "Misconfiguration",
        "triggers": {"always": True},
        "payloads": ["Malformed JSON body", "Invalid Content-Type", "Missing required fields", "SQL syntax in params"],
    },
    {
        "id": "MISC-003",
        "title": "Security headers missing",
        "description": (
            "Check response for missing security headers: "
            "Strict-Transport-Security, X-Content-Type-Options, X-Frame-Options, "
            "Content-Security-Policy, X-XSS-Protection, Referrer-Policy."
        ),
        "owasp": "API8",
        "source": "OWASP API8",
        "severity": "low",
        "category": "Misconfiguration",
        "triggers": {"always": True},
        "payloads": ["Check all response headers"],
    },
    {
        "id": "MISC-004",
        "title": "Content-Type manipulation — parser differential",
        "description": (
            "Change Content-Type header: application/json → application/xml, "
            "→ application/x-www-form-urlencoded, → text/plain. "
            "Some APIs process content regardless of declared type."
        ),
        "owasp": "API8",
        "source": "Bugcrowd misconfiguration pattern",
        "severity": "medium",
        "category": "Misconfiguration",
        "triggers": {"has_body": True},
        "payloads": ["Switch to XML", "Switch to form-urlencoded", "Send JSON with XML Content-Type"],
    },
    {
        "id": "MISC-005",
        "title": "HTTP request smuggling / header injection",
        "description": (
            "Test for header injection via CRLF: \\r\\n in header values. "
            "Test Transfer-Encoding vs Content-Length conflicts. "
            "Check for HTTP/2 downgrade issues."
        ),
        "owasp": "API8",
        "source": "HackerOne request smuggling pattern",
        "severity": "high",
        "category": "Misconfiguration",
        "triggers": {"always": True},
        "payloads": ["CRLF injection in headers", "CL.TE smuggling", "TE.CL smuggling"],
    },

    # ═══════════════════════════════════════════
    # API9: Improper Inventory Management
    # ═══════════════════════════════════════════
    {
        "id": "INV-001",
        "title": "API versioning — access old/deprecated endpoints",
        "description": (
            "If the API uses versioning (v1, v2, v3), try older versions. "
            "Old versions often lack security patches. "
            "Try: /api/v1/users when current is /api/v3/users"
        ),
        "owasp": "API9",
        "source": "OWASP API9",
        "severity": "medium",
        "category": "Inventory",
        "triggers": {"url_patterns": ["/v1/", "/v2/", "/v3/", "/api/v"]},
        "payloads": ["Downgrade to v1", "Try v0", "Try /api/internal/", "Try /api/beta/"],
    },
    {
        "id": "INV-002",
        "title": "Hidden endpoints discovery",
        "description": (
            "Look for undocumented endpoints: /debug, /test, /internal, /healthcheck, "
            "/metrics, /swagger, /graphql, /admin, /.env, /config. "
            "Use wordlists for API endpoint fuzzing."
        ),
        "owasp": "API9",
        "source": "Bugcrowd inventory pattern",
        "severity": "medium",
        "category": "Inventory",
        "triggers": {"always": True},
        "payloads": ["Fuzz common paths", "Check /swagger.json", "Check /openapi.json", "Check /.well-known/"],
    },

    # ═══════════════════════════════════════════
    # API10: Unsafe Consumption of APIs
    # ═══════════════════════════════════════════
    {
        "id": "UNSAFE-001",
        "title": "Third-party API injection — via upstream data",
        "description": (
            "If the API consumes third-party APIs, inject payloads via data that "
            "flows through to those services. E.g., webhook callbacks, "
            "payment processor responses, OAuth provider data."
        ),
        "owasp": "API10",
        "source": "OWASP API10",
        "severity": "medium",
        "category": "Unsafe Consumption",
        "triggers": {"param_names": ["webhook", "callback", "redirect_uri", "return_url"]},
        "payloads": ["Inject payload in callback URL", "SSRF via webhook", "XSS via OAuth display_name"],
    },

    # ═══════════════════════════════════════════
    # INJECTION (Cross-cutting — applies to many OWASP categories)
    # ═══════════════════════════════════════════
    {
        "id": "INJ-001",
        "title": "SQL injection — all input parameters",
        "description": (
            "Test each parameter with SQL payloads: ' OR 1=1--, ' UNION SELECT NULL--, "
            "' AND SLEEP(5)--, '; DROP TABLE users--. "
            "Test in: query params, body params, headers (X-Forwarded-For, Referer)."
        ),
        "owasp": "API8",
        "source": "HackerOne/Bugcrowd injection pattern",
        "severity": "critical",
        "category": "Injection",
        "triggers": {"param_names": ["id", "name", "search", "query", "filter", "sort", "order", "q", "keyword", "username", "email", "user"]},
        "payloads": ["' OR 1=1--", "' UNION SELECT NULL--", "' AND SLEEP(5)--", "1; DROP TABLE users--"],
    },
    {
        "id": "INJ-002",
        "title": "NoSQL injection — MongoDB/DynamoDB operators",
        "description": (
            'Test with NoSQL operators: {"$gt": ""}, {"$ne": null}, {"$regex": ".*"}, '
            '{"$where": "sleep(5000)"}. Common in Node.js/MongoDB stacks.'
        ),
        "owasp": "API8",
        "source": "HackerOne NoSQL injection pattern",
        "severity": "critical",
        "category": "Injection",
        "triggers": {"content_types": ["json"]},
        "payloads": ['{"$gt": ""}', '{"$ne": null}', '{"$regex": ".*"}', '{"$where": "sleep(5000)"}'],
    },
    {
        "id": "INJ-003",
        "title": "Command injection — via parameter values",
        "description": (
            "Inject OS commands: ; ls, | cat /etc/passwd, `whoami`, $(id). "
            "Target params that might interact with the OS: filename, path, cmd, exec, run."
        ),
        "owasp": "API8",
        "source": "Bugcrowd command injection pattern",
        "severity": "critical",
        "category": "Injection",
        "triggers": {"param_names": ["file", "filename", "path", "cmd", "exec", "run", "command", "process", "dir", "folder", "name"]},
        "payloads": ["; ls -la", "| cat /etc/passwd", "`whoami`", "$(id)", "& ping -c 3 attacker.com"],
    },
    {
        "id": "INJ-004",
        "title": "XSS — reflected in API response",
        "description": (
            "Inject XSS payloads in every parameter and check if they reflect in response body. "
            "Even APIs that return JSON can be vulnerable if Content-Type is wrong. "
            'Payloads: <script>alert(1)</script>, "><img src=x onerror=alert(1)>'
        ),
        "owasp": "API8",
        "source": "Bugcrowd XSS pattern",
        "severity": "medium",
        "category": "Injection",
        "triggers": {"param_names": ["name", "title", "description", "comment", "message", "search", "q", "query", "input", "text", "content", "bio", "about"]},
        "payloads": ["<script>alert(1)</script>", '"><img src=x onerror=alert(1)>', "{{7*7}}", "${7*7}"],
    },
    {
        "id": "INJ-005",
        "title": "Path traversal — file access via parameters",
        "description": (
            "Inject path traversal payloads: ../../etc/passwd, ..\\..\\windows\\win.ini, "
            "%2e%2e%2f encoded variants, double encoding, null byte injection."
        ),
        "owasp": "API8",
        "source": "HackerOne path traversal pattern",
        "severity": "high",
        "category": "Injection",
        "triggers": {"param_names": ["file", "path", "filename", "name", "doc", "document", "dir", "folder", "template", "attachment", "download"]},
        "payloads": ["../../etc/passwd", "..\\..\\windows\\win.ini", "%2e%2e%2fetc%2fpasswd", "....//....//etc/passwd"],
    },
    {
        "id": "INJ-006",
        "title": "SSTI — Server-side template injection",
        "description": (
            "Inject template expressions: {{7*7}}, ${7*7}, #{7*7}, <%=7*7%>. "
            "If the response contains '49', the server is evaluating templates. "
            "Common in email/notification/PDF generation endpoints."
        ),
        "owasp": "API8",
        "source": "HackerOne SSTI pattern",
        "severity": "critical",
        "category": "Injection",
        "triggers": {"param_names": ["template", "email", "message", "subject", "body", "content", "text", "name", "title", "description"]},
        "payloads": ["{{7*7}}", "${7*7}", "#{7*7}", "<%= 7*7 %>", "{{config}}"],
    },

    # ═══════════════════════════════════════════
    # FILE UPLOAD specific
    # ═══════════════════════════════════════════
    {
        "id": "UPLOAD-001",
        "title": "File upload — unrestricted file type",
        "description": (
            "Upload files with dangerous extensions: .php, .jsp, .aspx, .py, .sh, .exe. "
            "Try bypasses: .php5, .phtml, .php.jpg, null byte (.php%00.jpg), "
            "double extension (.jpg.php), Content-Type mismatch."
        ),
        "owasp": "API8",
        "source": "Bugcrowd file upload pattern",
        "severity": "critical",
        "category": "File Upload",
        "triggers": {"param_names": ["file", "upload", "attachment", "image", "avatar", "photo", "document", "media"], "content_types": ["multipart"]},
        "payloads": ["Upload .php shell", "Double extension bypass", "Content-Type mismatch", "Null byte injection"],
    },

    # ═══════════════════════════════════════════
    # GraphQL specific
    # ═══════════════════════════════════════════
    {
        "id": "GQL-001",
        "title": "GraphQL — introspection query enabled",
        "description": (
            "Send introspection query to dump entire schema: "
            "{__schema{types{name,fields{name,type{name}}}}}. "
            "Reveals all types, queries, mutations, and their arguments."
        ),
        "owasp": "API9",
        "source": "HackerOne GraphQL pattern",
        "severity": "medium",
        "category": "GraphQL",
        "triggers": {"url_patterns": ["graphql", "gql"]},
        "payloads": ["Introspection query", "Query batching", "Alias-based DoS", "Nested query depth attack"],
    },
    {
        "id": "GQL-002",
        "title": "GraphQL — query depth / complexity attack",
        "description": (
            "Send deeply nested queries to exhaust server resources: "
            "{user{friends{friends{friends{friends{name}}}}}}}. "
            "Check for query depth and complexity limits."
        ),
        "owasp": "API4",
        "source": "Bugcrowd GraphQL pattern",
        "severity": "medium",
        "category": "GraphQL",
        "triggers": {"url_patterns": ["graphql", "gql"]},
        "payloads": ["20-level nested query", "1000 aliases in one query", "Fragment cycle attack"],
    },
]

# ──────────────────────────────────────────────
# Custom Checklists Store
# ──────────────────────────────────────────────
custom_checklists: list[dict] = []


# ──────────────────────────────────────────────
# Auto-Selection Engine
# ──────────────────────────────────────────────

def auto_select_tests(endpoint: dict) -> list[dict]:
    """
    Analyze endpoint and return matching test cases with enabled flag.
    Returns list of test case dicts with 'auto_selected' and 'enabled' fields.
    """
    url = endpoint.get("url", "").lower()
    method = endpoint.get("method", "GET").upper()
    headers = endpoint.get("headers", {})
    query_params = endpoint.get("query_params", {})
    body_params = endpoint.get("body_params", {})
    content_type = endpoint.get("content_type", "").lower()
    has_body = bool(body_params)

    all_param_names = [p.lower() for p in list(query_params.keys()) + list(body_params.keys())]
    header_names = [h.lower() for h in headers.keys()]

    results = []
    all_tests = MASTER_CHECKLIST + custom_checklists

    for tc in all_tests:
        triggers = tc.get("triggers", {})
        matched = False
        match_reasons = []

        # Check 'always' trigger
        if triggers.get("always"):
            matched = True
            match_reasons.append("always applicable")

        # Check param name triggers
        trigger_params = triggers.get("param_names", [])
        if trigger_params:
            matched_params = [p for p in all_param_names if any(t in p for t in trigger_params)]
            if matched_params:
                matched = True
                match_reasons.append(f"param match: {', '.join(matched_params)}")

        # Check header name triggers
        trigger_headers = triggers.get("header_names", [])
        if trigger_headers:
            matched_headers = [h for h in header_names if h in trigger_headers]
            if matched_headers:
                matched = True
                match_reasons.append(f"header match: {', '.join(matched_headers)}")

        # Check method triggers
        trigger_methods = triggers.get("methods", [])
        if trigger_methods and method in trigger_methods:
            matched = True
            match_reasons.append(f"method match: {method}")

        # Check URL pattern triggers
        trigger_urls = triggers.get("url_patterns", [])
        if trigger_urls:
            matched_urls = [u for u in trigger_urls if u in url]
            if matched_urls:
                matched = True
                match_reasons.append(f"URL match: {', '.join(matched_urls)}")

        # Check has_body trigger
        if triggers.get("has_body") and has_body:
            matched = True
            match_reasons.append("has request body")

        # Check content_type triggers
        trigger_ct = triggers.get("content_types", [])
        if trigger_ct:
            if any(ct in content_type for ct in trigger_ct):
                matched = True
                match_reasons.append(f"content-type match: {content_type}")

        result = {
            **tc,
            "auto_selected": matched,
            "enabled": matched,  # auto-enabled if matched, user can toggle
            "match_reasons": match_reasons if matched else [],
            "status": "pending",
            "evidence": "",
            "tested_at": None,
            "tested_by": "",
            "notes": "",
            "target_params": [],  # which specific params this applies to
        }

        # Identify target parameters for per-parameter view
        if trigger_params:
            result["target_params"] = [p for p in all_param_names if any(t in p for t in trigger_params)]

        results.append(result)

    return results


def get_per_parameter_view(test_cases: list[dict], endpoint: dict) -> dict:
    """Organize test cases by parameter for the per-parameter view."""
    all_params = list(endpoint.get("query_params", {}).keys()) + list(endpoint.get("body_params", {}).keys())
    header_params = list(endpoint.get("headers", {}).keys())

    param_view = {}

    # Initialize all params
    for p in all_params:
        param_view[f"param:{p}"] = {"type": "parameter", "name": p, "tests": []}
    for h in header_params:
        param_view[f"header:{h}"] = {"type": "header", "name": h, "tests": []}
    param_view["_general"] = {"type": "general", "name": "General / Endpoint-level", "tests": []}

    for tc in test_cases:
        assigned = False
        target_params = tc.get("target_params", [])

        if target_params:
            for tp in target_params:
                key = f"param:{tp}"
                if key in param_view:
                    param_view[key]["tests"].append(tc["id"])
                    assigned = True

        # Check header triggers
        trigger_headers = tc.get("triggers", {}).get("header_names", [])
        if trigger_headers:
            for h in header_params:
                if h.lower() in trigger_headers:
                    key = f"header:{h}"
                    if key in param_view:
                        param_view[key]["tests"].append(tc["id"])
                        assigned = True

        if not assigned:
            param_view["_general"]["tests"].append(tc["id"])

    return param_view


def get_per_vuln_class_view(test_cases: list[dict]) -> dict:
    """Organize test cases by vulnerability class."""
    vuln_view = {}
    for tc in test_cases:
        cat = tc.get("category", "Other")
        if cat not in vuln_view:
            vuln_view[cat] = {
                "owasp": tc.get("owasp", ""),
                "owasp_name": OWASP_CATEGORIES.get(tc.get("owasp", ""), {}).get("name", ""),
                "tests": [],
            }
        vuln_view[cat]["tests"].append(tc["id"])
    return vuln_view


# ──────────────────────────────────────────────
# Helper: Summary stats for a set of test cases
# ──────────────────────────────────────────────

def test_case_stats(test_cases: list[dict], enabled_only: bool = False) -> dict:
    """Calculate stats for a list of test cases."""
    cases = [tc for tc in test_cases if tc.get("enabled")] if enabled_only else test_cases
    total = len(cases)
    passed = sum(1 for tc in cases if tc["status"] == "pass")
    failed = sum(1 for tc in cases if tc["status"] == "fail")
    na = sum(1 for tc in cases if tc["status"] == "na")
    skipped = sum(1 for tc in cases if tc["status"] == "skipped")
    pending = sum(1 for tc in cases if tc["status"] == "pending")
    done = passed + failed + na + skipped

    return {
        "total": total,
        "enabled": sum(1 for tc in test_cases if tc.get("enabled")),
        "disabled": sum(1 for tc in test_cases if not tc.get("enabled")),
        "passed": passed,
        "failed": failed,
        "na": na,
        "skipped": skipped,
        "pending": pending,
        "done": done,
        "coverage_pct": (done / total * 100) if total > 0 else 0,
    }
