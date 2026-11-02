"""API Contract Forge - analysis engine.

Parses an API contract (free-form brief or OpenAPI 3 JSON) and produces a
readiness review: a 6-axis scorecard, ranked findings with concrete fixes, a
prioritised fix plan, example payloads, and a starter OpenAPI document.

No network calls, no API keys, standard library only.
"""

from __future__ import annotations

import json
import re
from typing import Any, Dict, List, Optional, Tuple

AXES: List[Tuple[str, str]] = [
    ("naming", "Naming & consistency"),
    ("errors", "Error design"),
    ("idempotency", "Idempotency & retries"),
    ("pagination", "Pagination & listing"),
    ("security", "Security & access"),
    ("versioning", "Versioning & compatibility"),
]

PROFILES: Dict[str, Dict[str, Any]] = {
    "rest": {
        "label": "General REST API",
        "weights": {"naming": 0.20, "errors": 0.22, "idempotency": 0.16,
                    "pagination": 0.12, "security": 0.22, "versioning": 0.08},
    },
    "public": {
        "label": "Public / partner API",
        "weights": {"naming": 0.12, "errors": 0.22, "idempotency": 0.12,
                    "pagination": 0.08, "security": 0.28, "versioning": 0.18},
    },
    "internal": {
        "label": "Internal service API",
        "weights": {"naming": 0.24, "errors": 0.24, "idempotency": 0.18,
                    "pagination": 0.12, "security": 0.14, "versioning": 0.08},
    },
    "webhook": {
        "label": "Webhook / event API",
        "weights": {"naming": 0.08, "errors": 0.20, "idempotency": 0.28,
                    "pagination": 0.08, "security": 0.16, "versioning": 0.20},
    },
}

SEVERITY_POINTS = {"high": 12, "medium": 7, "low": 3}

VALID_STATUS = {
    200, 201, 202, 203, 204, 206, 301, 302, 304, 307, 308,
    400, 401, 402, 403, 404, 405, 406, 409, 410, 412, 413, 415,
    422, 423, 424, 428, 429, 431, 451,
    500, 501, 502, 503, 504, 507, 511,
}

VERDICTS = [
    (85, "prod_ready", "Production ready"),
    (70, "mostly_ready", "Mostly ready"),
    (55, "needs_polish", "Needs polish"),
    (40, "tight_but_usable", "Tight but usable"),
    (0, "needs_rework", "Needs rework"),
]

VERB_SEGMENTS = {
    "get", "fetch", "create", "update", "delete", "remove", "list", "make",
    "set", "post", "put", "patch", "process", "cancel", "approve", "reject",
    "send", "sync", "import", "export", "generate", "do", "handle", "trigger",
    "refund", "activate", "deactivate", "retry", "reset", "reverse",
}

SENSITIVE_HINTS = (
    "password", "passwd", "secret", "token", "api_key", "apikey", "ssn",
    "social_security", "card_number", "cardnumber", "cvv", "cvc",
    "credit_card", "private_key", "credential", "otp", "pin", "salt",
    "signature_key", "auth_key", "access_key",
)

AUTH_WORDS = ("auth", "oauth", "bearer", "api key", "api-key", "apikey",
              "jwt", "token", "session", "credential", "scope", "permission",
              "signature", "hmac")

PAGINATION_PARAMS = ("limit", "offset", "cursor", "page", "page_size",
                     "per_page", "size", "after", "before", "starting_after")

PAGINATION_META = ("next_cursor", "next_page", "has_more", "hasnextpage",
                   "total", "total_count", "links", "next", "cursor",
                   "page_info", "pagination")


# --------------------------------------------------------------------------
# small helpers
# --------------------------------------------------------------------------

def _case_style(name: str) -> str:
    if not name:
        return "unknown"
    if re.fullmatch(r"[a-z][a-z0-9]*([A-Z][a-z0-9]*)+", name):
        return "camelCase"
    if re.fullmatch(r"[A-Z][a-z0-9]*([A-Z][a-z0-9]*)*", name) and not name.isupper():
        return "PascalCase"
    if "_" in name and re.fullmatch(r"[a-z][a-z0-9_]*", name):
        return "snake_case"
    return "single"


def _plural(word: str) -> bool:
    w = word.lower()
    if w.endswith("ies") and len(w) > 4:
        return True
    if w.endswith("s") and not w.endswith("ss"):
        return True
    return False


def _dedupe(items: List[str], limit: int = 6) -> List[str]:
    seen, out = set(), []
    for it in items:
        if it not in seen:
            seen.add(it)
            out.append(it)
        if len(out) >= limit:
            break
    return out


def _norm_type(raw: Optional[str]) -> str:
    if not raw:
        return "string"
    t = raw.strip().lower().replace(" ", "")
    t = t.replace("<", "").replace(">", "")
    if t.startswith("array<"):
        return "array"
    if t in ("int", "integer", "long", "int64"):
        return "integer"
    if t in ("float", "double", "decimal", "number"):
        return "number"
    if t in ("bool", "boolean"):
        return "boolean"
    if t in ("array", "list"):
        return "array"
    if t in ("object", "map", "dict"):
        return "object"
    if t in ("str", "string", "uuid", "date", "datetime", "email"):
        return "string"
    return t or "string"


def _parse_meta(inner: str) -> Dict[str, Any]:
    meta: Dict[str, Any] = {"type": "string", "required": False,
                             "default": None, "max": None}
    if not inner:
        return meta
    parts = [p.strip() for p in inner.split(",") if p.strip()]
    if not parts:
        return meta
    first = parts[0].lower()
    if first not in ("required", "optional", "mandatory", "nullable"):
        meta["type"] = _norm_type(parts[0])
    for part in parts[1:]:
        low = part.lower()
        if low in ("required", "mandatory"):
            meta["required"] = True
        elif low in ("optional", "nullable"):
            meta["required"] = False
        m = re.search(r"default\s*=?\s*([A-Za-z0-9_.]+)", part, re.I)
        if m:
            raw = m.group(1)
            meta["default"] = int(raw) if raw.isdigit() else raw
        m = re.search(r"max(?:imum)?\s*=?\s*(\d+)", part, re.I)
        if m:
            meta["max"] = int(m.group(1))
    return meta


# --------------------------------------------------------------------------
# brief parsing
# --------------------------------------------------------------------------

ENDPOINT_RE = re.compile(
    r"(?im)(?:^|[\s(\[\"'])(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\b\s+"
    r"((?:https?://[^\s\"']+|/[A-Za-z0-9_{}.\-/]*))"
)

FIELD_RE = re.compile(
    r"([A-Za-z_][A-Za-z0-9_]*)\s*(?:\(([^)]*)\)|:\s*([A-Za-z][A-Za-z0-9\[\]]*))"
)

SECTION_RE = re.compile(
    r"(?i)(?:\A|[\n;]|(?<=[.!?])\s)\s*"
    r"(body(?:\s+(?:fields?|payload|schema))?|fields?|payload|"
    r"query(?:\s+(?:params?|parameters?|params|string))?|"
    r"path\s+params?|url\s+params?|headers?|"
    r"response(?:\s+body)?|returns?|responds?|"
    r"error\s+responses?|errors?|"
    r"auth(?:orization)?|scopes?|permissions?|"
    r"idempoten(?:cy|t)|retry[- ]safe|webhooks?|pagination|deprecated)"
    r"(?:\s*[:\-–]\s*|\s+(?=\d{3}\b))"
)

SECTION_KEYS = {
    "body": "body", "body fields": "body", "body payload": "body",
    "body schema": "body", "fields": "body", "payload": "body",
    "query": "query", "query params": "query", "query parameters": "query",
    "query string": "query",
    "path params": "path_params", "url params": "path_params",
    "headers": "headers", "response": "response", "response body": "response",
    "returns": "response", "responds": "response",
    "error responses": "errors", "errors": "errors",
    "auth": "auth", "scopes": "auth",
    "permissions": "auth", "idempotency": "idempotency",
    "idempotent": "idempotency", "retry-safe": "idempotency",
    "webhooks": "webhooks", "pagination": "response",
    "deprecated": "deprecated",
}


def _sections(block: str) -> Dict[str, str]:
    out: Dict[str, str] = {}
    marks = list(SECTION_RE.finditer(block))
    for i, m in enumerate(marks):
        marker = m.group(1).strip().lower().replace("authoriz" + "ation", "auth")
        key = SECTION_KEYS.get(marker)
        if not key:
            continue
        start = m.end()
        end = marks[i + 1].start() if i + 1 < len(marks) else len(block)
        chunk = block[start:end].strip()
        if key not in out or len(chunk) > len(out[key]):
            out[key] = chunk
    return out


def _fields_from(text: str) -> List[Dict[str, Any]]:
    fields: List[Dict[str, Any]] = []
    for m in FIELD_RE.finditer(text or ""):
        name = m.group(1)
        inner = m.group(2) if m.group(2) is not None else m.group(3)
        if not name:
            continue
        meta = _parse_meta(inner or "")
        fields.append({
            "name": name,
            "type": meta["type"],
            "required": meta["required"],
            "default": meta["default"],
            "max": meta["max"],
        })
    return fields


def _jsonish_keys(text: str) -> List[str]:
    keys: List[str] = []
    for m in re.finditer(r"[\"']?([A-Za-z_][A-Za-z0-9_]*)[\"']?\s*:\s*"
                         r"(\"[^\"]*\"|'[^']*'|\d+|\[|\{|true|false|null)", text or ""):
        keys.append(m.group(1))
    return _dedupe(keys, 12)


def _bare_fields(text: str) -> List[str]:
    out = []
    for part in (text or "").split(","):
        p = part.strip()
        if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", p):
            out.append(p)
    return _dedupe(out, 16)


def _brace_list_fields(text: str) -> List[str]:
    out = []
    for m in re.finditer(r"\{([^{}]*)\}", text or ""):
        inner = m.group(1)
        if ":" in inner:
            continue
        for part in inner.split(","):
            p = part.strip()
            if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", p):
                out.append(p)
    return _dedupe(out, 16)


def _clean_path(raw: str) -> str:
    p = (raw or "").strip().strip("\"'")
    p = p.rstrip(".,;)")
    if "://" in p:
        rest = p.split("://", 1)[1]
        idx = rest.find("/")
        p = rest[idx:] if idx >= 0 else "/"
    p = p.split("?")[0].split("#")[0]
    if not p.startswith("/"):
        p = "/" + p
    if len(p) > 1:
        p = p.rstrip("/")
    return p or "/"


def _statuses(block: str) -> List[int]:
    found = []
    for m in re.finditer(r"(?<![\d.])([1-5]\d{2})(?![\d.])", block or ""):
        code = int(m.group(1))
        if code in VALID_STATUS and code not in found:
            found.append(code)
    return sorted(found)


def _scopes(text: str) -> List[str]:
    scopes = []
    for m in re.finditer(r"\b([a-z][a-z0-9_-]*:[a-z0-9_*.-]+)\b", text or ""):
        scopes.append(m.group(1))
    return _dedupe(scopes, 6)


def _endpoint_from_brief(method: str, path: str, block: str) -> Dict[str, Any]:
    secs = _sections(block)
    low = block.lower()
    body_fields = _fields_from(secs.get("body", ""))
    if not body_fields:
        body_fields = [{"name": n, "type": "string", "required": False,
                        "default": None, "max": None}
                       for n in _bare_fields(secs.get("body", ""))]
    query_fields = _fields_from(secs.get("query", ""))
    path_fields = _fields_from(secs.get("path_params", ""))
    header_fields = _fields_from(secs.get("headers", ""))
    response_text = secs.get("response", "")
    response_fields = [{"name": k, "type": "string"} for k in _jsonish_keys(response_text)]
    if not response_fields:
        response_fields = [{"name": k, "type": "string"}
                           for k in _brace_list_fields(response_text)]
    statuses = _statuses(block)
    errors = {str(c): "" for c in statuses if c >= 400}
    auth = any(w in low for w in AUTH_WORDS)
    scopes = _scopes(block)
    params = [p["name"] for p in query_fields]
    pagination = any(p.lower() in PAGINATION_PARAMS for p in params) or "cursor" in low
    summary = ""
    first_line = block.split("\n")[0].strip()
    if first_line and first_line.upper() != method:
        summary = first_line
    return {
        "method": method.upper(),
        "path": path,
        "summary": summary[:160],
        "operation_id": "",
        "body_fields": body_fields,
        "query_fields": query_fields,
        "path_fields": path_fields,
        "header_fields": header_fields,
        "response_fields": response_fields,
        "response_text": response_text,
        "statuses": statuses,
        "errors": errors,
        "auth": auth,
        "scopes": scopes,
        "idempotent": ("idempoten" in low or "retry-safe" in low or "safe to retry" in low),
        "pagination": pagination,
        "filters": any(w in low for w in ("filter", "sort", "order_by", "orderby",
                                          "search", "query by")),
        "mutating": any(w in low for w in ("increment", "consume", "mark as read",
                                           "reset", "trigger", "fire", "send email",
                                           "publish", "acknowledge")),
        "async": ("202" in [str(s) for s in statuses] or "async" in low
                  or "long-running" in low or "background" in low),
        "deprecated": "deprecated" in low,
        "is_collection": False,
        "raw": block,
    }


def parse_brief(text: str) -> Dict[str, Any]:
    matches = list(ENDPOINT_RE.finditer(text or ""))
    endpoints: List[Dict[str, Any]] = []
    preamble = text or ""
    for i, m in enumerate(matches):
        method = m.group(1).upper()
        path = _clean_path(m.group(2))
        if not path or path == "/":
            continue
        start = m.start()
        end = matches[i + 1].start() if i + 1 < len(matches) else len(text or "")
        block = (text or "")[start:end]
        ep = _endpoint_from_brief(method, path, block)
        ep["is_collection"] = ("{" not in path)
        endpoints.append(ep)
        if i == 0:
            preamble = (text or "")[:start]
    title = ""
    first = (preamble or text or "").strip().split("\n")[0].strip()
    if first:
        title = first[:120]
    version = ""
    vm = re.search(r"\bv(\d+)\b", text or "")
    if vm:
        version = vm.group(1)
    else:
        vm2 = re.search(r"\bversion[:\s]+([0-9][0-9A-Za-z.\-]*)", text or "", re.I)
        if vm2:
            version = vm2.group(1)
    low = (text or "").lower()
    auth_declared = any(w in low for w in AUTH_WORDS)
    rate_limit = any(w in low for w in
                     ("rate limit", "rate-limit", "ratelimit", "429", "throttle",
                      "requests per", "requests/minute", "quota"))
    global_error = bool(re.search(
        r"(?i)\b(all errors|every error|error (?:format|shape|body|contract|response))\b",
        text or ""))
    webhook_global = "webhook" in low
    servers = re.findall(r"(?im)^\s*(?:base\s*url|server|host)\s*:\s*(\S+)", text or "")
    return {
        "mode": "brief",
        "title": title,
        "version": version,
        "servers": servers,
        "endpoints": endpoints,
        "text": text or "",
        "preamble": preamble,
        "auth_declared": auth_declared,
        "rate_limit": rate_limit,
        "global_error": global_error,
        "webhook_global": webhook_global,
        "fields_global": [],
    }


# --------------------------------------------------------------------------
# OpenAPI parsing
# --------------------------------------------------------------------------

def _resolve(doc: Dict[str, Any], schema: Any, depth: int = 0) -> Dict[str, Any]:
    if not isinstance(schema, dict) or depth > 4:
        return {}
    ref = schema.get("$ref")
    if isinstance(ref, str) and ref.startswith("#/components/schemas/"):
        name = ref.rsplit("/", 1)[-1]
        schemas = doc.get("components", {}).get("schemas", {}) or {}
        return _resolve(doc, schemas.get(name, {}), depth + 1)
    return schema


def _schema_fields(doc: Dict[str, Any], schema: Any) -> List[Dict[str, Any]]:
    resolved = _resolve(doc, schema)
    props = resolved.get("properties") or {}
    required = set(resolved.get("required") or [])
    fields = []
    for name, sch in props.items():
        sch = sch if isinstance(sch, dict) else {}
        ftype = "object" if sch.get("$ref") else _norm_type(sch.get("type") or "string")
        fields.append({
            "name": name,
            "type": ftype,
            "required": name in required,
            "default": sch.get("default"),
            "max": sch.get("maximum"),
        })
    return fields


def parse_openapi(doc: Dict[str, Any]) -> Dict[str, Any]:
    endpoints: List[Dict[str, Any]] = []
    paths = doc.get("paths") or {}
    global_security = doc.get("security") or []
    for path, item in paths.items():
        if not isinstance(item, dict):
            continue
        shared_params = item.get("parameters") or []
        for method in ("get", "post", "put", "patch", "delete", "head", "options"):
            op = item.get(method)
            if not isinstance(op, dict):
                continue
            params = list(shared_params) + list(op.get("parameters") or [])
            path_fields: List[Dict[str, Any]] = []
            query_fields: List[Dict[str, Any]] = []
            header_fields: List[Dict[str, Any]] = []
            for p in params:
                if not isinstance(p, dict):
                    continue
                sch = _resolve(doc, p.get("schema") or {})
                entry = {
                    "name": p.get("name", ""),
                    "type": _norm_type(sch.get("type") or "string"),
                    "required": bool(p.get("required")),
                    "default": sch.get("default"),
                    "max": sch.get("maximum"),
                }
                where = (p.get("in") or "").lower()
                if where == "path":
                    path_fields.append(entry)
                elif where == "query":
                    query_fields.append(entry)
                elif where == "header":
                    header_fields.append(entry)
            body_fields: List[Dict[str, Any]] = []
            rb = op.get("requestBody") or {}
            content = rb.get("content") or {}
            for _ctype, cobj in content.items():
                if isinstance(cobj, dict) and cobj.get("schema"):
                    body_fields = _schema_fields(doc, cobj["schema"])
                    break
            statuses: List[int] = []
            errors: Dict[str, str] = {}
            response_fields: List[Dict[str, Any]] = []
            responses = op.get("responses") or {}
            for code, robj in responses.items():
                try:
                    ic = int(code)
                except (TypeError, ValueError):
                    continue
                statuses.append(ic)
                desc = ""
                if isinstance(robj, dict):
                    desc = str(robj.get("description") or "")
                    c = robj.get("content") or {}
                    for _ct, cobj in c.items():
                        if isinstance(cobj, dict) and cobj.get("schema"):
                            rf = _schema_fields(doc, cobj["schema"])
                            if rf and not response_fields:
                                response_fields = rf
                            break
                if ic >= 400:
                    errors[str(ic)] = desc
            sec = op.get("security")
            if sec is None:
                sec = global_security
            scopes: List[str] = []
            for s in sec or []:
                if isinstance(s, dict):
                    scopes.extend(list(s.keys()))
            endpoints.append({
                "method": method.upper(),
                "path": path,
                "summary": str(op.get("summary") or op.get("description") or "")[:160],
                "operation_id": str(op.get("operationId") or ""),
                "body_fields": body_fields,
                "query_fields": query_fields,
                "path_fields": path_fields,
                "header_fields": header_fields,
                "response_fields": response_fields,
                "response_text": "",
                "statuses": sorted(set(statuses)),
                "errors": errors,
                "auth": bool(sec),
                "scopes": _dedupe(scopes, 6),
                "idempotent": "idempoten" in json.dumps(op).lower(),
                "pagination": any(p["name"].lower() in PAGINATION_PARAMS for p in query_fields),
                "filters": any(p["name"].lower() in ("filter", "sort", "order_by", "orderby",
                                                     "search", "q", "status")
                               for p in query_fields),
                "mutating": False,
                "async": 202 in statuses,
                "deprecated": bool(op.get("deprecated")),
                "is_collection": "{" not in path,
                "raw": json.dumps(op),
            })
    info = doc.get("info") or {}
    servers = [s.get("url", "") for s in (doc.get("servers") or []) if isinstance(s, dict)]
    text = json.dumps(doc, indent=2)
    low = text.lower()
    components = doc.get("components") or {}
    auth_declared = bool(components.get("securitySchemes") or doc.get("security"))
    rate_limit = ("429" in text or "ratelimit" in low or "rate limit" in low
                  or "rate-limit" in low)
    schema_names = list((components.get("schemas") or {}).keys())
    global_error = any("error" in str(n).lower() for n in schema_names)
    webhook_global = "webhook" in low
    return {
        "mode": "openapi",
        "title": str(info.get("title") or ""),
        "version": str(info.get("version") or ""),
        "servers": servers,
        "endpoints": endpoints,
        "text": text,
        "preamble": "",
        "auth_declared": auth_declared,
        "rate_limit": rate_limit,
        "global_error": global_error,
        "webhook_global": webhook_global,
        "fields_global": [],
        "doc": doc,
    }


def parse_contract(raw: str, mode: str = "auto") -> Dict[str, Any]:
    raw = raw or ""
    chosen = mode
    if mode == "auto":
        stripped = raw.strip()
        if stripped.startswith("{"):
            try:
                doc = json.loads(stripped)
            except Exception:
                chosen = "brief"
            else:
                if isinstance(doc, dict) and ("paths" in doc or "openapi" in doc):
                    chosen = "openapi"
                else:
                    chosen = "openapi"
        else:
            chosen = "brief"
    if chosen == "openapi":
        try:
            doc = json.loads(raw)
        except Exception as exc:
            raise ValueError("That does not parse as JSON: %s" % exc)
        if not isinstance(doc, dict):
            raise ValueError("OpenAPI input must be a JSON object.")
        return parse_openapi(doc)
    return parse_brief(raw)


# --------------------------------------------------------------------------
# findings
# --------------------------------------------------------------------------

def _f(fid: str, axis: str, severity: str, title: str, why: str, fix: str,
       evidence: Optional[List[str]] = None, endpoint: str = "") -> Dict[str, Any]:
    return {
        "id": fid, "axis": axis, "severity": severity, "title": title,
        "why": why, "fix": fix, "evidence": evidence or [], "endpoint": endpoint,
    }


def _all_field_names(model: Dict[str, Any]) -> List[Tuple[str, str]]:
    out = []
    for ep in model["endpoints"]:
        for key in ("body_fields", "query_fields", "path_fields", "response_fields"):
            for f in ep.get(key, []):
                out.append((f["name"], ep["method"] + " " + ep["path"]))
    return out


# @@APPEND@@

def collect_findings(model: Dict[str, Any]) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    eps = model["endpoints"]
    text = model.get("text") or ""
    low = text.lower()
    mode = model["mode"]

    # ---------------- naming ----------------
    styles: Dict[str, List[str]] = {}
    for name, _where in _all_field_names(model):
        st = _case_style(name)
        if st in ("snake_case", "camelCase", "PascalCase"):
            styles.setdefault(st, []).append(name)
    if len(styles) > 1:
        findings.append(_f(
            "mixed_field_casing", "naming", "medium",
            "Field names mix naming conventions",
            "Mixed casing forces every client to carry a translation layer and makes generated SDKs inconsistent.",
            "Pick one convention for body and query fields (snake_case is the most common) and convert the rest in one pass.",
            ["%s: %s" % (k, ", ".join(_dedupe(v, 6))) for k, v in styles.items()]))

    path_styles: Dict[str, List[str]] = {}
    for ep in eps:
        for seg in ep["path"].strip("/").split("/"):
            if not seg or seg.startswith("{") or re.fullmatch(r"v\d+", seg):
                continue
            st = _case_style(seg)
            if st in ("snake_case", "camelCase", "PascalCase"):
                path_styles.setdefault(st, []).append(seg)
    if len(path_styles) > 1:
        findings.append(_f(
            "mixed_path_casing", "naming", "medium",
            "URL path segments mix naming conventions",
            "Inconsistent path casing breaks routing conventions, caches and SDK method names.",
            "Normalise every path segment to one convention (lowercase kebab-case is the usual REST choice).",
            ["%s: %s" % (k, ", ".join(_dedupe(v, 6))) for k, v in path_styles.items()]))

    versioned = [ep for ep in eps if re.match(r"^/v\d+", ep["path"])]
    unversioned = [ep for ep in eps if not re.match(r"^/v\d+", ep["path"])]
    if versioned and unversioned:
        findings.append(_f(
            "partial_version_prefix", "naming", "medium",
            "Some paths are versioned and others are not",
            "Half-versioned URLs make it impossible to tell which surface a client is pinned to.",
            "Version every path (or every path none) and keep the scheme uniform.",
            ["versioned: %s" % ", ".join(_dedupe([e["path"] for e in versioned], 4)),
             "unversioned: %s" % ", ".join(_dedupe([e["path"] for e in unversioned], 4))]))

    plurals = set()
    for ep in eps:
        seg = ep["path"].strip("/").split("/")
        if not seg:
            continue
        last = seg[-1]
        if "{" in last:
            continue
        plurals.add(_plural(last))
    if len(plurals) > 1:
        findings.append(_f(
            "mixed_collection_naming", "naming", "low",
            "Collection paths mix singular and plural forms",
            "Clients cannot infer whether a path returns one resource or a collection.",
            "Use plural nouns for collections and singular only where a singleton resource is addressed.",
            ["paths: %s" % ", ".join(_dedupe([e["path"] for e in eps], 6))]))

    verbs = []
    for ep in eps:
        for seg in ep["path"].strip("/").split("/"):
            if seg and seg.lower() in VERB_SEGMENTS:
                verbs.append(ep["method"] + " " + ep["path"])
    if verbs:
        findings.append(_f(
            "verb_in_path", "naming", "medium",
            "Paths contain verbs",
            "Verbs in URLs duplicate the HTTP method and make the resource hierarchy unreadable.",
            "Express the action with the method instead: POST /orders rather than POST /createOrder.",
            _dedupe(verbs, 4)))

    deep = [ep["method"] + " " + ep["path"] for ep in eps
            if len([s for s in ep["path"].strip("/").split("/") if s]) > 3]
    if deep:
        findings.append(_f(
            "deep_path_nesting", "naming", "low",
            "Some paths nest more than three levels",
            "Deep nesting usually signals missing sub-resources and becomes painful to extend.",
            "Flatten the hierarchy or expose the nested collection as its own top-level resource.",
            _dedupe(deep, 4)))

    if mode == "openapi":
        op_ids = [ep["operation_id"] for ep in eps]
        missing = [e["method"] + " " + e["path"] for e in eps if not e["operation_id"]]
        if missing:
            findings.append(_f(
                "missing_operation_ids", "naming", "medium",
                "Operations have no operationId",
                "Without operationIds generated SDK method names are guesses and API gateways cannot map routes.",
                "Give every operation a stable, unique operationId (verbNoun, for example listOrders).",
                _dedupe(missing, 5)))
        dupes = [oid for oid in set(op_ids) if oid and op_ids.count(oid) > 1]
        if dupes:
            findings.append(_f(
                "duplicate_operation_id", "naming", "high",
                "Duplicate operationIds",
                "Duplicate operationIds break generated clients and tracing spans.",
                "Make every operationId unique across the document.",
                _dedupe(sorted(dupes), 5)))
        id_styles = set()
        for oid in op_ids:
            if not oid:
                continue
            if re.fullmatch(r"[a-z]+[A-Z][A-Za-z0-9]*", oid):
                id_styles.add("verbNoun")
            elif "_" in oid:
                id_styles.add("snake_case")
            elif re.fullmatch(r"[a-z]+-[a-z-]+", oid):
                id_styles.add("kebab-case")
        if len(id_styles) > 1:
            findings.append(_f(
                "mixed_operation_id_style", "naming", "low",
                "operationIds use more than one naming style",
                "Mixed operationId styles look sloppy in generated clients and docs.",
                "Settle on one style, normally verbNoun camelCase.",
                ["styles found: %s" % ", ".join(sorted(id_styles))]))
        no_summary = [e["method"] + " " + e["path"] for e in eps if not e["summary"]]
        if no_summary:
            findings.append(_f(
                "missing_summaries", "naming", "low",
                "Operations have no summary or description",
                "Undocumented operations force integrators to guess the contract from field names.",
                "Add a one-line summary to every operation.",
                _dedupe(no_summary, 5)))
        declared = set()
        for ep in eps:
            for p in ep["path_fields"]:
                declared.add(p["name"])
        for ep in eps:
            for seg in ep["path"].split("/"):
                m = re.fullmatch(r"\{([A-Za-z0-9_]+)\}", seg)
                if m and m.group(1) not in declared:
                    findings.append(_f(
                        "undeclared_path_param", "naming", "high",
                        "Path placeholder is not declared",
                        "An undeclared placeholder means clients cannot substitute a value correctly.",
                        "Declare every {placeholder} as a required path parameter with a type.",
                        ["%s %s -> {%s}" % (ep["method"], ep["path"], m.group(1))],
                        ep["method"] + " " + ep["path"]))

    # ---------------- errors ----------------
    all_status = [s for ep in eps for s in ep["statuses"]]
    err_status = [s for s in all_status if s >= 400]
    if eps and not err_status:
        findings.append(_f(
            "no_error_responses", "errors", "high",
            "No error responses are documented",
            "Clients cannot build error handling when the failure contract is undefined.",
            "Document the 4xx and 5xx responses for every operation, with a shared error schema.",
            ["%d operations, 0 documented error responses" % len(eps)]))
    if eps and not any(s in (401, 403) for s in all_status):
        findings.append(_f(
            "no_auth_failure_codes", "errors", "high",
            "No 401 or 403 responses",
            "Authentication and authorisation failures are the most common runtime errors in a real integration.",
            "Document 401 (not authenticated) and 403 (authenticated but not allowed) where they apply.",
            ["statuses found: %s" % (", ".join(str(s) for s in sorted(set(all_status))) or "none")]))
    if eps and not any(s == 422 for s in all_status):
        findings.append(_f(
            "no_validation_error_code", "errors", "medium",
            "No dedicated validation error status",
            "Without 422 a client cannot tell a malformed body from a semantically invalid one.",
            "Return 422 with field-level details for validation failures, keep 400 for malformed syntax.",
            ["statuses found: %s" % (", ".join(str(s) for s in sorted(set(all_status))) or "none")]))

    shapes = set()
    for ep in eps:
        if ep["errors"]:
            keys = {f["name"] for f in ep["response_fields"]}
            hit = keys & {"error", "errors", "message", "detail", "reason", "title"}
            if hit:
                shapes |= hit
    if len(shapes) > 1:
        findings.append(_f(
            "inconsistent_error_shape", "errors", "medium",
            "Error bodies use different field names",
            "Every client has to branch on error shape, which is where integration bugs live.",
            "Adopt one error envelope everywhere, for example an error object with code, message and request_id.",
            ["error fields seen: %s" % ", ".join(sorted(shapes))]))
    if re.search(r"(?i)(stack ?trace|sql state|traceback|java\.lang)", text):
        findings.append(_f(
            "error_leaks_internals", "errors", "high",
            "Error responses expose internal detail",
            "Stack traces and internal messages leak implementation detail and help attackers.",
            "Return a generic message plus a request id, and keep the detail in server logs.",
            [m.group(0) for m in re.finditer(
                r"(?i)(stack ?trace|sql state|traceback|java\.lang)", text)][:3]))

    if not model.get("global_error") and eps and err_status:
        findings.append(_f(
            "no_shared_error_contract", "errors", "medium",
            "No shared error contract across endpoints",
            "Without one documented error shape each endpoint invents its own failure format.",
            "Define a single Error schema and reference it from every 4xx and 5xx response.",
            ["%d operations document errors in their own way" % len(eps)]))

    if 429 in all_status and not re.search(r"(?i)retry[- _]?after", text):
        findings.append(_f(
            "no_retry_after", "errors", "medium",
            "429 is documented without Retry-After",
            "Without Retry-After a client cannot back off correctly and will hammer the API.",
            "Return a Retry-After header (and ideally X-RateLimit headers) with every 429.",
            ["429 present, Retry-After absent"]))
    if (503 in all_status or 500 in all_status) and not re.search(r"(?i)retry", text):
        findings.append(_f(
            "no_retry_guidance", "errors", "low",
            "Transient failures have no retry guidance",
            "Clients treat 5xx as permanent errors and fail requests that a retry would fix.",
            "Document which failures are retryable and add a Retry-After header.",
            ["500 or 503 documented without retry guidance"]))
    if not re.search(r"(?i)(request[_ ]?id|correlation[_ ]?id|trace[_ ]?id)", text):
        findings.append(_f(
            "no_correlation_id", "errors", "medium",
            "No request or correlation id",
            "Without a correlation id support cannot trace a failed call back to a log line.",
            "Return a request id in the error body and echo it in the X-Request-Id header.",
            ["no request_id or correlation id mentioned"]))

    creates = [ep for ep in eps if ep["method"] == "POST" and ep["is_collection"]]
    for ep in creates:
        if 201 not in ep["statuses"] and 200 in ep["statuses"]:
            findings.append(_f(
                "create_returns_200", "errors", "medium",
                "Create operation returns 200 instead of 201",
                "200 on creation hides the fact that a new resource exists and loses the Location signal.",
                "Return 201 with a Location header pointing at the new resource.",
                ["%s %s" % (ep["method"], ep["path"])],
                ep["method"] + " " + ep["path"]))
    for ep in eps:
        if "{" in ep["path"] and ep["method"] in ("GET", "PATCH", "PUT", "DELETE"):
            if 404 not in ep["statuses"]:
                findings.append(_f(
                    "missing_404", "errors", "medium",
                    "Addressable resource does not document 404",
                    "Clients treat a missing resource as a transport failure and retry forever.",
                    "Document 404 for every endpoint that addresses a single resource.",
                    ["%s %s" % (ep["method"], ep["path"])],
                    ep["method"] + " " + ep["path"]))

    # ---------------- idempotency ----------------
    if eps and not re.search(r"(?i)idempoten|retry[- ]safe|safe to retry", text):
        findings.append(_f(
            "no_idempotency_policy", "idempotency", "medium",
            "No idempotency or retry policy",
            "Clients cannot decide which calls are safe to retry after a timeout.",
            "State the retry policy per operation and support an Idempotency-Key header on unsafe creates.",
            ["%d operations, no idempotency guidance" % len(eps)]))
    for ep in creates:
        if not ep["idempotent"]:
            findings.append(_f(
                "create_without_idempotency_key", "idempotency", "high",
                "Create operation has no idempotency key",
                "A retried create silently duplicates orders, charges or shipments.",
                "Accept an Idempotency-Key header on POST creates and make replays return the original result.",
                ["%s %s" % (ep["method"], ep["path"])],
                ep["method"] + " " + ep["path"]))
    for ep in eps:
        if ep["method"] == "PATCH" and not re.search(
                r"(?i)if-match|etag|precondition|version|updated_at|last-modified",
                ep.get("raw") or ""):
            findings.append(_f(
                "patch_without_precondition", "idempotency", "medium",
                "PATCH has no concurrency precondition",
                "Two writers silently overwrite each other and clients cannot detect lost updates.",
                "Require If-Match with an ETag, or accept a client-supplied version field.",
                ["%s %s" % (ep["method"], ep["path"])],
                ep["method"] + " " + ep["path"]))
        if ep["method"] == "GET" and ep["mutating"]:
            findings.append(_f(
                "mutating_get", "idempotency", "high",
                "GET endpoint appears to change state",
                "A GET that mutates breaks caching, prefetching and retry safety.",
                "Move the side effect to POST or PATCH and keep GET read-only.",
                ["%s %s" % (ep["method"], ep["path"])],
                ep["method"] + " " + ep["path"]))
        if ep["method"] == "DELETE" and not ep["idempotent"]:
            findings.append(_f(
                "delete_without_idempotency_note", "idempotency", "low",
                "DELETE does not state whether repeats are safe",
                "Clients need to know if a repeated DELETE returns 404 or 204.",
                "Document the repeated-call behaviour and make delete idempotent.",
                ["%s %s" % (ep["method"], ep["path"])],
                ep["method"] + " " + ep["path"]))
    if model.get("webhook_global"):
        if not re.search(r"(?i)event[ _-]?id|delivery[ _-]?id|message[ _-]?id", text):
            findings.append(_f(
                "webhook_without_event_id", "idempotency", "high",
                "Webhooks carry no event or delivery id",
                "Consumers cannot deduplicate redelivered webhooks, which every provider does.",
                "Include a unique event id on every delivery and document that consumers must dedupe on it.",
                ["webhooks are described but no event or delivery id is mentioned"]))
        if not re.search(r"(?i)signatur|hmac|shared secret|verify", text):
            findings.append(_f(
                "webhook_unsigned", "idempotency", "high",
                "Webhook payloads are not signed",
                "An unsigned webhook endpoint is a free-for-all for anyone who finds the URL.",
                "Sign every payload over timestamp plus body and publish a verification guide.",
                ["webhooks are described but no signature scheme is mentioned"]))
        if not re.search(r"(?i)retry|backoff|redeliver", text):
            findings.append(_f(
                "webhook_retry_policy_missing", "idempotency", "medium",
                "Webhook retry behaviour is undefined",
                "Consumers cannot build a retry or replay strategy without knowing the delivery contract.",
                "Publish the retry schedule, the backoff and the replay window.",
                ["no retry or redelivery guidance found"]))

    # ---------------- pagination ----------------
    collections = [ep for ep in eps if ep["is_collection"] and ep["method"] == "GET"]
    for ep in collections:
        names = [p["name"].lower() for p in ep["query_fields"]]
        has_pag = any(n in PAGINATION_PARAMS for n in names)
        if not has_pag and not ep["pagination"]:
            findings.append(_f(
                "list_without_pagination", "pagination", "high",
                "List endpoint has no pagination",
                "Unbounded lists time out, blow up memory and make the response shape unstable.",
                "Add cursor or limit and offset parameters with a documented default and maximum.",
                ["%s %s" % (ep["method"], ep["path"])],
                ep["method"] + " " + ep["path"]))
            continue
        limit_param = next((p for p in ep["query_fields"]
                            if p["name"].lower() in ("limit", "page_size", "per_page", "size")),
                           None)
        if limit_param is not None and limit_param.get("max") is None:
            findings.append(_f(
                "unbounded_page_size", "pagination", "medium",
                "Page size has no maximum",
                "A caller can ask for a million rows and take the database down with it.",
                "Cap the page size (for example max 100) and document the default.",
                ["%s %s -> %s" % (ep["method"], ep["path"], limit_param["name"])],
                ep["method"] + " " + ep["path"]))
        if any(n in ("offset", "page") for n in names) and "cursor" not in names:
            findings.append(_f(
                "offset_pagination", "pagination", "low",
                "Offset pagination without a stable sort key",
                "Offset paging skips or repeats rows when the data changes between pages.",
                "Prefer cursor pagination, or pair offset paging with a stable unique sort key.",
                ["%s %s" % (ep["method"], ep["path"])],
                ep["method"] + " " + ep["path"]))
        meta = {f["name"].lower() for f in ep["response_fields"]}
        if meta and not (meta & set(PAGINATION_META)):
            findings.append(_f(
                "no_pagination_metadata", "pagination", "medium",
                "List response carries no pagination metadata",
                "A client cannot fetch the next page without guessing the cursor format.",
                "Return a next cursor (or next link) and ideally a has_more flag beside the data array.",
                ["%s %s" % (ep["method"], ep["path"])],
                ep["method"] + " " + ep["path"]))
        if not ep["filters"]:
            findings.append(_f(
                "no_filter_or_sort", "pagination", "low",
                "List endpoint exposes no filter or sort parameters",
                "Every consumer has to download the whole collection and filter locally.",
                "Add documented filter and sort query parameters with allow-listed values.",
                ["%s %s" % (ep["method"], ep["path"])],
                ep["method"] + " " + ep["path"]))
    pag_param_sets = set()
    for ep in collections:
        names = tuple(sorted(n for n in (p["name"].lower() for p in ep["query_fields"])
                             if n in PAGINATION_PARAMS))
        if names:
            pag_param_sets.add(names)
    if len(pag_param_sets) > 1:
        findings.append(_f(
            "inconsistent_pagination_params", "pagination", "medium",
            "List endpoints paginate with different parameter names",
            "One client helper cannot work across the collection endpoints.",
            "Use the same pagination parameter names on every list endpoint.",
            ["; ".join(", ".join(s) for s in sorted(pag_param_sets))]))

    # ---------------- security ----------------
    if eps and not model.get("auth_declared"):
        findings.append(_f(
            "no_authentication_declared", "security", "high",
            "No authentication scheme is declared",
            "An unauthenticated contract invites clients to ship credentials in the wrong place, or nothing at all.",
            "Declare the auth scheme (OAuth2, API key, bearer token) and which operations require it.",
            ["no auth, token, key, scope or permission language found"]))
    for ep in eps:
        if ep["method"] in ("PUT", "PATCH", "DELETE") and not ep["auth"]:
            findings.append(_f(
                "write_without_auth", "security", "high",
                "Mutating operation does not require authentication",
                "An unprotected write endpoint is an open door to data loss.",
                "Require authentication and a permission scope on every mutating operation.",
                ["%s %s" % (ep["method"], ep["path"])],
                ep["method"] + " " + ep["path"]))
    if model.get("auth_declared") and not any(ep["scopes"] for ep in eps):
        findings.append(_f(
            "no_scopes_or_permissions", "security", "medium",
            "Authentication without scopes or permissions",
            "Any valid token then grants every operation, which is not what least privilege means.",
            "Declare the scope or role required for each operation and document the token claims.",
            ["auth is mentioned but no scope list was found"]))
    for ep in eps:
        for group, label in (("response_fields", "response"),
                             ("query_fields", "query"),
                             ("path_fields", "path")):
            for f in ep.get(group, []):
                lname = f["name"].lower()
                if any(h in lname for h in SENSITIVE_HINTS):
                    findings.append(_f(
                        "sensitive_field_exposed", "security", "high",
                        "Sensitive-looking field is part of the contract",
                        "Secrets, tokens and full card numbers in a response or URL end up in logs and browser dev tools.",
                        "Never return secrets in a response body, and never carry them in a URL.",
                        ["%s (%s %s)" % (f["name"], label, ep["method"] + " " + ep["path"])],
                        ep["method"] + " " + ep["path"]))
        for f in ep.get("body_fields", []):
            lname = f["name"].lower()
            if any(h in lname for h in SENSITIVE_HINTS):
                findings.append(_f(
            "write_only_secret_not_marked", "security", "low",
            "Secret field in a request body is not marked write-only",
            "A secret that is accepted on the way in can easily be echoed back on the way out.",
            "Mark the field write-only and state that it is never returned in a response.",
            ["%s (%s)" % (f["name"], ep["method"] + " " + ep["path"])],
            ep["method"] + " " + ep["path"]))
    if not model.get("rate_limit"):
        findings.append(_f(
            "no_rate_limit", "security", "medium",
            "No rate limiting is documented",
            "Without limits one integration can degrade the service for everyone else.",
            "Document the limit, the window and the 429 response with a Retry-After header.",
            ["no rate limit, quota or 429 mentioned"]))
    if re.search(r"(?i)allow[- ]?origin[^\n]{0,30}\*|cors[^\n]{0,30}\*", text):
        findings.append(_f(
            "wildcard_cors", "security", "high",
            "Wildcard CORS origin",
            "A wildcard origin lets any website call the API with the user's session.",
            "Allow-list the exact origins that need browser access.",
            ["wildcard origin detected in the contract"]))
    for srv in model.get("servers", []):
        if str(srv).lower().startswith("http://"):
            findings.append(_f(
                "insecure_server_url", "security", "high",
                "Server URL is plain HTTP",
                "Plain HTTP exposes credentials and payloads to anyone on the path.",
                "Serve the API over TLS only and redirect http to https.",
                [str(srv)]))
    if re.search(r"(?i)(sk_live_|xox[baprs]-|AKIA[0-9A-Z]{16}|ghp_[A-Za-z0-9]{20,})", text):
        findings.append(_f(
            "example_looks_like_a_real_secret", "security", "medium",
            "Example value looks like a real credential",
            "Example secrets get copy-pasted into production systems and then published.",
            "Replace examples with obviously fake values such as a test-prefixed key.",
            [m.group(0)[:40] for m in re.finditer(
                r"(?i)(sk_live_[A-Za-z0-9]+|xox[baprs]-[A-Za-z0-9-]+|AKIA[0-9A-Z]{16})", text)][:3]))

    # ---------------- versioning ----------------
    has_version = re.search(r"(?i)(/v\d+|\"version\"\s*:|api[-_ ]version|x-api-version)", text)
    if eps and not has_version:
        findings.append(_f(
            "no_versioning", "versioning", "medium",
            "No versioning scheme",
            "A contract with no version strategy cannot evolve without breaking clients.",
            "Version in the path (/v1) or in a header, and publish the deprecation policy with it.",
            ["no version marker found"]))
    if re.search(r"/v\d+", text) and re.search(r"(?i)(x-api-version|api-version)", text):
        findings.append(_f(
            "version_in_two_places", "versioning", "medium",
            "Version is carried in both the path and a header",
            "Two version sources drift and clients end up on an unexpected contract.",
            "Pick one versioning mechanism and document how mismatches are rejected.",
            ["path prefix and version header both present"]))
    deprecated = [ep for ep in eps if ep["deprecated"]]
    if deprecated and not re.search(r"(?i)sunset|deprecat\w* (date|header|notice)|removal date", text):
        findings.append(_f(
            "deprecated_without_sunset", "versioning", "medium",
            "Deprecated operation has no sunset date",
            "Clients cannot plan migrations when no removal date exists.",
            "Publish a sunset date and return the Deprecation and Sunset headers.",
            ["%s %s" % (ep["method"], ep["path"]) for ep in deprecated][:4]))
    if has_version and not re.search(
            r"(?i)deprecat|sunset|backward[- ]compat|additive", text):
        findings.append(_f(
            "no_compatibility_policy", "versioning", "low",
            "No compatibility or deprecation policy",
            "Without a stated policy, clients assume any change can land at any time.",
            "State the compatibility rules: additions are safe, removals and renames need a new version.",
            ["version marker present but no policy text"]))
    for m in re.finditer(r"(?i)enum\s*:\s*\[([^\]]*)\]", text):
        vals = [v.strip().strip("\"'") for v in m.group(1).split(",") if v.strip()]
        if len(vals) >= 3 and all(re.fullmatch(r"[a-z][a-z0-9_-]*", v) for v in vals):
            findings.append(_f(
                "closed_enum_values", "versioning", "low",
                "Closed enum list is a compatibility trap",
                "A closed enum forces a breaking change the moment a new value appears.",
                "Document unknown-enum behaviour, or model it as a string plus a documented value list.",
                ["values: %s" % ", ".join(vals[:8])]))

    return findings


# --------------------------------------------------------------------------
# scoring
# --------------------------------------------------------------------------

def _verdict(score: float) -> Tuple[str, str]:
    for threshold, key, label in VERDICTS:
        if score >= threshold:
            return key, label
    return "needs_rework", "Needs rework"


def analyze(model: Dict[str, Any], profile: str = "rest") -> Dict[str, Any]:
    profile = profile if profile in PROFILES else "rest"
    weights = PROFILES[profile]["weights"]
    findings = collect_findings(model)
    eps = model["endpoints"]

    axis_scores: Dict[str, float] = {}
    axis_reasons: Dict[str, List[str]] = {}
    for key, _label in AXES:
        pts = sum(SEVERITY_POINTS.get(f["severity"], 5) for f in findings if f["axis"] == key)
        axis_scores[key] = max(0.0, 100.0 - pts)
        axis_reasons[key] = [f["title"] for f in findings if f["axis"] == key][:4]

    caps: Dict[str, str] = {}
    if not eps:
        axis_scores = {k: 0.0 for k in axis_scores}
    else:
        if not model.get("auth_declared"):
            axis_scores["security"] = min(axis_scores["security"], 30.0)
            caps["security"] = "no authentication declared"
        if not any(s >= 400 for ep in eps for s in ep["statuses"]):
            axis_scores["errors"] = min(axis_scores["errors"], 35.0)
            caps["errors"] = "no error responses documented"
        collections = [ep for ep in eps if ep["is_collection"] and ep["method"] == "GET"]
        if collections and not any(ep["pagination"] for ep in collections):
            axis_scores["pagination"] = min(axis_scores["pagination"], 35.0)
            caps["pagination"] = "no list endpoint paginates"
        if not re.search(r"(?i)(/v\d+|\"version\"\s*:|api[-_ ]version|x-api-version)",
                         model.get("text") or ""):
            axis_scores["versioning"] = min(axis_scores["versioning"], 45.0)
            caps["versioning"] = "no versioning scheme"

    overall = sum(axis_scores[k] * weights[k] for k, _l in AXES)
    high = [f for f in findings if f["severity"] == "high"]
    if high:
        overall = min(overall, 79.0)
    overall = round(max(0.0, min(100.0, overall)), 1)
    vkey, vlabel = _verdict(overall)

    severity_rank = {"high": 0, "medium": 1, "low": 2}
    findings.sort(key=lambda f: (severity_rank.get(f["severity"], 3),
                                 -weights.get(f["axis"], 0),
                                 f["axis"], f["title"]))

    counts = {"high": 0, "medium": 0, "low": 0}
    for f in findings:
        counts[f["severity"]] = counts.get(f["severity"], 0) + 1

    axes_out = []
    for key, label in AXES:
        axes_out.append({
            "key": key, "label": label,
            "score": round(axis_scores[key], 1),
            "weight": weights[key],
            "reasons": axis_reasons[key],
            "cap": caps.get(key, ""),
        })

    priorities = [{
        "title": f["title"], "fix": f["fix"], "axis": f["axis"],
        "severity": f["severity"], "why": f["why"], "endpoint": f["endpoint"],
    } for f in findings[:6]]

    stats = {
        "endpoints": len(eps),
        "fields": len(_all_field_names(model)),
        "findings": len(findings),
        "methods": len({ep["method"] for ep in eps}),
        "paths": len({ep["path"] for ep in eps}),
    }

    return {
        "mode": model["mode"],
        "title": model.get("title") or "Untitled API",
        "version": model.get("version") or "",
        "servers": model.get("servers", []),
        "profile": profile,
        "profile_label": PROFILES[profile]["label"],
        "score": overall,
        "verdict": vkey,
        "verdict_label": vlabel,
        "axes": axes_out,
        "findings": findings,
        "counts": counts,
        "stats": stats,
        "priorities": priorities,
        "endpoints": eps,
        "examples": build_examples(model),
        "openapi": build_openapi(model),
        "input_excerpt": (model.get("text") or "")[:400],
    }


# --------------------------------------------------------------------------
# examples + OpenAPI export
# --------------------------------------------------------------------------

def _example_value(f: Dict[str, Any]) -> Any:
    t = f.get("type") or "string"
    name = f.get("name", "")
    lname = name.lower()
    if f.get("default") is not None:
        return f["default"]
    if t == "integer":
        return 42
    if t == "number":
        return 19.99
    if t == "boolean":
        return True
    if t == "array":
        return []
    if t == "object":
        return {}
    if any(k in lname for k in ("id", "_id")) and not lname.startswith("url"):
        return "id_123"
    if "email" in lname:
        return "user@example.com"
    if any(k in lname for k in ("created", "updated", "date", "time", "at")):
        return "2026-01-15T09:30:00Z"
    if any(k in lname for k in ("name", "title")):
        return "Example"
    if any(k in lname for k in ("amount", "price", "total", "cost")):
        return 49.99
    return "string"


def build_examples(model: Dict[str, Any]) -> List[Dict[str, Any]]:
    out = []
    base = model["servers"][0] if model.get("servers") else "https://api.example.com"
    for ep in model["endpoints"]:
        body = None
        if ep["body_fields"]:
            body = {f["name"]: _example_value(f) for f in ep["body_fields"]}
        resp = None
        if ep["response_fields"]:
            resp = {f["name"]: _example_value(f) for f in ep["response_fields"][:8]}
        query = []
        for p in ep["query_fields"]:
            query.append(p["name"] + "=" + str(_example_value(p)))
        url = str(base).rstrip("/") + ep["path"]
        for p in ep["path_fields"]:
            url = url.replace("{%s}" % p["name"], str(_example_value(p)))
        if query:
            url += "?" + "&".join(query)
        curl = "curl -X %s '%s'" % (ep["method"], url)
        if body is not None:
            curl += " -H 'Content-Type: application/json' -d '%s'" % json.dumps(body)
        out.append({
            "method": ep["method"], "path": ep["path"], "summary": ep["summary"],
            "request": body, "response": resp, "curl": curl,
            "statuses": ep["statuses"], "scopes": ep["scopes"],
            "fields": ep["body_fields"], "query": ep["query_fields"],
            "response_fields": ep["response_fields"],
            "errors": ep["errors"],
        })
    return out


def build_openapi(model: Dict[str, Any]) -> Dict[str, Any]:
    info = {
        "title": model.get("title") or "Untitled API",
        "version": model.get("version") or "1.0.0",
    }
    paths: Dict[str, Dict[str, Any]] = {}
    for ep in model["endpoints"]:
        item = paths.setdefault(ep["path"], {})
        op: Dict[str, Any] = {}
        if ep.get("summary"):
            op["summary"] = ep["summary"]
        if ep.get("operation_id"):
            op["operationId"] = ep["operation_id"]
        params = []
        for p in ep["path_fields"]:
            params.append({"name": p["name"], "in": "path", "required": True,
                           "schema": {"type": p.get("type") or "string"}})
        for p in ep["query_fields"]:
            sch: Dict[str, Any] = {"type": p.get("type") or "string"}
            if p.get("default") is not None:
                sch["default"] = p["default"]
            if p.get("max") is not None:
                sch["maximum"] = p["max"]
            params.append({"name": p["name"], "in": "query",
                           "required": bool(p.get("required")), "schema": sch})
        if params:
            op["parameters"] = params
        if ep["body_fields"]:
            props = {}
            required = []
            for f in ep["body_fields"]:
                props[f["name"]] = {"type": f.get("type") or "string"}
                if f.get("required"):
                    required.append(f["name"])
            schema: Dict[str, Any] = {"type": "object", "properties": props}
            if required:
                schema["required"] = required
            op["requestBody"] = {"required": bool(required),
                                  "content": {"application/json": {"schema": schema}}}
        responses: Dict[str, Any] = {}
        for code in ep["statuses"] or [200]:
            desc = "Success" if code < 400 else "Error"
            responses[str(code)] = {"description": desc}
        op["responses"] = responses
        item[ep["method"].lower()] = op
    doc: Dict[str, Any] = {"openapi": "3.0.3", "info": info, "paths": paths}
    if model.get("servers"):
        doc["servers"] = [{"url": s} for s in model["servers"]]
    if model.get("auth_declared"):
        doc["components"] = {
            "securitySchemes": {
                "bearerAuth": {"type": "http", "scheme": "bearer"},
            },
        }
    return doc


def _yaml_scalar(v: Any) -> str:
    if v is None:
        return "null"
    if isinstance(v, bool):
        return "true" if v else "false"
    if isinstance(v, (int, float)):
        return str(v)
    s = str(v)
    if s == "" or re.search(r"[:#\[\]{}&*!|>'\"%@,]|^\s|\s$", s):
        return '"%s"' % s.replace('"', '\\"')
    return s


def to_yaml(obj: Any, indent: int = 0) -> str:
    sp = "  " * indent
    lines: List[str] = []
    if isinstance(obj, dict):
        if not obj:
            return sp + "{}\n"
        for k, v in obj.items():
            if isinstance(v, (dict, list)) and v:
                lines.append("%s%s:" % (sp, k))
                lines.append(to_yaml(v, indent + 1).rstrip("\n"))
            elif isinstance(v, (dict, list)):
                lines.append("%s%s: %s" % (sp, k, "{}" if isinstance(v, dict) else "[]"))
            else:
                lines.append("%s%s: %s" % (sp, k, _yaml_scalar(v)))
    elif isinstance(obj, list):
        if not obj:
            return sp + "[]\n"
        for item in obj:
            if isinstance(item, (dict, list)) and item:
                block = to_yaml(item, indent + 1).rstrip("\n")
                parts = block.split("\n")
                lines.append("%s- %s" % (sp, parts[0].strip()))
                for extra in parts[1:]:
                    lines.append(extra)
            else:
                lines.append("%s- %s" % (sp, _yaml_scalar(item)))
    else:
        lines.append(sp + _yaml_scalar(obj))
    return "\n".join(lines) + "\n"


def render_markdown(report: Dict[str, Any]) -> str:
    lines = []
    lines.append("# API contract review - %s" % report.get("title", "Untitled API"))
    lines.append("")
    lines.append("- Source: %s" % ("OpenAPI document" if report["mode"] == "openapi"
                                   else "written brief"))
    lines.append("- Profile: %s" % report.get("profile_label", ""))
    if report.get("version"):
        lines.append("- API version: %s" % report["version"])
    lines.append("- Readiness score: %s/100 (%s)" % (report["score"], report.get("verdict_label", "")))
    lines.append("- Operations reviewed: %d" % report["stats"]["endpoints"])
    lines.append("- Findings: %d high, %d medium, %d low" %
                 (report["counts"]["high"], report["counts"]["medium"], report["counts"]["low"]))
    lines.append("")
    lines.append("## Scorecard")
    lines.append("")
    for ax in report["axes"]:
        lines.append("- %s: %s/100 (weight %s)" % (ax["label"], ax["score"],
                                                    round(ax["weight"], 2)))
    lines.append("")
    lines.append("## Top priorities")
    lines.append("")
    for i, p in enumerate(report.get("priorities", []), 1):
        lines.append("%d. **%s** (%s / %s) - %s" % (i, p["title"], p["severity"],
                                                    p["axis"], p["fix"]))
    lines.append("")
    lines.append("## Findings")
    lines.append("")
    for f in report["findings"]:
        lines.append("### %s [%s / %s]" % (f["title"], f["severity"].upper(), f["axis"]))
        lines.append("")
        lines.append(f["why"])
        lines.append("")
        lines.append("**Fix:** %s" % f["fix"])
        if f.get("evidence"):
            lines.append("")
            for ev in f["evidence"]:
                lines.append("- %s" % ev)
        lines.append("")
    lines.append("## Operations")
    lines.append("")
    for ex in report.get("examples", []):
        lines.append("### %s %s" % (ex["method"], ex["path"]))
        if ex.get("summary"):
            lines.append("")
            lines.append(ex["summary"])
        lines.append("")
        lines.append("    %s" % ex["curl"])
        lines.append("")
    return "\n".join(lines) + "\n"
