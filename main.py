from __future__ import annotations
from typing import Optional, Dict, Any, Tuple
from dataclasses import dataclass
import hashlib
import time

# --- Modelos simples ---
@dataclass
class Request:
    ip: str
    data: Dict[str, Any]
    auth_token: Optional[str] = None

@dataclass
class Response:
    ok: bool
    status_code: int
    message: str
    payload: Optional[Any] = None

# --- Chain of Responsibility base ---
class Handler:
    def set_next(self, handler: "Handler") -> "Handler":
        raise NotImplementedError

    def handle(self, req: Request) -> Response:
        raise NotImplementedError

class BaseHandler(Handler):
    def __init__(self):
        self._next: Optional[Handler] = None

    def set_next(self, handler: Handler) -> Handler:
        self._next = handler
        return handler

    def handle(self, req: Request) -> Response:
        # Each concrete handler implements process()
        result = self.process(req)
        if not result.ok:
            # early exit on failure
            return result
        if self._next:
            return self._next.handle(req)
        return result

    def process(self, req: Request) -> Response:
        """Override in subclasses. Return Response(ok=True/False, ...)"""
        return Response(ok=True, status_code=200, message="OK (base)", payload=None)

# --- Concrete Handlers ---

# 1) Authentication
class AuthenticationHandler(BaseHandler):
    def __init__(self, token_store: Dict[str, Dict[str,Any]]):
        super().__init__()
        self.token_store = token_store  # token -> user info

    def process(self, req: Request) -> Response:
        token = req.auth_token
        if not token:
            return Response(False, 401, "Missing auth token")
        user = self.token_store.get(token)
        if not user:
            return Response(False, 401, "Invalid credentials")
        # Attach user info into request data for later handlers
        req.data.setdefault("_user", user)
        return Response(True, 200, "Authenticated", payload=user)

# 2) Input validation / sanitization
class ValidationHandler(BaseHandler):
    def __init__(self, required_fields: Tuple[str, ...]):
        super().__init__()
        self.required_fields = required_fields

    def process(self, req: Request) -> Response:
        # Simple sanitization: ensure required fields, strip strings, type checks
        for f in self.required_fields:
            if f not in req.data:
                return Response(False, 400, f"Missing field: {f}")
            v = req.data[f]
            if isinstance(v, str):
                req.data[f] = v.strip()
        # Example extra check
        if "quantity" in req.data:
            try:
                q = int(req.data["quantity"])
                if q <= 0:
                    return Response(False, 400, "Quantity must be > 0")
                req.data["quantity"] = q
            except Exception:
                return Response(False, 400, "Invalid quantity")
        return Response(True, 200, "Validated")

# 3) Rate limiting / Brute-force protection by IP
class RateLimitHandler(BaseHandler):
    def __init__(self, window_seconds: int = 60, max_attempts: int = 10):
        super().__init__()
        self.window = window_seconds
        self.max_attempts = max_attempts
        self.attempts: Dict[str, list[float]] = {}  # ip -> list of timestamps

    def process(self, req: Request) -> Response:
        now = time.time()
        arr = self.attempts.setdefault(req.ip, [])
        # prune
        arr[:] = [t for t in arr if t > now - self.window]
        if len(arr) >= self.max_attempts:
            return Response(False, 429, "Too many requests from this IP")
        arr.append(now)
        return Response(True, 200, "Rate OK")

# 4) Cache check - return cached response if same request seen
class CacheHandler(BaseHandler):
    def __init__(self):
        super().__init__()
        self.cache: Dict[str, Tuple[float, Response]] = {}  # key -> (ts, response)
        self.ttl = 30  # seconds

    def _make_key(self, req: Request) -> str:
        # Create a deterministic cache key based on payload (excluding auth_token)
        key_source = (req.ip, tuple(sorted((k,v) for k,v in req.data.items() if not k.startswith("_"))))
        raw = repr(key_source).encode()
        return hashlib.sha256(raw).hexdigest()

    def process(self, req: Request) -> Response:
        key = self._make_key(req)
        entry = self.cache.get(key)
        now = time.time()
        if entry:
            ts, resp = entry
            if now - ts <= self.ttl:
                # return a copy or the same; for simplicity return same object, mark it's cached
                cached_resp = Response(True, 200, "Cached response", payload=resp.payload)
                return cached_resp
            else:
                del self.cache[key]
        
        req.data["_cache_key"] = key
        return Response(True, 200, "No cache - continue")

# 5) Authorization (admin - full access)
class AuthorizationHandler(BaseHandler):
    def __init__(self):
        super().__init__()

    def process(self, req: Request) -> Response:
        user = req.data.get("_user")
        # Require user to be authenticated already
        if not user:
            return Response(False, 403, "No authenticated user for authorization")
        # If admin, mark and continue
        if user.get("is_admin"):
            req.data["_is_admin"] = True
        else:
            req.data["_is_admin"] = False
        return Response(True, 200, "Authorized (role checked)")

# Final handler that executes the business logic (creating order)
class OrderCreationHandler(BaseHandler):
    def __init__(self, cache_handler: Optional[CacheHandler] = None):
        super().__init__()
        self.cache_handler = cache_handler

    def process(self, req: Request) -> Response:
        # real system would perform DB writes, etc.
        user = req.data.get("_user", {"username": "anonymous"})
        is_admin = req.data.get("_is_admin", False)
        # Example business rule: only authenticated users may create orders (enforced by auth handler)
        order = {
            "order_id": f"ORD-{int(time.time()*1000)}",
            "user": user["username"],
            "data": {k:v for k,v in req.data.items() if not k.startswith("_")}
        }
        resp = Response(True, 201, "Order created", payload=order)

        # If we have a cache key in request, store the response
        key = req.data.get("_cache_key")
        if key and self.cache_handler is not None:
            self.cache_handler.cache[key] = (time.time(), resp)
        return resp

# --- Client builder / assembler ---
class OrderClient:
    def __init__(self, chain_start: Handler):
        self.chain_start = chain_start

    def send(self, req: Request) -> Response:
        return self.chain_start.handle(req)

# --- Example usage & simple test run ---
if __name__ == "__main__":
    # Simulated token store
    token_store = {
        "valid-token-user": {"username": "juan", "is_admin": False},
        "admin-token": {"username": "admin", "is_admin": True}
    }

    auth = AuthenticationHandler(token_store)
    val = ValidationHandler(required_fields=("product_id", "quantity"))
    rate = RateLimitHandler(window_seconds=60, max_attempts=5)
    cache = CacheHandler()
    authz = AuthorizationHandler()
    create = OrderCreationHandler(cache_handler=cache)

    # compose chain: Auth -> Validation -> RateLimit -> Cache -> Authz -> Create
    auth.set_next(val).set_next(rate).set_next(cache).set_next(authz).set_next(create)

    client = OrderClient(chain_start=auth)

    # Request 1 - should create
    r1 = Request(ip="1.2.3.4", data={"product_id": "SKU123", "quantity": "2"}, auth_token="valid-token-user")
    resp1 = client.send(r1)
    print("Resp1:", resp1)

    # Request 2 - same payload from same IP within cache TTL -> gets cached
    r2 = Request(ip="1.2.3.4", data={"product_id": "SKU123", "quantity": "2"}, auth_token="valid-token-user")
    resp2 = client.send(r2)
    print("Resp2 (cached):", resp2)

    # Request 3 - invalid token
    r3 = Request(ip="5.6.7.8", data={"product_id": "SKU123", "quantity": "1"}, auth_token="bad")
    resp3 = client.send(r3)
    print("Resp3 (invalid token):", resp3)

    # Request 4 - admin token (admin has full access)
    r4 = Request(ip="9.9.9.9", data={"product_id": "SKU999", "quantity": "1"}, auth_token="admin-token")
    resp4 = client.send(r4)
    print("Resp4 (admin):", resp4)
