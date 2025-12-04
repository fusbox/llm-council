# Unified Authentication Implementation Plan

This document provides a comprehensive plan for implementing authentication in the LLM Council application, synthesizing the best elements from all 3 auth PRs (#1, #2, #3).

---

## Executive Summary

### Recommendation

**Use PR #1 as the base for development. Close PRs #2 and #3.**

PR #1 provides the strongest foundation with proper JWT implementation, bcrypt password hashing, and refresh token rotation. The valuable features from PRs #2 and #3 should be integrated into PR #1's architecture.

### Rationale

| Criteria | PR #1 | PR #2 | PR #3 |
|----------|-------|-------|-------|
| **Password Security** | ✅ bcrypt (industry standard) | ❌ SHA-256 (weak) | ❌ No password auth |
| **Token Architecture** | ✅ JWT with refresh rotation | ❌ No tokens | ❌ No tokens |
| **Code Structure** | ✅ Service/Storage separation | ⚠️ Monolithic | ⚠️ Monolithic |
| **User Model** | ✅ Extensible | ⚠️ Limited | ✅ Rich but no password |
| **Rate Limiting** | ❌ Missing | ✅ Good | ❌ Missing |
| **Observability** | ❌ Missing | ✅ Prometheus | ❌ Missing |
| **MFA Support** | ❌ Missing | ❌ Missing | ✅ TOTP/WebAuthn |
| **SSO/OIDC** | ❌ Missing | ❌ Missing | ✅ OIDC callback |
| **Session Mgmt** | ⚠️ Via refresh tokens | ❌ Missing | ✅ Explicit sessions |

---

## Best Elements from Each PR

### From PR #1 (Foundation - KEEP)
- ✅ **bcrypt password hashing** - Industry standard, adaptive cost factor
- ✅ **JWT access/refresh token pattern** - Proper token separation
- ✅ **Refresh token rotation** - Security best practice
- ✅ **Service/Storage separation** - Clean architecture
- ✅ **Device-based token revocation** - Multi-device support
- ✅ **Token hashing in storage** - Secure token persistence

### From PR #2 (Security - INTEGRATE)
- ✅ **Rate limiting** - Essential for brute-force protection
- ✅ **Admin bootstrap** - Useful for initial deployment
- ✅ **Password reset flow** - Essential user feature
- ✅ **Prometheus metrics** - Observability
- ✅ **Structured logging** - Audit trail

### From PR #3 (Enhancement - INTEGRATE)
- ✅ **MFA factor model** - Extensible MFA support
- ✅ **TOTP implementation** - Standard 2FA
- ✅ **OIDC claim mapping** - SSO support
- ✅ **Session listing/revocation** - User control
- ⚠️ **WebAuthn** - Keep as stub/hook for future

---

## Unified Implementation Architecture

### File Structure

```
backend/
├── auth/
│   ├── __init__.py           # Re-exports public API
│   ├── service.py            # AuthService class (from PR #1)
│   ├── storage.py            # User/token persistence (from PR #1)
│   ├── rate_limiter.py       # Rate limiting (from PR #2)
│   ├── mfa.py                # MFA factors (from PR #3)
│   ├── oidc.py               # OIDC mapping (from PR #3)
│   ├── password_reset.py     # Password reset (from PR #2)
│   └── metrics.py            # Prometheus counters (from PR #2)
├── config.py                 # Unified config
└── main.py                   # API routes
```

### Unified User Model

The following shows the target user model structure (actual implementation will include proper imports and type definitions):

```python
@dataclass
class User:
    """Complete user record combining all PR features."""
    
    # Core identity (PR #1)
    id: str
    email: str
    password_hash: str              # bcrypt from PR #1
    created_at: str
    
    # Additional profile (PR #2)
    username: Optional[str] = None
    
    # OIDC/SSO (PR #3)
    oidc_issuer: Optional[str] = None
    oidc_subject: Optional[str] = None
    
    # MFA (PR #3) - MfaFactor defined in auth/mfa.py
    mfa_factors: List[MfaFactor] = field(default_factory=list)
    
    # Admin flags (PR #2)
    is_admin: bool = False
    requires_password_change: bool = False
```

### Unified Config

The following config additions should be made to `backend/config.py`:

```python
# backend/config.py additions

# Auth secret (unified from JWT_SECRET and AUTH_SECRET)
AUTH_SECRET = os.getenv("AUTH_SECRET", "dev-secret-key-change-me")

# JWT settings (from PR #1)
ACCESS_TOKEN_EXPIRE_MINUTES = 15
REFRESH_TOKEN_EXPIRE_DAYS = 30

# Rate limiting (from PR #2)
RATE_LIMIT_MAX_ATTEMPTS = 5
RATE_LIMIT_WINDOW_SECONDS = 60
RATE_LIMIT_BLOCK_SECONDS = 300

# Admin bootstrap (from PR #2)
DEFAULT_ADMIN_EMAIL = os.getenv("DEFAULT_ADMIN_EMAIL", "admin@example.com")
DEFAULT_ADMIN_PASSWORD = os.getenv("DEFAULT_ADMIN_PASSWORD", None)  # Must be set

# Storage
AUTH_DATA_DIR = "data/auth"
```

### API Endpoints (Unified)

```
POST /api/auth/signup              # PR #1 - User registration
POST /api/auth/login               # PR #1 + PR #2 rate limiting
POST /api/auth/logout              # PR #1
POST /api/auth/refresh             # PR #1 - Token rotation

POST /api/auth/password/forgot     # PR #2 - Request reset
POST /api/auth/password/reset      # PR #2 - Confirm reset

POST /api/auth/oidc/callback       # PR #3 - SSO login

GET  /api/auth/sessions            # PR #3 - List sessions
POST /api/auth/sessions/{id}/revoke  # PR #3 - Revoke session

POST /api/auth/mfa/totp/enroll     # PR #3 - Start TOTP setup
POST /api/auth/mfa/totp/verify     # PR #3 - Verify TOTP code
POST /api/auth/mfa/totp/disable    # New - Remove TOTP

GET  /metrics                      # PR #2 - Prometheus endpoint
```

---

## Development Plan

### Phase 1: Foundation (Use PR #1 as-is)

1. **Merge PR #1** after addressing these items:
   - [ ] Add input validation for email format
   - [ ] Add password strength requirements
   - [ ] Add unit tests for auth_service.py
   - [ ] Add unit tests for auth_storage.py

2. **Close PR #2 and PR #3** - Their features will be added in subsequent phases

### Phase 2: Security Hardening (From PR #2)

3. **Add rate limiting**
   - [ ] Create `backend/auth/rate_limiter.py` (port from PR #2)
   - [ ] Wrap login endpoint with rate limiter
   - [ ] Add rate limiting to password reset endpoints

4. **Add password reset flow**
   - [ ] Create `backend/auth/password_reset.py`
   - [ ] Port signed token generation from PR #2
   - [ ] Add forgot/reset endpoints

5. **Add observability**
   - [ ] Create `backend/auth/metrics.py`
   - [ ] Add Prometheus counters for auth events
   - [ ] Add structured logging

6. **Admin bootstrap** (optional)
   - [ ] Add bootstrap logic on first run
   - [ ] Require password change on first login

### Phase 3: Advanced Features (From PR #3)

7. **Add MFA support**
   - [ ] Create `backend/auth/mfa.py`
   - [ ] Extend user model with mfa_factors
   - [ ] Add TOTP enrollment/verification endpoints
   - [ ] Integrate MFA check into login flow

8. **Add OIDC/SSO support**
   - [ ] Create `backend/auth/oidc.py`
   - [ ] Add OIDC callback endpoint
   - [ ] Map OIDC claims to user model

9. **Add explicit session management**
   - [ ] Extend storage to list active sessions
   - [ ] Add session listing endpoint
   - [ ] Add session revocation endpoint

### Phase 4: Production Readiness

10. **Security hardening**
    - [ ] Encrypt sensitive data at rest (MFA secrets)
    - [ ] Add HTTPS enforcement
    - [ ] Add CORS configuration for production
    - [ ] Add secret rotation support

11. **Testing**
    - [ ] Integration tests for auth flows
    - [ ] Security tests (rate limiting, token expiry)
    - [ ] Load tests for auth endpoints

---

## Dependencies

### Required (from PR #1)
```toml
bcrypt>=4.2.0
python-jose[cryptography]>=3.3.0
```

### Additional (from PR #2)
```toml
prometheus-client>=0.21.0
```

### Future (for Phase 3)
```toml
# If adding full WebAuthn support
webauthn>=2.0.0
```

---

## Security Improvements Over Individual PRs

1. **Password hashing**: Use bcrypt from PR #1 (not SHA-256 from PR #2)
2. **Rate limiting**: Apply to ALL auth endpoints, not just login
3. **Token storage**: Hash tokens before storing (from PR #1)
4. **MFA secrets**: Encrypt at rest (improvement over PR #3)
5. **Admin bootstrap**: Require password change (improvement over PR #2)
6. **Session binding**: Tie sessions to refresh tokens (unified approach)

---

## PR Disposition

| PR | Recommendation | Reason |
|----|----------------|--------|
| **#1** | ✅ **Use as base** | Best architecture, secure password handling, proper JWT implementation |
| **#2** | ❌ **Close** | Valuable features (rate limiting, metrics) to be integrated; SHA-256 passwords are a security concern |
| **#3** | ❌ **Close** | Valuable features (MFA, OIDC) to be integrated; lacks password-based auth foundation |

---

## Conclusion

PR #1 provides the strongest foundation for authentication with proper security practices. Development should proceed by:

1. **Using PR #1 as the base** - It has the right architecture and security practices
2. **Closing PRs #2 and #3** - Their best features will be integrated incrementally
3. **Following the phased development plan** - Foundation → Security → Advanced Features

This approach delivers a production-ready authentication system that combines the best elements from all three approaches while maintaining a clean, maintainable codebase.
