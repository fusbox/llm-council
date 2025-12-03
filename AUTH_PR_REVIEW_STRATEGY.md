# Authentication PR Review Strategy

This document provides recommendations for reviewing and merging the 3 authentication PRs (#1, #2, #3).

## Executive Summary

**Recommendation: Evaluate together, but merge separately after resolving conflicts.**

The 3 PRs have significant conflicts and overlap. They should be reviewed together to understand the complete authentication picture, then merged in a specific order with conflict resolution at each step.

---

## PR Overview

| PR | Title | Key Features | New Files |
|----|-------|-------------|-----------|
| #1 | Add authentication endpoints with JWT and refresh tokens | JWT auth, bcrypt hashing, signup/login/logout/refresh | `auth_service.py`, `auth_storage.py` |
| #2 | Add authentication protections and observability | Rate limiting, admin bootstrap, password reset, Prometheus metrics | `auth.py` |
| #3 | Add MFA, OIDC SSO, and session management APIs | TOTP MFA, WebAuthn, OIDC callback, session management | `auth.py` |

---

## Conflict Analysis

### Critical Conflicts

1. **`backend/auth.py`**: PR #2 and PR #3 both create this file with completely different implementations
   - PR #2: Rate limiting, password reset tokens, admin bootstrap
   - PR #3: MFA factors, OIDC mapping, session management

2. **`backend/main.py`**: All 3 PRs modify this file with different auth endpoints and imports

3. **`backend/config.py`**: All 3 PRs add different configuration variables

4. **`pyproject.toml`**: All 3 PRs add different dependencies

### Architectural Concerns

- **No unified auth model**: Each PR has its own user/session model
- **Duplicate functionality**: PR #1 has sessions via refresh tokens; PR #3 has explicit session management
- **Inconsistent naming**: PR #1 uses `auth_service.py`/`auth_storage.py`; PRs #2/#3 use `auth.py`

---

## Recommended Merge Strategy

### Option A: Sequential Merge with Integration (Recommended)

**Order: PR #1 → PR #2 → PR #3**

This order builds from foundational auth to enhancements:

1. **PR #1 first**: Provides the core JWT authentication foundation
   - Clean merge (no conflicts with master)
   - Establishes user model and token patterns

2. **PR #2 second**: Adds security protections on top
   - Requires merging/renaming `auth.py` to avoid conflict
   - Rate limiting should wrap PR #1's login endpoint
   - Password reset can use PR #1's user storage

3. **PR #3 third**: Adds advanced features
   - Requires significant integration work
   - MFA factors should be added to PR #1's user model
   - Session management overlaps with PR #1's refresh tokens

**Pros**: Incremental review, each PR reviewed independently
**Cons**: Later PRs need rework after earlier merges

### Option B: Combined Review then Sequential Merge

1. Review all 3 PRs together to understand the full picture
2. Identify integration points and conflicts
3. Create a unified architecture plan
4. Merge PR #1 first
5. Have PR #2 and #3 authors rebase and integrate with PR #1's patterns

**Pros**: Better architectural coherence
**Cons**: More coordination overhead

### Option C: Single Unified Auth PR

1. Close all 3 PRs
2. Create a new PR that combines and integrates all features coherently
3. Single comprehensive review

**Pros**: Clean architecture, no conflicts
**Cons**: Discards existing work, longer timeline

---

## Technical Integration Notes

If proceeding with Option A or B, here's how to resolve conflicts:

### User Model Unification

PR #1's `auth_storage.py` user model:
```python
user = {
    "id": user_id,
    "email": email,
    "password_hash": hashed,
    "created_at": timestamp,
}
```

PR #3's user model should extend this:
```python
user = {
    "id": user_id,
    "email": email,
    "password_hash": hashed,  # from PR #1
    "created_at": timestamp,
    "oidc_issuer": issuer,    # from PR #3
    "oidc_subject": subject,  # from PR #3
    "mfa_factors": [],        # from PR #3
}
```

### File Organization

Recommended structure after merging:
```
backend/
├── auth/
│   ├── __init__.py
│   ├── service.py      # Core JWT auth (from PR #1)
│   ├── storage.py      # User/token persistence (from PR #1)
│   ├── mfa.py          # MFA factors (from PR #3)
│   ├── oidc.py         # OIDC mapping (from PR #3)
│   ├── rate_limit.py   # Rate limiting (from PR #2)
│   └── metrics.py      # Prometheus metrics (from PR #2)
├── config.py
└── main.py
```

### Config Consolidation

**Recommended unified config** (not separate sections per PR):
```python
# Unified auth secret - use ONE secret for all auth operations
# PR #1 calls it JWT_SECRET, PR #2 calls it AUTH_SECRET - consolidate to one
AUTH_SECRET = os.getenv("AUTH_SECRET", "dev-secret-key-change-me")

# JWT-specific settings (from PR #1)
ACCESS_TOKEN_EXPIRE_MINUTES = 15
REFRESH_TOKEN_EXPIRE_DAYS = 30

# Admin bootstrap settings (from PR #2)
DEFAULT_ADMIN_USERNAME = os.getenv("DEFAULT_ADMIN_USERNAME", "admin")
DEFAULT_ADMIN_EMAIL = os.getenv("DEFAULT_ADMIN_EMAIL", "admin@example.com")
DEFAULT_ADMIN_PASSWORD = os.getenv("DEFAULT_ADMIN_PASSWORD", "admin123")

# Unified storage - use ONE directory structure for all auth data
# PR #1 uses data/auth.json, PR #3 uses data/auth/auth_state.json - consolidate:
AUTH_DATA_DIR = "data/auth"
AUTH_USERS_FILE = os.path.join(AUTH_DATA_DIR, "users.json")      # User records
AUTH_TOKENS_FILE = os.path.join(AUTH_DATA_DIR, "tokens.json")    # Refresh tokens
AUTH_SESSIONS_FILE = os.path.join(AUTH_DATA_DIR, "sessions.json") # Active sessions
```

**Important**: The consolidation requires refactoring each PR's code to use the unified config variables, not just combining them as-is.

---

## Review Checklist for Each PR

### PR #1 Review Points
- [ ] JWT secret handling and rotation strategy
- [ ] Refresh token rotation implementation
- [ ] Password hashing cost factor (bcrypt)
- [ ] Device ID tracking approach

### PR #2 Review Points
- [ ] Rate limiting thresholds (5 attempts/60s, 300s block)
- [ ] Default admin credentials security warning
- [ ] Password reset token expiry (1 hour)
- [ ] Prometheus metric naming conventions

### PR #3 Review Points
- [ ] TOTP implementation correctness
- [ ] WebAuthn integration approach (stub implementation)
- [ ] OIDC claim mapping completeness
- [ ] Session revocation semantics

---

## Security Considerations

1. **JWT_SECRET/AUTH_SECRET**: Should be the same secret, strong, and rotatable
2. **Default admin password**: Should require change on first login
3. **Rate limiting**: Should apply to all auth endpoints, not just login
4. **Password reset tokens**: One-time use is good; ensure proper invalidation
5. **TOTP secrets**: Should be encrypted at rest, not stored in plaintext JSON

---

## Conclusion

**Recommended approach**: Review all 3 PRs together to understand the complete authentication story, then merge sequentially (PR #1 → PR #2 → PR #3) with conflict resolution at each step.

The key insight is that these PRs are **complementary features**, not **competing implementations**:
- PR #1 = Foundation (JWT auth)
- PR #2 = Protection (rate limiting, observability)
- PR #3 = Enhancement (MFA, SSO, sessions)

They can be merged together with some integration work, rather than choosing one over the others.
