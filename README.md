# Auth System

Production-oriented authentication and user management API built with Spring Boot, PostgreSQL, Redis, JWT, and Micrometer. The system supports registration, email verification, password reset, refresh-token rotation, session management, and layered login abuse protection designed for distributed deployments.

## Features

- User registration with email verification OTP
- Forgot-password and password-reset flow
- Self-service account unlock flow for protected accounts
- JWT access tokens with refresh-token rotation
- Global logout that invalidates access tokens and refresh-token sessions across devices
- Authenticated soft-delete account lifecycle with password and email confirmation
- Session listing and revocation
- Uses Redis to handle login attempts and security checks across multiple servers.
- Limits how many times someone can try login or OTP requests (prevents brute-force attacks)
- System does not reveal whether an email exists or not (for security).
- Access-token invalidation after password change/reset
- Audit logging for security-sensitive events
- Tracks system performance and security events using monitoring tools and alerts.

## Tech Stack

- Java 24
- Spring Boot 3.5
- Spring Security
- Spring Data JPA
- PostgreSQL
- Redis
- Flyway
- Spring Mail
- Micrometer + Prometheus
- Maven

## High-Level Security Design

### PostgreSQL is the source of truth for:

- users
- password hashes
- email verification state
- password change timestamp
- global session invalidation timestamp
- refresh tokens / sessions
- audit logs

### Redis is used for:

- per-IP login throttling
- per-account+IP login throttling
- Temporary security flags stored for accounts
- Detect sudden high activity from an IP
- Handle OTP when unlocking account
- OTP issuance and OTP verification limits
- storesb OTP codes, OTP attempts, resend cooldowns
- token/session blacklist support

This split keeps durable account state in PostgreSQL and short-lived abuse-control state in Redis.

## Global Logout Logic

Global logout is implemented as a first-class account security operation, not just a loop over refresh tokens.

- `POST /api/auth/logout-all` requires a valid access token
- backend writes `session_invalidated_at` on the user row in PostgreSQL
- backend revokes all active refresh tokens for that user
- backend blacklists the current access token and session immediately
- `JwtAuthenticationFilter` rejects any JWT issued at or before `session_invalidated_at`

This makes global logout work correctly in distributed deployments because every application instance checks the same durable invalidation marker from PostgreSQL.

### Frontend flow

- user clicks `Log out of all devices`
- frontend calls `POST /api/auth/logout-all` with the current bearer token
- backend returns the number of revoked sessions and the invalidation timestamp
- frontend clears local access token, refresh token, and any cached user/session state
- frontend redirects the user to the login screen

### Example response

```json
{
  "message": "All active sessions were revoked",
  "revokedSessions": 3,
  "accessTokensInvalidatedAt": "2026-03-26T10:15:30Z"
}
```

## Account Deletion Logic

Account deletion is implemented as a production-style soft delete, not a hard row removal.

- endpoint: `POST /api/users/me/delete-account`
- requires a valid bearer token
- requires `currentPassword`
- requires `confirmEmail` to match the authenticated account email exactly
- revokes all refresh-token sessions
- blacklists the current access token and session immediately
- sets `deleted_at` on the user row
- stores a SHA-256 hash of the original email in `deleted_email_hash`
- replaces the stored email with a tombstone alias like `deleted+<userId>@deleted.auth.local`
- rotates the stored password hash and invalidates existing JWTs

This keeps the account recoverable for audit/history purposes while making it unusable for login, refresh, profile access, and password reset flows. The tombstone email also frees the original address for future re-registration.

Recommended frontend flow:

- show a dedicated danger-zone dialog
- require the user to type their email
- require the current password
- after `204 No Content`, clear frontend auth state and redirect to login or a goodbye screen

## Login Protection Logic

The login endpoint no longer depends on a durable database lockout like `5m -> 10m -> 40m -> 24h`. Instead it applies layered Redis-backed controls.

### 1. Per-IP throttling

Purpose: stop high-volume brute force and credential stuffing from one source.

- `ip-burst`: 20 attempts per 60 seconds, then block for 60 seconds
- `ip-sustained`: 100 attempts per 15 minutes, then block for 15 minutes

If either trips, the client gets `429 Too Many Requests`.

### 2. Per-account+IP throttling

Purpose: stop one source from hammering one account.

- 5 failed attempts per 10 minutes
- first cooldown: 60 seconds
- repeated threshold crossing within 1 hour: 5 minutes
- capped max cooldown: 10 minutes

This is narrower than a global account lock and avoids easy account-lock abuse.

### 3. Per-account protection mode

Purpose: detect a targeted account when failures accumulate across many IPs without creating a user-hostile hard lock.

- threshold: 8 failed attempts per 15 minutes
- first activation: 5 minutes
- repeated activation within 24 hours: 15 minutes
- automatic protection is capped at 15 minutes
- this is treated as a soft risk signal for observability and future step-up, not a long durable hard lock

This is intentionally softer than a 24-hour lock. It reduces denial-of-service risk against real users.

### 4. Suspicious IP burst detection

Purpose: detect one IP trying many different accounts.

- if one IP fails against more than 20 distinct accounts in 15 minutes
- block that IP for 15 minutes

This is the credential-stuffing control.

### 5. Anti-enumeration behavior

For login:

- unknown email and wrong password both return the same public error
- unverified account also returns the same public `401`
- password hash work is still performed for unknown users via a dummy hash to reduce timing leakage

For forgot password:

- the API returns generic accepted responses whether the account exists or not

For account unlock:

- the unlock request endpoint also returns a generic accepted response
- unlock OTP is only sent when the account exists, is verified, and current login protection makes self-service recovery relevant

### 6. Reset after success

After a successful login:

- per-account failure counters are cleared
- per-account+IP failure counters are cleared
- short-lived account protection state is cleared

This gives legitimate users a clean recovery path.

### 7. Account unlock recovery

When a legitimate user is blocked by account-level or account+IP protection, the system supports self-service recovery:

- user requests unlock OTP
- system sends OTP to the verified email address if recovery is applicable
- user submits the OTP
- backend clears Redis protection state for the account and the originating client context

This is production-grade because:

- it does not create a durable database lock that requires manual intervention
- it proves inbox control before clearing the protection state
- it does not bypass IP-wide suspicious-source blocks
- it keeps anti-enumeration behavior on the request endpoint

## OTP Rate Limiting Logic

OTP-related endpoints use three scopes:

- `per-account`
- `per-ip`
- `per-account-ip`

### Verification email OTP generation

- per account: 5 per hour
- per IP: 10 per 15 minutes
- per account+IP: 5 per 15 minutes

### Verification email OTP verification

- per account: 10 per 30 minutes
- per IP: 20 per 30 minutes
- per account+IP: 10 per 5 minutes

### Password reset request

- per account: 3 per 15 minutes
- per IP: 10 per 15 minutes
- per account+IP: 3 per 15 minutes

### Password reset verification

- per account: 10 per 30 minutes
- per IP: 20 per 30 minutes
- per account+IP: 10 per 5 minutes

### Account unlock request

- per account: 3 per 15 minutes
- per IP: 10 per 15 minutes
- per account+IP: 3 per 15 minutes

### Account unlock verification

- per account: 10 per 30 minutes
- per IP: 20 per 30 minutes
- per account+IP: 10 per 5 minutes

Each issued OTP also has its own attempt limit inside Redis.

## API Endpoints

Base URL: `http://localhost:8080`

| Method | Endpoint | Auth Required | Description |
| --- | --- | --- | --- |
| `POST` | `/api/auth/register` | No | Register a user and send an email verification OTP |
| `POST` | `/api/auth/verify-email` | No | Verify the 6-digit email OTP |
| `POST` | `/api/auth/resend-verification-otp` | No | Resend an email verification OTP |
| `POST` | `/api/auth/login` | No | Login with layered Redis-backed abuse protection |
| `POST` | `/api/auth/forgot-password` | No | Request a password reset OTP with anti-enumeration behavior |
| `POST` | `/api/auth/reset-password` | No | Reset password using the emailed OTP |
| `POST` | `/api/auth/request-account-unlock` | No | Request an account unlock OTP when recovery is available |
| `POST` | `/api/auth/unlock-account` | No | Unlock an account by verifying the emailed OTP |
| `POST` | `/api/auth/refresh` | No | Rotate refresh token and issue a new access token |
| `POST` | `/api/auth/logout` | Yes | Revoke refresh token and blacklist current access token |
| `POST` | `/api/auth/logout-all` | Yes | Revoke all active sessions and invalidate all existing access tokens |
| `POST` | `/api/auth/change-password` | Yes | Change password and revoke active sessions |
| `POST` | `/api/users/me/delete-account` | Yes | Soft-delete the authenticated account after password and email confirmation |
| `GET` | `/api/sessions` | Yes | List active sessions |
| `DELETE` | `/api/sessions/{sessionId}` | Yes | Revoke one session |
| `DELETE` | `/api/sessions/others` | Yes | Revoke all other sessions |
| `GET` | `/api/users/me` | Yes | Get authenticated user profile |
| `GET` | `/api/users/{userId}` | Yes | Get self/admin-visible user profile |
| `GET` | `/api/admin/users` | Admin only | List users |

## Common Request Payloads

```json
POST /api/auth/login
{
  "email": "user@example.com",
  "password": "StrongPass123",
  "deviceId": "postman-local"
}
```

```json
POST /api/auth/forgot-password
{
  "email": "user@example.com"
}
```

```json
POST /api/auth/reset-password
{
  "email": "user@example.com",
  "otp": "123456",
  "newPassword": "NewSecurePass@123",
  "deviceId": "postman-local"
}
```

```json
POST /api/auth/request-account-unlock
{
  "email": "user@example.com"
}
```

```json
POST /api/auth/unlock-account
{
  "email": "user@example.com",
  "otp": "123456"
}
```

```json
POST /api/users/me/delete-account
{
  "currentPassword": "StrongPass123",
  "confirmEmail": "user@example.com",
  "deviceId": "web-browser"
}
```

## Configuration

Prefer environment variables. Do not commit real secrets.

```env
SERVER_PORT=8080

DB_HOST=localhost
DB_PORT=5432
DB_NAME=authdatabase
DB_USERNAME=postgres
DB_PASSWORD=your_db_password

REDIS_HOST=localhost
REDIS_PORT=6379
REDIS_USERNAME=
REDIS_PASSWORD=
REDIS_SSL_ENABLED=false

JWT_SECRET=BASE64_ENCODED_SECRET_AT_LEAST_32_BYTES_LONG
JWT_ISSUER=authesystem1
JWT_ACCESS_TOKEN_MINUTES=15
JWT_REFRESH_TOKEN_DAYS=30

OTP_DELIVERY_MODE=smtp
MAIL_FROM=no-reply@example.com
MAIL_VERIFICATION_SUBJECT=Verify your email address
MAIL_PASSWORD_RESET_SUBJECT=Reset your password
MAIL_ACCOUNT_UNLOCK_SUBJECT=Unlock your account
MAIL_LOG_OTP=true

MAIL_HOST=smtp.gmail.com
MAIL_PORT=587
MAIL_USERNAME=your_email@gmail.com
MAIL_PASSWORD=your_app_password
MAIL_SMTP_AUTH=true
MAIL_SMTP_STARTTLS_ENABLED=true
MAIL_SMTP_STARTTLS_REQUIRED=true

PERMIT_PROMETHEUS_SCRAPE=false

LOGIN_IP_BURST_ATTEMPTS=20
LOGIN_IP_BURST_WINDOW_SECONDS=60
LOGIN_IP_BURST_BLOCK_SECONDS=60
LOGIN_IP_SUSTAINED_ATTEMPTS=100
LOGIN_IP_SUSTAINED_WINDOW_SECONDS=900
LOGIN_IP_SUSTAINED_BLOCK_SECONDS=900
LOGIN_ACCOUNT_IP_ATTEMPTS=5
LOGIN_ACCOUNT_IP_WINDOW_SECONDS=600
LOGIN_ACCOUNT_IP_INITIAL_BLOCK_SECONDS=60
LOGIN_ACCOUNT_IP_REPEAT_BLOCK_SECONDS=300
LOGIN_ACCOUNT_IP_MAX_BLOCK_SECONDS=600
LOGIN_ACCOUNT_IP_STRIKE_WINDOW_SECONDS=3600
LOGIN_ACCOUNT_THRESHOLD=8
LOGIN_ACCOUNT_WINDOW_SECONDS=900
LOGIN_ACCOUNT_INITIAL_PROTECTION_SECONDS=300
LOGIN_ACCOUNT_REPEAT_PROTECTION_SECONDS=900
LOGIN_ACCOUNT_MAX_PROTECTION_SECONDS=900
LOGIN_ACCOUNT_STRIKE_WINDOW_SECONDS=86400
LOGIN_SUSPICIOUS_IP_DISTINCT_ACCOUNTS=20
LOGIN_SUSPICIOUS_IP_WINDOW_SECONDS=900
LOGIN_SUSPICIOUS_IP_BLOCK_SECONDS=900

OTP_GENERATION_ACCOUNT_ATTEMPTS=5
OTP_GENERATION_ACCOUNT_WINDOW_SECONDS=3600
OTP_GENERATION_IP_ATTEMPTS=10
OTP_GENERATION_IP_WINDOW_SECONDS=900
OTP_GENERATION_ACCOUNT_IP_ATTEMPTS=5
OTP_GENERATION_ACCOUNT_IP_WINDOW_SECONDS=900

OTP_VERIFICATION_ACCOUNT_ATTEMPTS=10
OTP_VERIFICATION_ACCOUNT_WINDOW_SECONDS=1800
OTP_VERIFICATION_IP_ATTEMPTS=20
OTP_VERIFICATION_IP_WINDOW_SECONDS=1800
OTP_VERIFICATION_ACCOUNT_IP_ATTEMPTS=10
OTP_VERIFICATION_ACCOUNT_IP_WINDOW_SECONDS=300

PASSWORD_RESET_REQUEST_ACCOUNT_ATTEMPTS=3
PASSWORD_RESET_REQUEST_ACCOUNT_WINDOW_SECONDS=900
PASSWORD_RESET_REQUEST_IP_ATTEMPTS=10
PASSWORD_RESET_REQUEST_IP_WINDOW_SECONDS=900
PASSWORD_RESET_REQUEST_ACCOUNT_IP_ATTEMPTS=3
PASSWORD_RESET_REQUEST_ACCOUNT_IP_WINDOW_SECONDS=900

PASSWORD_RESET_CONFIRM_ACCOUNT_ATTEMPTS=10
PASSWORD_RESET_CONFIRM_ACCOUNT_WINDOW_SECONDS=1800
PASSWORD_RESET_CONFIRM_IP_ATTEMPTS=20
PASSWORD_RESET_CONFIRM_IP_WINDOW_SECONDS=1800
PASSWORD_RESET_CONFIRM_ACCOUNT_IP_ATTEMPTS=10
PASSWORD_RESET_CONFIRM_ACCOUNT_IP_WINDOW_SECONDS=300

ACCOUNT_UNLOCK_REQUEST_ACCOUNT_ATTEMPTS=3
ACCOUNT_UNLOCK_REQUEST_ACCOUNT_WINDOW_SECONDS=900
ACCOUNT_UNLOCK_REQUEST_IP_ATTEMPTS=10
ACCOUNT_UNLOCK_REQUEST_IP_WINDOW_SECONDS=900
ACCOUNT_UNLOCK_REQUEST_ACCOUNT_IP_ATTEMPTS=3
ACCOUNT_UNLOCK_REQUEST_ACCOUNT_IP_WINDOW_SECONDS=900

ACCOUNT_UNLOCK_CONFIRM_ACCOUNT_ATTEMPTS=10
ACCOUNT_UNLOCK_CONFIRM_ACCOUNT_WINDOW_SECONDS=1800
ACCOUNT_UNLOCK_CONFIRM_IP_ATTEMPTS=20
ACCOUNT_UNLOCK_CONFIRM_IP_WINDOW_SECONDS=1800
ACCOUNT_UNLOCK_CONFIRM_ACCOUNT_IP_ATTEMPTS=10
ACCOUNT_UNLOCK_CONFIRM_ACCOUNT_IP_WINDOW_SECONDS=300
```

## Monitoring

Micrometer metrics now include:

- `auth.operation.total`
- `auth.operation.duration`
- `auth.login.attempts.total`
- `auth.login.failures.total`
- `auth.rate_limit.total`
- `auth.account.protection.total`
- `auth.ip.burst.total`
- `auth.redis.operation.total`
- `auth.audit.event.total`
- `auth.audit.persistence.duration`

Prometheus alert rules include:

- elevated login failures
- account protection activations
- suspicious IP burst detection
- refresh token replay detection
- audit persistence failures
- excessive rate-limit rejections
- login protection Redis backend errors
- high login latency

## Swagger / OpenAPI

Swagger UI:

- `http://localhost:8080/swagger-ui.html`

OpenAPI JSON:

- `http://localhost:8080/v3/api-docs`

The OpenAPI descriptions now document:

- anti-enumeration login behavior
- layered Redis-backed login throttling
- password reset endpoints
- account unlock recovery endpoints
- OTP throttling semantics

## Postman Testing

Suggested flow:

1. `POST /api/auth/register`
2. retrieve verification OTP from logs or email
3. `POST /api/auth/verify-email`
4. `POST /api/auth/login`
5. `POST /api/auth/forgot-password`
6. retrieve password reset OTP from logs or email
7. `POST /api/auth/reset-password`
8. `POST /api/auth/login` with the new password

### Account unlock UI to backend flow

Frontend:

1. login returns `429` after protection trips
2. UI shows: `Too many login attempts. Unlock with email code or wait and try again.`
3. user clicks `Unlock account`
4. UI posts `POST /api/auth/request-account-unlock`
5. user receives OTP in email
6. UI posts `POST /api/auth/unlock-account`
7. UI returns user to the login form

Backend:

1. `request-account-unlock` checks whether the account exists, is verified, and has recoverable protection state
2. if recovery is relevant, it generates an unlock OTP in Redis and emails it
3. the response stays generic to avoid account-state leakage
4. `unlock-account` verifies the OTP
5. the service clears Redis account protection state and the originating account+IP protection state
6. the next login can proceed normally unless the source IP is still blocked for wider abuse

## Project Structure

```text
authesystem1/
|-- monitoring/
|-- pom.xml
|-- src/
|   |-- main/
|   |   |-- java/com/vikas/authsystem/
|   |   |   |-- config/
|   |   |   |-- controller/
|   |   |   |-- dto/
|   |   |   |-- entity/
|   |   |   |-- exception/
|   |   |   |-- repository/
|   |   |   |-- security/
|   |   |   `-- service/
|   |   `-- resources/
|   |       |-- application.yml
|   |       `-- db/migration/
|   `-- test/
`-- target/
```

## Notes

- For local development, `OTP_DELIVERY_MODE=log` is still useful.
- For shared or production-like environments, use SMTP and real secrets from environment variables or a secret manager.
- The current repository should still have secrets rotated and removed from committed defaults before any real deployment.
