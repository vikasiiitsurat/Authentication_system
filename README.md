# Auth System

A production-oriented authentication and user management API built with Spring Boot. The project provides registration, email verification with OTP, JWT-based authentication, refresh token rotation, role-based authorization, audit logging, and Redis-backed rate limiting.

## Features

- User registration with email verification
- OTP generation, resend control, and verification
- JWT access tokens for stateless authentication
- Refresh token rotation with replay detection
- Role-based access control for user and admin routes
- Account lockout after repeated failed login attempts
- Redis-backed rate limiting for login and OTP operations
- Logout with token revocation and access-token blacklisting
- Password change with refresh-token invalidation
- Device session listing and revocation APIs
- Audit logging for security-sensitive actions

## Tech Stack

- Java 24
- Spring Boot 3.5
- Spring Security
- Spring Web
- Spring Data JPA
- PostgreSQL
- Redis
- Flyway
- Java Mail Sender
- JJWT
- Maven

## Setup Instructions

### 1. Prerequisites

Make sure these are installed and running:

- Java 24
- Maven 3.9+
- PostgreSQL
- Redis
- An SMTP account if you want real email delivery

### 2. Clone or open the project

```bash
git clone <your-repository-url>
cd authesystem1
```

### 3. Create the PostgreSQL database

```sql
CREATE DATABASE authdatabase;
```

### 4. Configure environment variables

Spring Boot reads configuration from environment variables. Set the values shown in the next section before starting the app.

### 5. Start the application

```bash
mvn spring-boot:run
```

Flyway migrations run automatically on startup.

### 6. Run tests

```bash
mvn test
```

The API will start on `http://localhost:8080` unless `SERVER_PORT` is overridden.

OpenAPI docs are available at:

- `http://localhost:8080/swagger-ui.html`
- `http://localhost:8080/v3/api-docs`

Monitoring endpoints are available at:

- `http://localhost:8080/actuator/health`
- `http://localhost:8080/actuator/prometheus`

## Environment Variables Configuration

Use placeholders like the following instead of committing real secrets:

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

OTP_DELIVERY_MODE=log
MAIL_FROM=no-reply@example.com
MAIL_VERIFICATION_SUBJECT=Verify your email address
MAIL_LOG_OTP=true

MAIL_HOST=smtp.gmail.com
MAIL_PORT=587
MAIL_USERNAME=your_email@gmail.com
MAIL_PASSWORD=your_app_password
MAIL_SMTP_AUTH=true
MAIL_SMTP_STARTTLS_ENABLED=true
MAIL_SMTP_STARTTLS_REQUIRED=true

PERMIT_PROMETHEUS_SCRAPE=false

LOGIN_RATE_LIMIT_ATTEMPTS=10
LOGIN_RATE_LIMIT_WINDOW_SECONDS=60
OTP_GENERATION_RATE_LIMIT_ATTEMPTS=5
OTP_GENERATION_RATE_LIMIT_WINDOW_SECONDS=900
OTP_VERIFICATION_RATE_LIMIT_ATTEMPTS=10
OTP_VERIFICATION_RATE_LIMIT_WINDOW_SECONDS=300
```

### Important Notes

- `JWT_SECRET` must be a Base64-encoded secret key.
- For local development without real emails, set `OTP_DELIVERY_MODE=log`.
- Prefer setting `DB_URL` directly if you want full control over the PostgreSQL connection string.
- Do not keep real credentials inside `application.yml` for a public repository.
- Keep `PERMIT_PROMETHEUS_SCRAPE=false` unless Prometheus is scraping from a trusted network path.

## Email (SMTP) Setup

This project supports two OTP delivery modes:

- `log`: OTP is written to the application logs. Best for local development and Postman testing.
- `smtp`: OTP is sent to the user's email address using Spring Mail.

### To use SMTP mode

1. Set `OTP_DELIVERY_MODE=smtp`
2. Configure `MAIL_HOST`, `MAIL_PORT`, `MAIL_USERNAME`, `MAIL_PASSWORD`, and `MAIL_FROM`
3. Start the application

### Gmail example

If you use Gmail:

- Enable 2-Step Verification
- Generate an App Password
- Use that App Password as `MAIL_PASSWORD`
- Keep `MAIL_PORT=587` and TLS enabled

If SMTP delivery fails, the API returns a temporary service error for OTP sending.

## API Endpoints

Base URL: `http://localhost:8080`

| Method | Endpoint | Auth Required | Description |
| --- | --- | --- | --- |
| `POST` | `/api/auth/register` | No | Register a user and send an email verification OTP |
| `POST` | `/api/auth/verify-email` | No | Verify the 6-digit OTP and activate the account |
| `POST` | `/api/auth/resend-verification-otp` | No | Send a new verification OTP if resend rules allow it |
| `POST` | `/api/auth/login` | No | Authenticate user and return access and refresh tokens |
| `POST` | `/api/auth/refresh` | No | Rotate refresh token and issue a new access token |
| `POST` | `/api/auth/logout` | Yes | Revoke refresh token and blacklist the current access token |
| `POST` | `/api/auth/change-password` | Yes | Change password and revoke all active refresh tokens |
| `GET` | `/api/sessions` | Yes | List active sessions for the authenticated user |
| `DELETE` | `/api/sessions/{sessionId}` | Yes | Revoke a specific device session |
| `DELETE` | `/api/sessions/others` | Yes | Revoke all other active sessions except the current one |
| `GET` | `/api/users/me` | Yes | Return the authenticated user's profile |
| `GET` | `/api/users/{userId}` | Yes | Return a user profile for self or admin |
| `GET` | `/api/admin/users` | Admin only | Return all users |

### Common Request Payloads

```json
POST /api/auth/register
{
  "email": "user@example.com",
  "password": "StrongPass123"
}
```

```json
POST /api/auth/login
{
  "email": "user@example.com",
  "password": "StrongPass123",
  "deviceId": "postman-local"
}
```

```json
POST /api/auth/verify-email
{
  "email": "user@example.com",
  "otp": "123456",
  "deviceId": "postman-local"
}
```

```json
POST /api/auth/refresh
{
  "refreshToken": "<refresh-token>",
  "deviceId": "postman-local"
}
```

## Authentication Flow

1. A user registers through `/api/auth/register`.
2. The system creates the user in an unverified state.
3. A 6-digit OTP is generated, hashed, stored in Redis, and delivered by log or SMTP.
4. The user verifies the OTP through `/api/auth/verify-email`.
5. Once verified, the user logs in through `/api/auth/login`.
6. The API returns:
   - a short-lived JWT access token
   - a refresh token tied to the device
7. The access token is sent in the `Authorization: Bearer <token>` header for protected routes.
8. When the access token expires, the client calls `/api/auth/refresh` to rotate the refresh token and receive a new token pair.
9. On logout, the refresh token is revoked and the current access token JTI is blacklisted until it expires.
10. The client can review active sessions with `/api/sessions` and revoke a single session or all other sessions as needed.

## Security Features

- BCrypt password hashing
- Stateless JWT authentication
- Refresh token hashing before database storage
- Refresh token rotation on every refresh request
- Refresh token replay detection with full user token revocation
- Access token blacklisting on logout
- Session-aware access-token invalidation for revoked sessions
- Email verification before login is allowed
- Redis-backed rate limiting for login and OTP endpoints
- Progressive account lockout after repeated failed logins
- Role-based authorization with method-level checks
- Audit logs for registration, login, refresh, logout, password change, and verification events

## Monitoring Stack

The project already emits Micrometer metrics for auth operations, audit persistence, and rate-limit decisions. A local monitoring stack is included in the repository under `monitoring/`:

- Prometheus scrape config and auth-focused alert rules
- Alertmanager base config
- Grafana datasource provisioning
- A prebuilt `Auth System Overview` dashboard

### Included metrics

- `auth.operation.total`
- `auth.operation.duration`
- `auth.rate_limit.total`
- `auth.audit.event.total`
- `auth.audit.persistence.duration`

### Start the monitoring stack locally

1. Start the application with Prometheus scraping temporarily enabled:

```bash
PERMIT_PROMETHEUS_SCRAPE=true mvn spring-boot:run
```

On PowerShell:

```powershell
$env:PERMIT_PROMETHEUS_SCRAPE='true'
mvn spring-boot:run
```

2. In another terminal, start Prometheus, Alertmanager, and Grafana:

```bash
docker compose -f docker-compose.monitoring.yml up -d
```

3. Open the monitoring tools:

- Grafana: `http://localhost:3000`
- Prometheus: `http://localhost:9090`
- Alertmanager: `http://localhost:9093`

Default Grafana credentials:

- Username: `admin`
- Password: `admin`

### Notes

- The Prometheus config scrapes `host.docker.internal:8080`. If your app runs on a different host or port, update `monitoring/prometheus/prometheus.yml`.
- The Alertmanager receiver is intentionally a placeholder `default-null` receiver. Replace it with email, Slack, or webhook routing before using it for real notifications.
- Keep the Prometheus scrape endpoint protected in production unless it is exposed only on a trusted internal network.

## How to Test Using Postman

### Suggested Postman variables

- `baseUrl` = `http://localhost:8080`
- `email` = your test email
- `password` = your test password
- `deviceId` = `postman-local`
- `otp` = verification code
- `accessToken` = JWT from login
- `refreshToken` = token from login
- `userId` = returned from register response

### Recommended test flow

1. Call `POST {{baseUrl}}/api/auth/register`
2. Get the OTP:
   - from logs if `OTP_DELIVERY_MODE=log`
   - from your mailbox if `OTP_DELIVERY_MODE=smtp`
3. Call `POST {{baseUrl}}/api/auth/verify-email`
4. Call `POST {{baseUrl}}/api/auth/login`
5. Save `accessToken` and `refreshToken` from the response
6. Call `GET {{baseUrl}}/api/users/me` with header:

```http
Authorization: Bearer {{accessToken}}
```

7. Call `POST {{baseUrl}}/api/auth/refresh` to get a new token pair
8. Call `GET {{baseUrl}}/api/sessions` to inspect active device sessions
9. Call `DELETE {{baseUrl}}/api/sessions/{sessionId}` or `DELETE {{baseUrl}}/api/sessions/others` to revoke sessions
10. Call `POST {{baseUrl}}/api/auth/change-password` if you want to verify password rotation
11. Call `POST {{baseUrl}}/api/auth/logout` to revoke the session

## Project Structure Overview

```text
authesystem1/
|-- pom.xml
|-- src/
|   |-- main/
|   |   |-- java/com/vikas/authsystem/
|   |   |   |-- config/        # Security, JWT, Redis, mail, rate limit configuration
|   |   |   |-- controller/    # REST API endpoints
|   |   |   |-- dto/           # Request and response models
|   |   |   |-- entity/        # JPA entities such as User, RefreshToken, AuditLog
|   |   |   |-- exception/     # Custom exceptions and global handler
|   |   |   |-- repository/    # Spring Data repositories
|   |   |   |-- security/      # JWT utilities, filter, auth principal, blacklist service
|   |   |   `-- service/       # Business logic for auth, OTP, rate limiting, auditing
|   |   `-- resources/
|   |       |-- application.yml
|   |       `-- db/migration/  # Flyway SQL migrations
|   `-- test/
|       `-- java/com/vikas/authsystem/service/  # Service-layer tests
`-- target/
```

## Future Improvements

- Add Docker Compose for PostgreSQL and Redis
- Add forgot-password and password-reset flows
- Add email templates with HTML formatting
- Add distributed tracing for auth requests and downstream dependencies
- Add CI pipeline for build, test, and lint checks

## Author

**Vikas**

If you are maintaining this project publicly, consider adding your GitHub profile or contact links here.
