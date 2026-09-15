# Employee Access Management System

A small, easy-to-read Spring Boot backend implementing:

- Secure RBAC using **Spring Security + OAuth2 Resource Server + JWT**
- REST APIs for **onboarding, user management, and session auth**, documented with **Swagger/OpenAPI**
- **JUnit 5 + Mockito** unit tests, plus a full-stack **MockMvc integration test**

## How the pieces fit together

This app plays BOTH roles that "OAuth2 + JWT" normally splits across two
services:

1. **Authorization Server** (`AuthController` + `JwtService`) — on login, it
   checks the password and *mints* a signed JWT access token + a persisted,
   revocable refresh token.
2. **Resource Server** (`SecurityConfig`'s `JwtDecoder`) — on every other
   request, Spring Security's `oauth2ResourceServer().jwt()` support
   *validates* that JWT (signature, expiry, issuer) and turns its `role`
   claim into a `ROLE_ADMIN` / `ROLE_EMPLOYEE` authority.

RBAC is then just `@PreAuthorize("hasRole('ADMIN')")` on the controller
methods that need it — see `UserController`. Keeping the rule next to the
endpoint it protects means you never have to cross-reference a separate
security-rules file to know who can call what.

```
Client                     AuthController        JwtService          SecurityConfig (Resource Server)
  |--- POST /auth/login -------->|                    |                         |
  |                              |--- authenticate --->|                         |
  |                              |<--- User -----------|                         |
  |                              |--- generateAccessToken/RefreshToken --------->|
  |<--- access + refresh token --|                                               |
  |                                                                              |
  |--- GET /users/me  (Bearer <access token>) ---------------------------------->|
  |                                                        decode & validate --->|
  |                                                        role claim -> ROLE_*  |
  |<---------------------------------------------------- 200 OK ----------------|
```

## Project layout

```
src/main/java/com/eams/
├── EmployeeAccessManagementApplication.java   # entry point
├── config/
│   ├── SecurityConfig.java          # Spring Security + OAuth2 Resource Server wiring
│   ├── JwtProperties.java           # typed app.jwt.* config
│   ├── BootstrapAdminProperties.java
│   ├── DataInitializer.java         # seeds the first ADMIN on startup
│   └── OpenApiConfig.java           # Swagger "Authorize" (bearer) button
├── domain/
│   ├── User.java                    # entity, also implements UserDetails
│   ├── Role.java                    # ADMIN, EMPLOYEE
│   └── RefreshToken.java            # persisted, revocable refresh tokens
├── repository/                      # Spring Data JPA repositories
├── dto/request|response/            # request/response records (never expose the entity)
├── security/
│   ├── JwtService.java              # signs access + refresh tokens
│   └── CustomUserDetailsService.java# loads user by email at login only
├── service/
│   ├── AuthService.java             # login / refresh (rotation) / logout
│   ├── RefreshTokenService.java     # persistence + revocation of refresh tokens
│   └── UserService.java             # onboarding + user management
├── controller/
│   ├── AuthController.java          # /api/auth/**
│   └── UserController.java          # /api/users/** (RBAC enforced here)
└── exception/                       # custom exceptions + GlobalExceptionHandler

src/test/java/com/eams/
├── security/JwtServiceTest.java             # unit (token contents/expiry)
├── service/UserServiceTest.java             # unit, Mockito
├── service/AuthServiceTest.java             # unit, Mockito
└── controller/AuthAndRbacIntegrationTest.java  # full stack, MockMvc + H2
```

## Running it

**1. Start Postgres**

```bash
docker compose up -d
```

**2. Run the app**

```bash
mvn spring-boot:run
```

On first startup, `DataInitializer` seeds a default ADMIN account (since
onboarding new users is itself an ADMIN-only endpoint — someone has to be
the first ADMIN):

```
email:    admin@eams.local
password: Admin@12345
```

Change these via env vars (`BOOTSTRAP_ADMIN_EMAIL`, `BOOTSTRAP_ADMIN_PASSWORD`)
before running anywhere real. Same for `JWT_SECRET`.

**3. Explore the API**

Swagger UI: http://localhost:8080/swagger-ui.html
Click **Authorize**, paste an access token (no need to type "Bearer " — the
scheme adds it), and every protected endpoint becomes callable from the UI.

## Typical flow

```bash
# 1. Log in as the seeded admin
curl -X POST localhost:8080/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"admin@eams.local","password":"Admin@12345"}'
# -> { "accessToken": "...", "refreshToken": "...", ... }

# 2. Onboard an employee (ADMIN only)
curl -X POST localhost:8080/api/users \
  -H "Authorization: Bearer <ADMIN access token>" \
  -H "Content-Type: application/json" \
  -d '{"fullName":"New Hire","email":"new.hire@example.com","password":"SecurePass123","role":"EMPLOYEE"}'

# 3. Employee logs in and reads their own profile
curl -X POST localhost:8080/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"new.hire@example.com","password":"SecurePass123"}'

curl localhost:8080/api/users/me -H "Authorization: Bearer <EMPLOYEE access token>"

# 4. Employee tries to list all users -> 403 Forbidden (ADMIN only)
curl -i localhost:8080/api/users -H "Authorization: Bearer <EMPLOYEE access token>"

# 5. Refresh an access token
curl -X POST localhost:8080/api/auth/refresh \
  -H "Content-Type: application/json" \
  -d '{"refreshToken":"<refresh token>"}'

# 6. Log out (revokes all of that user's refresh tokens)
curl -X POST localhost:8080/api/auth/logout -H "Authorization: Bearer <access token>"
```

## Endpoints

| Method | Path                        | Access          | Purpose                              |
|--------|-----------------------------|-----------------|---------------------------------------|
| POST   | `/api/auth/login`           | public          | Authenticate, get token pair          |
| POST   | `/api/auth/refresh`         | public          | Rotate refresh token, get new pair    |
| POST   | `/api/auth/logout`          | authenticated   | Revoke all of my refresh tokens       |
| POST   | `/api/users`                | ADMIN           | Onboard a new user                    |
| GET    | `/api/users`                | ADMIN           | List all users                        |
| GET    | `/api/users/{id}`           | ADMIN           | Get any user by id                    |
| PATCH  | `/api/users/{id}/status`    | ADMIN           | Activate/deactivate a user            |
| GET    | `/api/users/me`             | authenticated   | Read my own profile                   |
| PUT    | `/api/users/me`             | authenticated   | Update my own profile (name only)     |

## Design choices worth knowing

- **Access + refresh tokens.** Access tokens are short-lived (15 min) and
  stateless. Refresh tokens are longer-lived (7 days) but persisted in
  Postgres, so logout / an admin action can actually invalidate a session
  instead of waiting for expiry.
- **Refresh token rotation.** Every `/auth/refresh` call revokes the old
  refresh token and issues a new one — reuse of a stolen-but-already-rotated
  token simply fails.
- **RBAC via `@PreAuthorize`, not URL pattern matching.** `SecurityConfig`
  only distinguishes public vs. authenticated; the ADMIN vs. EMPLOYEE split
  is method-level, next to the code it protects.
- **DTOs everywhere.** Controllers never accept or return the `User` entity
  directly, so the password hash can never leak into a response, and
  request payloads can't set fields like `enabled` that they shouldn't
  control.

## Testing notes

- Unit tests mock collaborators (`UserRepository`, `AuthenticationManager`,
  etc.) with Mockito — they test one class's logic in isolation.
- `AuthAndRbacIntegrationTest` boots the full Spring context with an H2
  in-memory database (`test` profile) and drives real HTTP requests through
  MockMvc, so it proves the security rules actually hold end-to-end: wrong
  password → 401, no token → 401, EMPLOYEE hitting an ADMIN endpoint → 403,
  and a token surviving logout → refresh rejected.

Run everything with:

```bash
mvn test
```

## A note on this environment

This project was scaffolded without network access to Maven Central, so the
build could not be compiled/run in the sandbox that generated it. Every file
was hand-reviewed for API correctness (jjwt 0.12.x fluent builder syntax,
Spring Security 6 / Boot 3.3 OAuth2 Resource Server APIs), but please run
`mvn test` yourself as the first step after downloading.
