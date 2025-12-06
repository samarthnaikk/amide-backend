# API Documentation

**Base URL**
`https://amide-backend.vercel.app` (production)

---

## Notes (global)

* All **POST** endpoints **must** use `Content-Type: application/json`.
* Passwords must be **hashed client-side** before being sent for signup/verify and signin.
* OTPs expire after **900 seconds (15 minutes)**.
* OTP is used **only for signup**. Signin does **not** require OTP.
* Redis is used to store OTPs (key format: `otp:<email>`).
* Supabase is used for user storage via the Supabase Python client.
* All responses are JSON.

---

## 1) `GET /` — Health check

**Request**

```
GET /
```

**Response (200)**

```json
{
  "status": "ok",
  "message": "API is running",
  "service": "amide-backend"
}
```

---

## 2) `POST /signup` — Send OTP for signup

**Purpose**: Generate a 6-digit OTP and send it to the user's email. If an OTP for the email already exists, returns the remaining TTL.

**Request body (JSON)**:

```json
{
  "email": "user@example.com",
  "password": "user_password"
}
```

**Responses**

* **New OTP created and email send attempted** — `200 OK`

```json
{
  "status": "ok",
  "otpSent": true,
  "email": "user@example.com"
}
```

* **OTP already exists for this email** — `200 OK`

```json
{
  "status": "exists",
  "otpSent": false,
  "timeLeft": 600,
  "email": "user@example.com"
}
```

* **Bad request (missing email or wrong Content-Type)** — `400 Bad Request`

```json
{
  "error": "Email is required"
}
```

* **Email send failure** — `500 Internal Server Error`

```json
{
  "error": "Failed to send email",
  "details": "error from Gmail API"
}
```

---

## 3) `POST /verify_otp` — Verify OTP and create user

**Purpose**: Verify OTP for signup. If OTP is valid, create the user in Supabase `users` table.

**Required request body (JSON)**:

```json
{
  "email": "user@example.com",
  "otp": "123456",
  "password": "user_password"
}
```

**Responses**

* **OTP verified and user created** — `200 OK`

```json
{
  "status": "verified",
  "verified": true,
  "message": "OTP verified and user created"
}
```

* **OTP verified but database insert failed** — `500 Internal Server Error`

```json
{
  "status": "db_error",
  "verified": true,
  "message": "OTP verified but failed to create user",
  "details": "supabase error details"
}
```

* **OTP expired or not found** — `400 Bad Request`

```json
{
  "status": "not_found",
  "verified": false,
  "message": "OTP does not exist or has expired"
}
```

* **OTP incorrect** — `400 Bad Request`

```json
{
  "status": "invalid",
  "verified": false,
  "message": "Invalid OTP"
}
```

* **Missing required fields** — `400 Bad Request`

```json
{
  "error": "Email, OTP and password are required"
}
```

---

## 4) `POST /signin` — Sign in with email and password

**Purpose**: Authenticate user by validating hashed password stored in Supabase.

**Request body (JSON)**:

```json
{
  "email": "user@example.com",
  "password": "user_password"
}
```

**Responses**

* **Success** — `200 OK`

```json
{
  "success": true
}
```

* **Fail (email missing or wrong password)** — `200 OK`

```json
{
  "success": false
}
```

* **Missing fields** — `400 Bad Request`

```json
{
  "error": "Email and password are required"
}
```

* **Database error** — `500 Internal Server Error`

```json
{
  "error": "Database error",
  "details": "error details"
}
```

---

## Error format (general)

```json
{
  "error": "Error message",
  "details": "Optional details"
}
```

