# API Documentation

## Base URL
`https://amide-backend.vercel.app` or `http://localhost:3000` (local development)

---

## Routes

### 1. **GET /** - Health Check
**Purpose:** Check if the API is running

**Request Format:**
```http
GET /
```

**Response:**
```json
{
    "status": "ok",
    "message": "API is running",
    "service": "amide-backend"
}
```

**Status Code:** `200 OK`

---

### 2. **POST /signup** - Send OTP for Signup
**Purpose:** Generate and send OTP to user's email for signup verification

**Request Format:**
```http
POST /signup
Content-Type: application/json

{
    "email": "user@example.com"
}
```

**Response (New OTP Sent):**
```json
{
    "status": "ok",
    "otpSent": true,
    "email": "user@example.com"
}
```

**Response (OTP Already Exists):**
```json
{
    "status": "exists",
    "otpSent": false,
    "timeLeft": 600,
    "email": "user@example.com"
}
```

**Response (Error):**
```json
{
    "error": "Email is required"
}
```

**Status Codes:**
- `200 OK` - OTP sent or already exists
- `400 Bad Request` - Missing email or invalid request format
- `500 Internal Server Error` - Email sending failed

---

### 3. **POST /verify_otp** - Verify OTP
**Purpose:** Verify the OTP sent to user's email

**Request Format:**
```http
POST /verify_otp
Content-Type: application/json

{
    "email": "user@example.com",
    "otp": "123456",
    "password": "user password"
}
```

**Response (Valid OTP):**
```json
{
    "status": "verified",
    "verified": true,
    "message": "OTP verified successfully"
}
```

**Response (Invalid OTP):**
```json
{
    "status": "invalid",
    "verified": false,
    "message": "Invalid OTP"
}
```

**Response (Expired/Not Found):**
```json
{
    "status": "not_found",
    "verified": false,
    "message": "OTP does not exist or has expired"
}
```

**Status Codes:**
- `200 OK` - OTP verified successfully
- `400 Bad Request` - Invalid OTP, expired OTP, or missing fields

---

### 4. **POST /signin** - Sign in with Email and Password
**Purpose:** Authenticate users using their email and password

**Request Format:**
```http
POST /signin
Content-Type: application/json

{
    "email": "user@example.com",
    "password": "hashed_password"
}
```

**Response (Success):**
```json
{
    "success": true
}
```

**Response (Failure):**
```json
{
    "success": false
}
```

**Response (Missing Fields):**
```json
{
    "error": "Email and password are required"
}
```

**Response (Database Error):**
```json
{
    "error": "Database error",
    "details": "..."
}
```

**Status Codes:**
- `200 OK` - Success or failure
- `400 Bad Request` - Missing fields
- `500 Internal Server Error` - Database error

---

## Notes

1. **OTP Expiry:** OTPs expire after 15 minutes (900 seconds)
2. **Rate Limiting:** Only one OTP per email at a time
3. **Email Template:** Uses branded HTML template with amide logo
4. **Content-Type:** All POST requests must use `application/json`
5. **Redis:** Uses Redis for OTP storage and management

## Error Handling

All routes return JSON responses. Common error formats:

```json
{
    "error": "Error description",
    "details": "Additional error details (if applicable)"
}
```

For invalid Content-Type:
```json
{
    "error": "Content-Type must be application/json"
}
```