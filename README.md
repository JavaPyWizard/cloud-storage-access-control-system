# Cloud Storage Access Control and Policy Verification System

**AegisVault — Cloud Storage Security Simulator**

A full-stack cybersecurity application developed using Python, FastAPI, PostgreSQL, HTML, CSS, and vanilla JavaScript.

The system models cloud-storage access policies, enforces authorization rules, simulates access requests, independently verifies policy decisions, and provides security monitoring through an administrative dashboard.

Developed as **Activity 12** for the Cryptography and Network Security course.

## Features

### Access Control
- PRIVATE, PUBLIC_READ, and ROLE_RESTRICTED policies
- Role-based authorization using ADMIN, EDITOR, and VIEWER roles
- Owner-based file permissions
- Authorized and unauthorized access-request simulation
- Independent expected-versus-actual access matrix
- CSV export of verification results

### File Management
- File upload and download
- Access-controlled file operations
- File ownership and policy management
- Filename, extension, and content validation
- Upload-size restrictions

### Security
- Password hashing using Argon2
- Session-based authentication
- CSRF protection
- Login rate limiting
- Secure cookie configuration
- HTTP security headers and Content Security Policy
- Audit logging of access decisions

### Security Monitoring
- Allowed and denied request statistics
- Access-denial rate
- Real versus simulated event classification
- Operation-level activity breakdown
- Rule-based suspicious-activity detection
- Administrator-only monitoring dashboard

## Technology Stack

| Layer | Technology |
|---|---|
| Backend | Python, FastAPI |
| Frontend | HTML, CSS, Vanilla JavaScript |
| Database | PostgreSQL / SQLite |
| ORM | SQLAlchemy |
| Authentication | Argon2, signed sessions |
| Testing | Pytest, FastAPI TestClient |
| Database driver | Psycopg 3 |

## System Architecture

```text
Browser
   |
   v
HTML / CSS / JavaScript
   |
   v
FastAPI REST Endpoints
   |
   +-- Authentication and Session Management
   |
   +-- Access-Control Policy Engine
   |
   +-- Access-Request Simulator
   |
   +-- Independent Verification Engine
   |
   +-- Security Analytics and Audit Logging
   |
   v
SQLAlchemy ORM
   |
   v
PostgreSQL / SQLite

File contents are stored separately
in the local storage directory.
```

## Access-Control Policies

| Policy | Owner | Matching role | Other user | Anonymous |
|---|---|---|---|---|
| PRIVATE | Read, Write, Delete | Denied | Denied | Denied |
| PUBLIC_READ | Read, Write, Delete | Read | Read | Read |
| ROLE_RESTRICTED | Read, Write, Delete | Read | Denied | Denied |

Write operations represent policy modifications. Simulated requests do not perform real file modifications or deletions.

## Installation

### Prerequisites

- Python 3.11 or later
- pip
- Git
- PostgreSQL 17 (optional for local development)

### Clone the repository

```bash
git clone YOUR_REPOSITORY_URL
cd cloud-storage-access-control-simulator
```

### Create a virtual environment

```bash
python3 -m venv .venv
source .venv/bin/activate
```

On Windows:

```powershell
.venv\Scripts\activate
```

### Install dependencies

```bash
pip install -r requirements.txt
```

### Configure environment variables

```bash
cp .env.example .env
```

Generate a secure session secret:

```bash
python -c "import secrets; print(secrets.token_urlsafe(48))"
```

Replace the placeholder `SESSION_SECRET` in `.env` with the generated value.

SQLite is configured by default for local development.

For PostgreSQL, create a database and configure `DATABASE_URL` using your own credentials.

### Start the application

```bash
uvicorn app.main:app --reload
```

Open:

http://127.0.0.1:8000

The first registered account becomes the bootstrap administrator.

## Running Tests

```bash
python -m pytest -q
```

**Latest verified local result: 66 passed, 0 failed.**

The automated tests cover access-control policies, API authorization, authentication, rate limiting, upload validation, analytics, CSRF protection, and session security.

Tests use an isolated temporary SQLite database and do not modify the configured PostgreSQL application database.

## Independent Policy Verification

The verification engine compares policy decisions against a separately implemented access matrix.

The tested configuration contained:

- 2 registered users
- 1 anonymous actor
- 3 storage objects
- 3 operations per actor and object

**Result: 27/27 expected decisions matched actual decisions.**

The matrix can be exported as CSV for independent review.

## Security Monitoring

The administrator dashboard provides access-decision statistics, operation breakdowns, audit history, and rule-based suspicious-activity alerts.

Repeated denied requests within a defined time window can trigger alerts. These alerts indicate unusual access patterns and do not establish malicious intent.

## Project Scope and Limitations

AegisVault is an educational cloud-storage access-control simulator, not a commercial cloud-storage platform.

File contents are stored locally rather than in AWS S3, Azure Blob Storage, or Google Cloud Storage.

The current implementation is designed for local development and academic demonstration. Public internet deployment would require additional hardening, including HTTPS, distributed rate limiting, malware scanning, managed secret storage, database migrations, and operational security controls.

## Academic Context

**Course:** Cryptography and Network Security
**Activity:** 12 — Cloud Storage Access Control Simulator

### Project Team

| Name | SAP ID |
|---|---|
| Divyansh Kumar Singh | 590012175 |
| Adithya Sai PV | 590012133 |
| Shivansh Gupta | 590017449 |
| Arnav Tiwari | 590011418 |
| Aaryan Mehta | 590018675 |

---

*Developed as an academic cybersecurity project to demonstrate access-control enforcement, independent policy verification, and security monitoring.*
