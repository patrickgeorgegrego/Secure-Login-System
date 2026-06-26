# Secure Login System

## Overview
A production-grade, secure authentication system built with Python, Flask, SQLAlchemy, and Bcrypt. This application provides robust user registration, secure login capabilities, and an authenticated dashboard. It has been engineered from the ground up with defensive security best practices to mitigate common OWASP vulnerabilities.

## Core Security Defenses

### 1. SQL Injection (SQLi) Mitigation
All database interactions and data manipulation are securely handled via the **SQLAlchemy ORM** (Object-Relational Mapping) data abstraction layer. By avoiding raw SQL strings and strictly utilizing parameterized execution, the application inherently defends against SQL Injection attacks.

### 2. Cryptographic Password Hashing
Raw passwords are never stored in the database. The system utilizes **Bcrypt** for secure cryptographic password hashing. Bcrypt includes built-in salting and adaptive key derivation functions, effectively defending against credential harvesting, rainbow tables, and brute-force attacks.

### 3. Server-Side Data Input Validation
To prevent malicious payloads and enforce data integrity at the boundary, rigorous server-side validation is implemented. Form inputs are thoroughly validated using strict Regex patterns to ensure only alphanumeric characters are processed, alongside explicit length boundary constraints for both usernames and passwords.

### 4. Session Tracking & Cookie Isolation
Session context and state tracking are hardened using critical security flags to protect authentication tokens:
- **`HttpOnly`**: Mitigates Cross-Site Scripting (XSS) token theft by completely blocking client-side JavaScript from accessing the session cookie.
- **`SameSite=Lax`**: Defends against Cross-Site Request Forgery (CSRF) vulnerabilities by restricting the browser from sending cookies alongside risky cross-site requests.

### 5. Access Control Filters
Internal resources and the user dashboard are strictly protected using authorization filters. The implementation utilizes Flask-Login's **`@login_required`** wrapper mechanisms to enforce authentication requirements, ensuring that unauthorized actors cannot bypass authentication logic to access private endpoints.

## Technology Stack
- **Framework**: Flask
- **Database**: SQLite & Flask-SQLAlchemy
- **Authentication**: Flask-Login
- **Cryptography**: Flask-Bcrypt
