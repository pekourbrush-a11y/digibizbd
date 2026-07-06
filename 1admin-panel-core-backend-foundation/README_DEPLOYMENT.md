# Admin Panel — Core Backend Foundation — Deployment Guide

## Scope of this delivery

This is **infrastructure only**. As requested, it deliberately does **not** include:

- Authentication (no login, sessions-as-login, password hashing/verification, 2FA, password reset)
- API endpoints / routes
- Controllers
- Models

What it *does* give you is the plumbing everything else will sit on top of: configuration, database connection, error handling, generic helpers, JSON output formatting, and two small non-auth infrastructure tables (`settings`, `activity_logs`, `notifications`).

## Recommended folder placement (cPanel)

```
/home/yourcpanelusername/            <- your cPanel home directory
│
├── app/                             <- upload here, OUTSIDE public_html
│   ├── config.php
│   ├── bootstrap.php
│   ├── autoload.php
│   ├── db.php
│   ├── response.php
│   ├── helpers.php
│   ├── functions.php
│   ├── classes/                    <- empty, ready for future classes
│   └── .htaccess                   <- copy of the provided .htaccess
│
├── storage/
│   ├── logs/                       <- php_errors.log written here
│   └── .htaccess                   <- copy of the provided .htaccess
│
├── database/
│   └── database.sql                <- import via phpMyAdmin, keep private
│
└── public_html/                    <- your EXISTING admin panel, untouched
    └── ...
```

Keeping `app/`, `storage/`, and `database/` **outside** `public_html` means your database password and internals are never reachable by any URL — no server config changes needed, this is standard on cPanel since your home directory already sits one level above `public_html`.

The single `.htaccess` file provided is a defense-in-depth extra: copy it into `app/` and `storage/` so that even a misconfigured upload can't expose those folders directly. A commented-out alternate block is included for hardening `public_html` itself.

## Setup steps

1. Upload `app/`, `storage/`, `database/` to your cPanel home directory (not inside `public_html`).
2. Open `app/config.php` and fill in your real database credentials (`DB_NAME`, `DB_USER`, `DB_PASS`) and set `APP_SECRET_KEY` to a random value:
   ```
   php -r "echo bin2hex(random_bytes(32));"
   ```
3. In phpMyAdmin, select your database and import `database/database.sql`. This creates `settings`, `activity_logs`, and `notifications`.
4. In any existing PHP file inside `public_html` that needs the database or helpers, add one line at the top:
   ```php
   require_once __DIR__ . '/../app/bootstrap.php';
   ```
   Adjust the `../` depth based on the file's location.
5. Set `APP_URL` and `APP_TIMEZONE` in `config.php` to match your actual site.

## What you get access to after including bootstrap.php

- `db()` — a `Database` singleton (PDO, prepared statements, transactions)
- `Response::success()` / `Response::error()` — JSON output helpers
- Helper functions in `helpers.php` — sanitisation, CSRF tokens, generic random tokens, client IP/user-agent, date formatting, flash messages
- Data functions in `functions.php` — `get_setting()`, `set_setting()`, `log_activity()`, `create_notification()`, `get_unread_notifications()`, `mark_notification_read()`
- A hardened, already-started `$_SESSION` (cookie flags only — no login logic)

Nothing in your existing HTML/CSS/JS/layout is touched. This foundation only activates in files that explicitly include `bootstrap.php`.

## What's intentionally missing (by design)

- **No `users` table** — add this yourself when you build Authentication, then attach real foreign keys from `activity_logs.actor_id` and `notifications.recipient_id` to `users.id`.
- **No login/session-auth flow, no password hashing, no 2FA, no password reset.**
- **No API routes or controllers** — `response.php` is only an output formatter; it defines no endpoints.

## Before going live

1. Replace the placeholder database credentials in `config.php`.
2. Replace `APP_SECRET_KEY` with a real random value.
3. Set `APP_URL` to your real domain.
4. Confirm `app/`, `storage/`, and `database/` are **not** reachable via any URL (try visiting `https://yourdomain.com/app/config.php` — it should 404 or connection-refuse, not display anything).
