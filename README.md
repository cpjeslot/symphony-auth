# Symphony Auth — Enterprise-Grade Authentication Suite

A production-ready, highly secure, and modular authentication system built with **Symfony 7.3** and **PHP 8.3+**. This platform provides a robust foundation for enterprise applications, featuring advanced security protocols, real-time auditing, and a premium modern user interface.

---

## 🌟 Key Features

### 🔐 Security & Authentication
- **Advanced Hashing**: Uses **Argon2id** (the industry winner of the Password Hashing Competition) for maximum resistance against GPU/ASIC cracking.
- **Two-Factor Authentication (2FA)**: Native support for multi-factor security.
- **JWT Integration**: Stateless authentication for mobile apps and SPAs via **LexikJWT**.
- **OAuth2 / Social Login**: Seamless integration with **Google, GitHub, Facebook, and Apple**.
- **Rate Limiting**: Intelligent brute-force protection for login, registration, and password reset endpoints.
- **Account Lockout**: Automatic temporary account locking after multiple failed attempts.

### 🛡️ Auditing & Monitoring
- **Live Security Audit Logs**: Tracks critical events (failed logins, password changes, 2FA toggles) with IP and User-Agent tracking.
- **Login History**: Transparent access logs for every user.
- **Administrative Dashboard**: Powered by **EasyAdmin 5**, providing a powerful interface for user management and system monitoring.

### 🎨 Modern Experience
- **Glassmorphism UI**: A stunning, premium design system using custom CSS and Bootstrap 5.
- **Responsive Layouts**: Optimized for mobile, tablet, and desktop.
- **User Dashboard**: A personalized space for users to manage profile settings, security, and active sessions.

---

## 🛠️ Technology Stack
- **Framework**: Symfony 7.3 (MicroKernel)
- **Runtime**: PHP 8.3 / 8.4 / 8.5
- **Database**: PostgreSQL 16+
- **Styling**: Vanilla CSS3 + Bootstrap 5 (Custom design system)
- **API**: JWT (JSON Web Tokens)
- **Background Jobs**: Symfony Messenger (Async processing)

---

## ⚙️ Environment Configuration (`.env`)

To set up the project, copy `.env` to `.env.local` and configure the following variables:

### Core Configuration
```bash
APP_ENV=dev
APP_SECRET=your_32_char_secret_here
TRUSTED_PROXIES=127.0.0.1,REMOTE_ADDR
TRUSTED_HOSTS='^localhost|127\.0\.0\.1$'
```

### Database (PostgreSQL)
```bash
# Format: postgresql://db_user:db_password@127.0.0.1:5432/db_name?serverVersion=16&charset=utf8
DATABASE_URL="postgresql://postgres:12345678@127.0.0.1:5432/auth_db?serverVersion=16&charset=utf8"
```

### OAuth2 Social Login
```bash
# Google
GOOGLE_CLIENT_ID=your_id
GOOGLE_CLIENT_SECRET=your_secret

# GitHub
GITHUB_CLIENT_ID=your_id
GITHUB_CLIENT_SECRET=your_secret

# Facebook
FACEBOOK_CLIENT_ID=your_id
FACEBOOK_CLIENT_SECRET=your_secret

# Apple (Requires .p8 key file)
APPLE_CLIENT_ID=your_id
APPLE_TEAM_ID=your_team_id
APPLE_KEY_ID=your_key_id
```

### Security & Sessions
```bash
# JWT Keys passphrase
JWT_PASSPHRASE=your_passphrase

# Session Lifetime (seconds)
SESSION_LIFETIME=3600
```

---

## 🚀 Installation & Setup

### 1. Requirements
Ensure you have **PHP 8.3+** and **PostgreSQL** installed. Recommended PHP extensions: `intl`, `openssl`, `sodium`, `pdo_pgsql`.

### 2. Install Dependencies
```bash
composer install
```

### 3. Database Migration
```bash
php bin/console doctrine:database:create
php bin/console doctrine:migrations:migrate
```

### 4. Generate JWT Keys
```bash
php bin/console lexik:jwt:generate-keypair
```

### 5. Create Initial Admin
Use the custom CLI tool to bootstrap your first super-admin account:
```bash
php bin/console app:create-admin admin@example.com admin123456
```

### 6. Start the Server
```bash
php -S localhost:8000 -t public
```

---

## 📂 Project Structure
- `src/Admin`: EasyAdmin Dashboards and Configurations.
- `src/Controller`: Route handlers grouped by domain (Auth, Profile, Admin).
- `src/Security`: Authenticators, Guards, and Passport badges.
- `src/Service`: Modular business logic (Audit Logging, Registration, OTP).
- `templates/`: Premium Twig templates with the glassmorphism design system.

---

---

## 👨‍💻 Developer Information

**Chetan Patel**  
*Full Stack Developer & Enterprise Solutions Architect*

- 📧 **Email**: [cpjeslot@gmail.com](mailto:cpjeslot@gmail.com)
- 🌐 **Portfolio**: [jeslot.in](https://jeslot.in)
- 💼 **LinkedIn**: [linkedin.com/in/chetan-patel-aa5b6928](https://www.linkedin.com/in/chetan-patel-aa5b6928)

> "Building secure, scalable, and elegant solutions for the modern web."

---

## ☕ Support the Project

If you find this project helpful and want to support its continued development, you can buy me a coffee!

<a href="https://www.buymeacoffee.com/cpjeslot" target="_blank">
    <img src="https://cdn.buymeacoffee.com/buttons/v2/default-yellow.png" alt="Buy Me A Coffee" style="height: 60px !important;width: 217px !important;" >
</a>

### Scan to Support
![Support QR Code](public/images/support_qr.png)

---

## 📜 License
Proprietary — Built with care by Chetan Patel for enterprise scale.
