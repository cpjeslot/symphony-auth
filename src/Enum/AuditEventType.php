<?php

declare(strict_types=1);

namespace App\Enum;

/**
 * Audit log event type enumeration.
 * Standardizes security event naming across the application.
 */
enum AuditEventType: string
{
    // Authentication events
    case LoginSuccess = 'login.success';
    case LoginFailure = 'login.failure';
    case LoginLockedOut = 'login.locked_out';
    case Logout = 'auth.logout';
    case SessionExpired = 'auth.session_expired';

    // Registration events
    case UserRegistered = 'user.registered';
    case EmailVerified = 'user.email_verified';
    case MobileVerified = 'user.mobile_verified';

    // 2FA events
    case TwoFactorEnabled = '2fa.enabled';
    case TwoFactorDisabled = '2fa.disabled';
    case OtpSent = '2fa.otp_sent';
    case OtpVerifySuccess = '2fa.otp_success';
    case OtpVerifyFailure = '2fa.otp_failure';
    case OtpExpired = '2fa.otp_expired';
    case OtpRateLimited = '2fa.otp_rate_limited';

    // Password events
    case PasswordChanged = 'password.changed';
    case PasswordResetRequested = 'password.reset_requested';
    case PasswordResetCompleted = 'password.reset_completed';
    case PasswordResetInvalid = 'password.reset_invalid';

    // OAuth events
    case SocialLoginSuccess = 'oauth.login_success';
    case SocialAccountLinked = 'oauth.account_linked';
    case SocialAccountUnlinked = 'oauth.account_unlinked';

    // Admin events
    case AdminUserDisabled = 'admin.user_disabled';
    case AdminUserEnabled = 'admin.user_enabled';
    case AdminForcePasswordReset = 'admin.force_password_reset';
    case AdminRoleChanged = 'admin.role_changed';

    // Security events
    case SuspiciousActivity = 'security.suspicious_activity';
    case TokenRefreshed = 'security.token_refreshed';
    case TokenRevoked = 'security.token_revoked';
    case ProfileUpdated = 'user.profile_updated';

    public function severity(): string
    {
        return match($this) {
            self::LoginFailure,
            self::LoginLockedOut,
            self::OtpVerifyFailure,
            self::SuspiciousActivity => 'warning',
            self::AdminUserDisabled,
            self::AdminForcePasswordReset,
            self::PasswordResetInvalid,
            self::TokenRevoked => 'error',
            default => 'info',
        };
    }
}
