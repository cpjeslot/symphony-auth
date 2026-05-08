<?php

declare(strict_types=1);

namespace DoctrineMigrations;

use Doctrine\DBAL\Schema\Schema;
use Doctrine\Migrations\AbstractMigration;

/**
 * Auto-generated Migration: Please modify to your needs!
 */
final class Version20260507113809 extends AbstractMigration
{
    public function getDescription(): string
    {
        return '';
    }

    public function up(Schema $schema): void
    {
        // this up() migration is auto-generated, please modify it to your needs
        $this->addSql('CREATE TABLE active_sessions (id UUID NOT NULL, session_token_hash VARCHAR(64) NOT NULL, ip_address VARCHAR(45) DEFAULT NULL, user_agent VARCHAR(500) DEFAULT NULL, device_description VARCHAR(200) DEFAULT NULL, expires_at TIMESTAMP(0) WITHOUT TIME ZONE NOT NULL, last_activity_at TIMESTAMP(0) WITHOUT TIME ZONE NOT NULL, is_revoked BOOLEAN DEFAULT false NOT NULL, created_at TIMESTAMP(0) WITHOUT TIME ZONE NOT NULL, user_id UUID NOT NULL, PRIMARY KEY (id))');
        $this->addSql('CREATE UNIQUE INDEX UNIQ_60ECECCC532A5C81 ON active_sessions (session_token_hash)');
        $this->addSql('CREATE INDEX idx_as_user ON active_sessions (user_id)');
        $this->addSql('CREATE INDEX idx_as_expires ON active_sessions (expires_at)');
        $this->addSql('CREATE TABLE email_otps (id UUID NOT NULL, otp_hash VARCHAR(255) NOT NULL, expires_at TIMESTAMP(0) WITHOUT TIME ZONE NOT NULL, retry_count INT DEFAULT 0 NOT NULL, max_retries INT DEFAULT 5 NOT NULL, is_used BOOLEAN DEFAULT false NOT NULL, purpose VARCHAR(50) DEFAULT \'login_2fa\' NOT NULL, request_ip VARCHAR(45) DEFAULT NULL, created_at TIMESTAMP(0) WITHOUT TIME ZONE NOT NULL, user_id UUID NOT NULL, PRIMARY KEY (id))');
        $this->addSql('CREATE INDEX idx_otp_user ON email_otps (user_id)');
        $this->addSql('CREATE INDEX idx_otp_expires ON email_otps (expires_at)');
        $this->addSql('CREATE TABLE email_verification_tokens (id UUID NOT NULL, token_hash VARCHAR(64) NOT NULL, email VARCHAR(254) NOT NULL, expires_at TIMESTAMP(0) WITHOUT TIME ZONE NOT NULL, is_used BOOLEAN DEFAULT false NOT NULL, created_at TIMESTAMP(0) WITHOUT TIME ZONE NOT NULL, verified_at TIMESTAMP(0) WITHOUT TIME ZONE DEFAULT NULL, user_id UUID NOT NULL, PRIMARY KEY (id))');
        $this->addSql('CREATE UNIQUE INDEX UNIQ_C81CA2ACB3BC57DA ON email_verification_tokens (token_hash)');
        $this->addSql('CREATE INDEX idx_evt_user ON email_verification_tokens (user_id)');
        $this->addSql('CREATE TABLE login_histories (id UUID NOT NULL, login_identifier VARCHAR(254) DEFAULT NULL, is_successful BOOLEAN DEFAULT false NOT NULL, failure_reason VARCHAR(100) DEFAULT NULL, ip_address VARCHAR(45) DEFAULT NULL, user_agent VARCHAR(500) DEFAULT NULL, auth_method VARCHAR(50) DEFAULT NULL, session_id VARCHAR(128) DEFAULT NULL, two_factor_completed BOOLEAN DEFAULT false NOT NULL, country VARCHAR(100) DEFAULT NULL, created_at TIMESTAMP(0) WITHOUT TIME ZONE NOT NULL, user_id UUID DEFAULT NULL, PRIMARY KEY (id))');
        $this->addSql('CREATE INDEX idx_lh_user ON login_histories (user_id)');
        $this->addSql('CREATE INDEX idx_lh_created ON login_histories (created_at)');
        $this->addSql('CREATE INDEX idx_lh_success ON login_histories (is_successful)');
        $this->addSql('COMMENT ON TABLE login_histories IS \'Immutable audit log of login attempts\'');
        $this->addSql('CREATE TABLE password_reset_tokens (id UUID NOT NULL, token_hash VARCHAR(64) NOT NULL, expires_at TIMESTAMP(0) WITHOUT TIME ZONE NOT NULL, is_used BOOLEAN DEFAULT false NOT NULL, request_ip VARCHAR(45) DEFAULT NULL, created_at TIMESTAMP(0) WITHOUT TIME ZONE NOT NULL, used_at TIMESTAMP(0) WITHOUT TIME ZONE DEFAULT NULL, user_id UUID NOT NULL, PRIMARY KEY (id))');
        $this->addSql('CREATE UNIQUE INDEX UNIQ_3967A216B3BC57DA ON password_reset_tokens (token_hash)');
        $this->addSql('CREATE INDEX idx_prt_user ON password_reset_tokens (user_id)');
        $this->addSql('CREATE INDEX idx_prt_expires ON password_reset_tokens (expires_at)');
        $this->addSql('CREATE TABLE security_audit_logs (id UUID NOT NULL, event_type VARCHAR(255) NOT NULL, description TEXT DEFAULT NULL, ip_address VARCHAR(45) DEFAULT NULL, user_agent VARCHAR(500) DEFAULT NULL, severity VARCHAR(20) DEFAULT \'info\' NOT NULL, context JSONB DEFAULT NULL, entity_type VARCHAR(100) DEFAULT NULL, entity_id VARCHAR(36) DEFAULT NULL, created_at TIMESTAMP(0) WITHOUT TIME ZONE NOT NULL, user_id UUID DEFAULT NULL, PRIMARY KEY (id))');
        $this->addSql('CREATE INDEX idx_sal_user ON security_audit_logs (user_id)');
        $this->addSql('CREATE INDEX idx_sal_event ON security_audit_logs (event_type)');
        $this->addSql('CREATE INDEX idx_sal_created ON security_audit_logs (created_at)');
        $this->addSql('CREATE INDEX idx_sal_ip ON security_audit_logs (ip_address)');
        $this->addSql('COMMENT ON TABLE security_audit_logs IS \'Immutable security event audit log\'');
        $this->addSql('CREATE TABLE social_accounts (id UUID NOT NULL, provider VARCHAR(255) NOT NULL, provider_user_id VARCHAR(255) NOT NULL, provider_email VARCHAR(254) DEFAULT NULL, provider_name VARCHAR(255) DEFAULT NULL, provider_avatar VARCHAR(500) DEFAULT NULL, access_token TEXT DEFAULT NULL, refresh_token TEXT DEFAULT NULL, token_expires_at TIMESTAMP(0) WITHOUT TIME ZONE DEFAULT NULL, provider_metadata JSONB DEFAULT NULL, created_at TIMESTAMP(0) WITHOUT TIME ZONE NOT NULL, updated_at TIMESTAMP(0) WITHOUT TIME ZONE NOT NULL, user_id UUID NOT NULL, PRIMARY KEY (id))');
        $this->addSql('CREATE INDEX idx_social_user ON social_accounts (user_id)');
        $this->addSql('CREATE UNIQUE INDEX uq_provider_user ON social_accounts (provider, provider_user_id)');
        $this->addSql('CREATE TABLE users (id UUID NOT NULL, employee_id VARCHAR(50) DEFAULT NULL, first_name VARCHAR(100) NOT NULL, middle_name VARCHAR(100) DEFAULT NULL, last_name VARCHAR(100) NOT NULL, full_name VARCHAR(300) NOT NULL, username VARCHAR(50) DEFAULT NULL, email VARCHAR(254) NOT NULL, mobile_number VARCHAR(20) DEFAULT NULL, alternate_mobile VARCHAR(20) DEFAULT NULL, profile_photo VARCHAR(500) DEFAULT NULL, gender VARCHAR(255) DEFAULT NULL, date_of_birth DATE DEFAULT NULL, marital_status VARCHAR(255) DEFAULT NULL, blood_group VARCHAR(255) DEFAULT NULL, nationality VARCHAR(100) DEFAULT NULL, language JSONB DEFAULT NULL, password_hash VARCHAR(255) NOT NULL, roles JSONB NOT NULL, permissions JSONB DEFAULT NULL, access_level INT DEFAULT 0 NOT NULL, login_type VARCHAR(255) DEFAULT \'email\' NOT NULL, two_factor_enabled BOOLEAN DEFAULT false NOT NULL, otp_verified BOOLEAN DEFAULT false NOT NULL, email_verified BOOLEAN DEFAULT false NOT NULL, mobile_verified BOOLEAN DEFAULT false NOT NULL, last_login TIMESTAMP(0) WITHOUT TIME ZONE DEFAULT NULL, last_login_ip VARCHAR(45) DEFAULT NULL, failed_login_attempts INT DEFAULT 0 NOT NULL, locked_until TIMESTAMP(0) WITHOUT TIME ZONE DEFAULT NULL, account_status VARCHAR(255) DEFAULT \'active\' NOT NULL, force_password_change BOOLEAN DEFAULT false NOT NULL, device_token VARCHAR(500) DEFAULT NULL, refresh_token VARCHAR(255) DEFAULT NULL, created_at TIMESTAMP(0) WITHOUT TIME ZONE NOT NULL, updated_at TIMESTAMP(0) WITHOUT TIME ZONE NOT NULL, deleted_at TIMESTAMP(0) WITHOUT TIME ZONE DEFAULT NULL, PRIMARY KEY (id))');
        $this->addSql('CREATE UNIQUE INDEX UNIQ_1483A5E98C03F15C ON users (employee_id)');
        $this->addSql('CREATE UNIQUE INDEX UNIQ_1483A5E9F85E0677 ON users (username)');
        $this->addSql('CREATE UNIQUE INDEX UNIQ_1483A5E9E7927C74 ON users (email)');
        $this->addSql('CREATE UNIQUE INDEX UNIQ_1483A5E9E9B4F45E ON users (mobile_number)');
        $this->addSql('CREATE INDEX idx_user_email ON users (email)');
        $this->addSql('CREATE INDEX idx_user_mobile ON users (mobile_number)');
        $this->addSql('CREATE INDEX idx_user_username ON users (username)');
        $this->addSql('CREATE INDEX idx_user_employee_id ON users (employee_id)');
        $this->addSql('CREATE INDEX idx_user_status ON users (account_status)');
        $this->addSql('COMMENT ON TABLE users IS \'Core user accounts table\'');
        $this->addSql('CREATE TABLE rememberme_token (series VARCHAR(88) NOT NULL, value VARCHAR(88) NOT NULL, lastUsed TIMESTAMP(0) WITHOUT TIME ZONE NOT NULL, class VARCHAR(100) NOT NULL, username VARCHAR(200) NOT NULL, PRIMARY KEY (series))');
        $this->addSql('ALTER TABLE active_sessions ADD CONSTRAINT FK_60ECECCCA76ED395 FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE NOT DEFERRABLE');
        $this->addSql('ALTER TABLE email_otps ADD CONSTRAINT FK_68FC8130A76ED395 FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE NOT DEFERRABLE');
        $this->addSql('ALTER TABLE email_verification_tokens ADD CONSTRAINT FK_C81CA2ACA76ED395 FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE NOT DEFERRABLE');
        $this->addSql('ALTER TABLE login_histories ADD CONSTRAINT FK_AF6FE456A76ED395 FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE SET NULL NOT DEFERRABLE');
        $this->addSql('ALTER TABLE password_reset_tokens ADD CONSTRAINT FK_3967A216A76ED395 FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE NOT DEFERRABLE');
        $this->addSql('ALTER TABLE security_audit_logs ADD CONSTRAINT FK_16FDFA2DA76ED395 FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE SET NULL NOT DEFERRABLE');
        $this->addSql('ALTER TABLE social_accounts ADD CONSTRAINT FK_44F90A80A76ED395 FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE NOT DEFERRABLE');
    }

    public function down(Schema $schema): void
    {
        // this down() migration is auto-generated, please modify it to your needs
        $this->addSql('ALTER TABLE active_sessions DROP CONSTRAINT FK_60ECECCCA76ED395');
        $this->addSql('ALTER TABLE email_otps DROP CONSTRAINT FK_68FC8130A76ED395');
        $this->addSql('ALTER TABLE email_verification_tokens DROP CONSTRAINT FK_C81CA2ACA76ED395');
        $this->addSql('ALTER TABLE login_histories DROP CONSTRAINT FK_AF6FE456A76ED395');
        $this->addSql('ALTER TABLE password_reset_tokens DROP CONSTRAINT FK_3967A216A76ED395');
        $this->addSql('ALTER TABLE security_audit_logs DROP CONSTRAINT FK_16FDFA2DA76ED395');
        $this->addSql('ALTER TABLE social_accounts DROP CONSTRAINT FK_44F90A80A76ED395');
        $this->addSql('DROP TABLE active_sessions');
        $this->addSql('DROP TABLE email_otps');
        $this->addSql('DROP TABLE email_verification_tokens');
        $this->addSql('DROP TABLE login_histories');
        $this->addSql('DROP TABLE password_reset_tokens');
        $this->addSql('DROP TABLE security_audit_logs');
        $this->addSql('DROP TABLE social_accounts');
        $this->addSql('DROP TABLE users');
        $this->addSql('DROP TABLE rememberme_token');
    }
}
