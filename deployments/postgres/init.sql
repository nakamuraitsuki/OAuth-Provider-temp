CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

CREATE TABLE IF NOT EXISTS users (
    id           UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    username     VARCHAR(255) NOT NULL UNIQUE,
    display_name VARCHAR(255) NOT NULL,
    created_at   TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS credentials (
    user_id       UUID PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    password_hash TEXT NOT NULL,
    updated_at    TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS authorization_codes (
    code            VARCHAR(255) PRIMARY KEY,
    client_id       UUID NOT NULL,
    user_id         UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    redirect_uri    TEXT NOT NULL,
    state           TEXT,
    nonce           TEXT,
    expires_at      TIMESTAMP WITH TIME ZONE NOT NULL
);

CREATE TABLE IF NOT EXISTS authorization_code_scopes (
    code VARCHAR(255) REFERENCES authorization_codes(code) ON DELETE CASCADE,
    scope_id INTEGER NOT NULL,
    PRIMARY KEY (code, scope_id)
);

CREATE TABLE IF NOT EXISTS access_tokens (
    token VARCHAR(255) PRIMARY KEY,
    client_id UUID NOT NULL,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL
);

CREATE TABLE IF NOT EXISTS access_token_scopes (
    token VARCHAR(255) REFERENCES access_tokens(token) ON DELETE CASCADE,
    scope_id INTEGER NOT NULL,
    PRIMARY KEY (token, scope_id)
);

CREATE TABLE IF NOT EXISTS refresh_tokens (
    token VARCHAR(255) PRIMARY KEY,
    client_id UUID NOT NULL,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL
);

CREATE TABLE IF NOT EXISTS refresh_token_scopes (
    token VARCHAR(255) REFERENCES refresh_tokens(token) ON DELETE CASCADE,
    scope_id INTEGER NOT NULL,
    PRIMARY KEY (token, scope_id)
);