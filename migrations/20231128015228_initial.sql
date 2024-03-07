CREATE TABLE "user" (
    id VARCHAR PRIMARY KEY,
    account_id VARCHAR NOT NULL,
    provider VARCHAR NOT NULL,
    username VARCHAR NOT NULL,
    image_url VARCHAR,
    CONSTRAINT unique_provider_account UNIQUE (provider, account_id)
);

CREATE TABLE user_session (
    id VARCHAR PRIMARY KEY,
    user_id VARCHAR NOT NULL,
    created_at TIMESTAMP NOT NULL,
    expires_at TIMESTAMP NOT NULL,
    FOREIGN KEY (user_id) REFERENCES "user"(id) ON DELETE CASCADE
);
