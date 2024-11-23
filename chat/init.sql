-- Use the specified database (Replace 'chatdb' with your actual database name if different)
USE chatdb;

-- Drop tables if they already exist (to avoid conflicts during development/testing)
DROP TABLE IF EXISTS users;
DROP TABLE IF EXISTS messages;
DROP TABLE IF EXISTS ivs;
DROP TABLE IF EXISTS salts;

-- Create 'users' table
CREATE TABLE users (
    user_id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(255) NOT NULL UNIQUE,
    password VARCHAR(255) NOT NULL, -- In a real application, this should store hashed passwords, not plain text
    password_salt VARCHAR(255) NOT NULL, 
    totp_key VARCHAR(255) NOT NULL,
    recovery_key VARCHAR(255) NOT NULL,
    recovery_key_salt VARCHAR(255) NOT NULL,
    public_key TEXT NOT NULL,

    failed_login_times INT DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);


-- Create 'messages' table
CREATE TABLE messages (
    message_id INT AUTO_INCREMENT PRIMARY KEY,
    sender_id INT NOT NULL,
    receiver_id INT NOT NULL,

    ciphertext TEXT NOT NULL,
    salt INT NOT NULL,
    IV INT NOT NULL,
    HMAC_IV TEXT NOT NULL,

    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (sender_id) REFERENCES users(user_id),
    FOREIGN KEY (receiver_id) REFERENCES users(user_id)
);

-- Create 'ivs' table
CREATE TABLE ivs (
    sender_id INT NOT NULL,
    receiver_id INT NOT NULL,
    salt INT NOT NULL,

    IV INT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (sender_id, receiver_id, salt)
);

-- Create 'salts' table
CREATE TABLE salts (
    user_id INT PRIMARY KEY,
    last_salt INT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Optionally, insert some initial data for testing
-- INSERT INTO users (username, password) VALUES ('Alice', 'AlicePassword'); -- Use hashed passwords in production
-- INSERT INTO users (username, password) VALUES ('Bob', 'BobPassword'); -- Use hashed passwords in production
