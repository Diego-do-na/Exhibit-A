CREATE TABLE users (
    id INTEGER PRIMARY KEY,
    username TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL
);
INSERT INTO users (id, username, password_hash, role) VALUES
    (1, 'alice', '6198f50cba51030c361ff55c6c2c32928f09ff71144cda86a1e22ff5d664b7fd', 'admin'),
    (2, 'bob', '7df25982c15c54e4067025d5e0de9f3ff26d289b980752883646666a706e133a', 'member'),
    (3, 'carol', 'c731884a35e095e31c6df567828a042ada3ea0196a58cf3af5ba4336d15dcd99', 'member');
