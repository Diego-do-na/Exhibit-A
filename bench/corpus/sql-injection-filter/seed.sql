CREATE TABLE products (
    id INTEGER PRIMARY KEY,
    name TEXT NOT NULL UNIQUE,
    price_cents INTEGER NOT NULL
);
INSERT INTO products (id, name, price_cents) VALUES
    (1, 'widget', 1999),
    (2, 'gadget', 2999),
    (3, 'sprocket', 399);
