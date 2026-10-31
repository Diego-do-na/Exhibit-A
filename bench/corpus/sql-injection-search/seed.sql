CREATE TABLE products (
    id INTEGER PRIMARY KEY,
    name TEXT NOT NULL,
    category TEXT NOT NULL,
    price_cents INTEGER NOT NULL
);
INSERT INTO products (id, name, category, price_cents) VALUES
    (1, 'claw hammer', 'tools', 1899),
    (2, 'garden hose', 'garden', 2450),
    (3, 'cast iron pan', 'kitchen', 3200),
    (4, 'hand saw', 'tools', 2199),
    (5, 'wooden spoon', 'kitchen', 399),
    (6, 'plant pot', 'garden', 799),
    (7, 'screwdriver set', 'tools', 1499),
    (8, 'chef knife', 'kitchen', 4999);
