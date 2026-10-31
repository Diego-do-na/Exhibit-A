CREATE TABLE orders (
    id INTEGER PRIMARY KEY,
    customer TEXT NOT NULL,
    placed_at TEXT NOT NULL,
    total_cents INTEGER NOT NULL,
    status TEXT NOT NULL
);
INSERT INTO orders (id, customer, placed_at, total_cents, status) VALUES
    (1, 'acme', '2023-11-03', 12500, 'paid'),
    (2, 'globex', '2023-11-19', 8900, 'paid'),
    (3, 'acme', '2023-12-02', 4300, 'paid'),
    (4, 'initech', '2023-12-24', 15000, 'refunded'),
    (5, 'umbrella', '2024-01-07', 22100, 'paid'),
    (6, 'acme', '2024-01-15', 6400, 'paid'),
    (7, 'globex', '2024-02-01', 9900, 'paid'),
    (8, 'initech', '2024-02-14', 3100, 'paid'),
    (9, 'umbrella', '2024-02-29', 17800, 'paid'),
    (10, 'acme', '2024-03-05', 5200, 'cancelled'),
    (11, 'globex', '2024-03-18', 7700, 'paid'),
    (12, 'initech', '2024-03-30', 12300, 'paid');
