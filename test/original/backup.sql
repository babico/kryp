CREATE TABLE users (id INT PRIMARY KEY, name TEXT, email TEXT);
INSERT INTO users VALUES (1, 'admin', 'admin@example.com');
INSERT INTO users VALUES (2, 'user', 'user@example.com');

CREATE TABLE orders (id INT PRIMARY KEY, user_id INT, amount DECIMAL, created_at TIMESTAMP);
INSERT INTO orders VALUES (1001, 1, 250.00, '2026-01-15 10:30:00');
INSERT INTO orders VALUES (1002, 1, 1750.00, '2026-02-20 14:45:00');
INSERT INTO orders VALUES (1003, 2, 89.99, '2026-03-05 09:15:00');
