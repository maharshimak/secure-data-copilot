import sqlite3
from pathlib import Path


def main() -> None:
    path = Path(__file__).with_name("demo.db")
    if path.exists():
        path.unlink()

    connection = sqlite3.connect(path)
    connection.executescript(
        """
        CREATE TABLE customers (
            id INTEGER PRIMARY KEY,
            name TEXT NOT NULL,
            segment TEXT NOT NULL
        );

        CREATE TABLE orders (
            id INTEGER PRIMARY KEY,
            customer_id INTEGER NOT NULL,
            amount REAL NOT NULL,
            created_at TEXT NOT NULL,
            FOREIGN KEY(customer_id) REFERENCES customers(id)
        );

        INSERT INTO customers(id, name, segment) VALUES
          (1, 'Atlas Labs', 'Enterprise'),
          (2, 'Nova Retail', 'SMB'),
          (3, 'Orion Health', 'Enterprise');

        INSERT INTO orders(id, customer_id, amount, created_at) VALUES
          (1, 1, 9200.0, '2026-08-01'),
          (2, 1, 3100.0, '2026-08-14'),
          (3, 2, 1400.0, '2026-08-19'),
          (4, 3, 6800.0, '2026-08-22'),
          (5, 3, 5100.0, '2026-09-02');
        """
    )
    connection.commit()
    connection.close()
    print(f"Created demo database at {path}")


if __name__ == "__main__":
    main()
