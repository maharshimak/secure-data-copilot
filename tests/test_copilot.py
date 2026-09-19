import sqlite3

from data_copilot.executor import DataCopilot


def test_top_customer_query(tmp_path) -> None:
    db = tmp_path / "demo.db"
    connection = sqlite3.connect(db)
    connection.executescript(
        """
        CREATE TABLE customers(id INTEGER PRIMARY KEY, name TEXT);
        CREATE TABLE orders(id INTEGER PRIMARY KEY, customer_id INTEGER, amount REAL, created_at TEXT);
        INSERT INTO customers VALUES (1, 'Alpha'), (2, 'Beta');
        INSERT INTO orders VALUES
          (1, 1, 100.0, '2026-01-01'),
          (2, 1, 50.0, '2026-01-02'),
          (3, 2, 70.0, '2026-01-03');
        """
    )
    connection.commit()
    connection.close()

    result = DataCopilot(str(db)).ask("show top customers by revenue")

    assert result.rows[0]["name"] == "Alpha"
    assert result.rows[0]["revenue"] == 150.0
    assert result.audit.row_count == 2
