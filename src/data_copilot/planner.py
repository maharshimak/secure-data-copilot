import re

from data_copilot.models import QueryPlan, TableInfo


class DeterministicPlanner:
    """Transparent baseline planner for a reproducible local demo."""

    def plan(self, question: str, schema: list[TableInfo]) -> QueryPlan:
        q = question.lower().strip()
        table_names = {table.name.lower(): table.name for table in schema}

        if (
            "customer" in q
            and "customers" in table_names
            and any(term in q for term in ("top", "highest", "revenue", "sales"))
        ):
            return QueryPlan(
                question=question,
                sql=(
                    "SELECT c.name, SUM(o.amount) AS revenue "
                    "FROM customers c "
                    "JOIN orders o ON o.customer_id = c.id "
                    "GROUP BY c.id, c.name "
                    "ORDER BY revenue DESC"
                ),
                rationale="Aggregate order value by customer and rank descending.",
                confidence=0.95,
            )

        if "revenue" in q and "orders" in table_names:
            return QueryPlan(
                question=question,
                sql="SELECT SUM(amount) AS total_revenue FROM orders",
                rationale="Sum the order amount column.",
                confidence=0.90,
            )

        if "order" in q and "orders" in table_names:
            return QueryPlan(
                question=question,
                sql="SELECT * FROM orders ORDER BY created_at DESC",
                rationale="Return recent orders.",
                confidence=0.80,
            )

        for lowered_name, actual_name in table_names.items():
            if re.search(rf"\b{re.escape(lowered_name)}\b", q):
                escaped = actual_name.replace('"', '""')
                return QueryPlan(
                    question=question,
                    sql=f'SELECT * FROM "{escaped}"',
                    rationale=f"Question references table {actual_name}.",
                    confidence=0.55,
                )

        raise ValueError("The deterministic planner could not map the question to the schema.")
