import re

from data_copilot.models import QueryPlan, TableInfo


class DeterministicPlanner:
    """Transparent baseline planner for a reproducible local demo."""

    def plan(self, question: str, schema: list[TableInfo]) -> QueryPlan:
        if not isinstance(question, str) or not question.strip() or len(question) > 2000:
            raise ValueError("A question of 1 to 2000 characters is required.")
        q = question.lower().strip()
        if re.search(
            r"\b(insert|update|delete|drop|alter|create|replace|truncate|attach|detach|pragma|vacuum|grant|revoke)\b",
            q,
        ):
            raise ValueError("Mutation or administrative intent is not allowed.")
        table_names = {table.name.lower(): table.name for table in schema}

        if (
            "customer" in q
            and "customers" in table_names
            and "orders" in table_names
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
                confidence=None,
            )

        if "revenue" in q and "orders" in table_names:
            return QueryPlan(
                question=question,
                sql="SELECT SUM(amount) AS total_revenue FROM orders",
                rationale="Sum the order amount column.",
                confidence=None,
            )

        if "order" in q and "orders" in table_names:
            return QueryPlan(
                question=question,
                sql="SELECT * FROM orders ORDER BY created_at DESC",
                rationale="Return recent orders.",
                confidence=None,
            )

        for lowered_name, actual_name in table_names.items():
            if re.search(rf"\b{re.escape(lowered_name)}\b", q):
                escaped = actual_name.replace('"', '""')
                return QueryPlan(
                    question=question,
                    sql=f'SELECT * FROM "{escaped}"',
                    rationale=f"Question references table {actual_name}.",
                    confidence=None,
                )

        raise ValueError("The deterministic planner could not map the question to the schema.")
