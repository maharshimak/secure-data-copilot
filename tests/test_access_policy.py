import pytest

from data_copilot.access import AccessPolicy, AccessPolicyError, authorize_sql


def test_access_policy_blocks_unauthorized_table_and_sensitive_column():
    policy = AccessPolicy(
        allowed_tables=frozenset({"orders", "customers"}),
        denied_columns=frozenset({"email"}),
    )
    authorize_sql("SELECT amount FROM orders", policy)

    with pytest.raises(AccessPolicyError, match="unauthorized"):
        authorize_sql("SELECT * FROM payroll", policy)

    with pytest.raises(AccessPolicyError, match="denied columns"):
        authorize_sql("SELECT email FROM customers", policy)


def test_guarded_table_requires_row_filter():
    policy = AccessPolicy(
        allowed_tables=frozenset({"customers"}),
        require_where_for_tables=frozenset({"customers"}),
    )
    with pytest.raises(AccessPolicyError, match="WHERE"):
        authorize_sql("SELECT name FROM customers", policy)
    authorize_sql("SELECT name FROM customers WHERE id = 1", policy)


@pytest.mark.parametrize(
    "sql",
    [
        "SELECT name FROM (SELECT name FROM customers) AS unfiltered WHERE name <> ''",
        "WITH exposed AS (SELECT name FROM customers) SELECT name FROM exposed WHERE name <> ''",
        "SELECT name FROM customers UNION ALL SELECT name FROM customers WHERE id = 1",
    ],
)
def test_outer_filters_cannot_authorize_unfiltered_guarded_scans(sql):
    policy = AccessPolicy(
        allowed_tables=frozenset({"customers", "exposed"}),
        require_where_for_tables=frozenset({"customers"}),
    )
    with pytest.raises(AccessPolicyError, match="WHERE"):
        authorize_sql(sql, policy)


def test_guarded_table_filter_on_own_select_is_accepted():
    policy = AccessPolicy(
        allowed_tables=frozenset({"customers"}),
        require_where_for_tables=frozenset({"customers"}),
    )
    authorize_sql(
        "SELECT name FROM (SELECT name FROM customers WHERE id = 1) AS filtered",
        policy,
    )
