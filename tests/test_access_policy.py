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


def test_cte_alias_does_not_require_database_table_allowlist_entry():
    policy = AccessPolicy(allowed_tables=frozenset({"customers"}))
    authorize_sql(
        "WITH selected AS (SELECT name FROM customers) SELECT name FROM selected",
        policy,
    )


def test_cte_cannot_hide_unauthorized_physical_table():
    policy = AccessPolicy(allowed_tables=frozenset({"customers"}))
    with pytest.raises(AccessPolicyError, match="unauthorized"):
        authorize_sql(
            "WITH selected AS (SELECT salary FROM payroll) SELECT salary FROM selected",
            policy,
        )


def test_schema_qualified_table_cannot_reuse_allowed_bare_name():
    policy = AccessPolicy(allowed_tables=frozenset({"customers"}))
    for sql in (
        "SELECT name FROM main.customers",
        "SELECT name FROM attached.customers",
    ):
        with pytest.raises(AccessPolicyError, match="Schema-qualified"):
            authorize_sql(sql, policy)


def test_cte_name_does_not_need_physical_table_authorization():
    policy = AccessPolicy(allowed_tables=frozenset({"customers"}))
    authorize_sql(
        "WITH derived AS (SELECT name FROM customers) SELECT name FROM derived",
        policy,
    )


def test_cte_does_not_exempt_physical_tables_in_other_scopes():
    policy = AccessPolicy(allowed_tables=frozenset({"customers"}))
    with pytest.raises(AccessPolicyError, match="unauthorized"):
        authorize_sql(
            "SELECT name FROM payroll WHERE EXISTS ("
            "WITH payroll AS (SELECT name FROM customers) "
            "SELECT 1 FROM payroll)",
            policy,
        )


def test_guard_applies_inside_cte_even_when_outer_query_is_filtered():
    policy = AccessPolicy(
        allowed_tables=frozenset({"customers"}),
        require_where_for_tables=frozenset({"customers"}),
    )
    with pytest.raises(AccessPolicyError, match="WHERE"):
        authorize_sql(
            "WITH visible AS (SELECT name FROM customers) "
            "SELECT name FROM visible WHERE name IS NOT NULL",
            policy,
        )


@pytest.mark.parametrize(
    "sql",
    [
        "SELECT name FROM customers WHERE TRUE",
        "SELECT name FROM customers WHERE (1 = 1)",
        "SELECT name FROM customers WHERE id = 7 OR TRUE",
        "SELECT name FROM customers WHERE (id = 7 OR (1 = 1))",
        "WITH c AS (SELECT name FROM customers WHERE TRUE) SELECT name FROM c",
    ],
)
def test_guard_rejects_obvious_true_conditions(sql):
    policy = AccessPolicy(
        allowed_tables=frozenset({"customers"}),
        require_where_for_tables=frozenset({"customers"}),
    )
    with pytest.raises(AccessPolicyError, match="trivial TRUE"):
        authorize_sql(sql, policy)


def test_guard_accepts_real_predicates_and_redundant_true_conjunction():
    policy = AccessPolicy(
        allowed_tables=frozenset({"customers"}),
        require_where_for_tables=frozenset({"customers"}),
    )
    authorize_sql("SELECT name FROM customers WHERE id = 7", policy)
    authorize_sql("SELECT name FROM customers WHERE 1 = 1 AND id = 7", policy)
