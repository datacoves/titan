"""
Unit tests for snowcap/lifecycle.py

Tests SQL generation functions for create, update, drop, and transfer operations.
All tests use mocked URN, FQN, and Props objects - no Snowflake connection required.
"""

import pytest

from snowcap import resources as res
from snowcap.lifecycle import (
    fqn_to_sql,
    create_resource,
    create__default,
    create_account_parameter,
    create_aggregation_policy,
    create_database,
    create_database_role_grant,
    create_function,
    create_grant,
    create_masking_policy,
    create_procedure,
    create_row_access_policy,
    create_role_grant,
    create_scanner_package,
    create_schema,
    create_table,
    create_tag_reference,
    create_tag_masking_policy_reference,
    create_view,
    update_resource,
    update__default,
    update_account_parameter,
    update_event_table,
    update_mcp_server,
    update_procedure,
    update_role_grant,
    update_scanner_package,
    update_schema,
    update_table,
    update_tag_masking_policy_reference,
    update_task,
    update_iceberg_table,
    drop_resource,
    drop__default,
    drop_account_parameter,
    drop_database,
    drop_database_role_grant,
    drop_function,
    drop_grant,
    drop_procedure,
    drop_role_grant,
    drop_scanner_package,
    drop_tag_masking_policy_reference,
    transfer_resource,
    transfer__default,
)
from snowcap.enums import GrantType, ResourceType
from snowcap.identifiers import FQN, URN
from snowcap.resource_name import ResourceName
from snowcap.props import Props

# ============================================================================
# Test fixtures and helpers
# ============================================================================


class MockProps:
    """Mock Props object for testing."""

    def __init__(self, rendered_output=""):
        self._rendered = rendered_output

    def render(self, data):
        return self._rendered


def make_fqn(name, database=None, schema=None, arg_types=None):
    """Helper to create FQN objects."""
    return FQN(
        name=ResourceName(name),
        database=ResourceName(database) if database else None,
        schema=ResourceName(schema) if schema else None,
        arg_types=arg_types,
    )


def make_urn(resource_type, name, database=None, schema=None, account_locator="ABC123"):
    """Helper to create URN objects."""
    fqn = make_fqn(name, database, schema)
    return URN(resource_type=resource_type, fqn=fqn, account_locator=account_locator)


def make_urn_with_params(resource_type, name, database=None, schema=None, params=None, account_locator="ABC123"):
    """Helper to create URN objects with FQN params (e.g. for TagMaskingPolicyReference)."""
    fqn = FQN(
        name=ResourceName(name),
        database=ResourceName(database) if database else None,
        schema=ResourceName(schema) if schema else None,
        params=params or {},
    )
    return URN(resource_type=resource_type, fqn=fqn, account_locator=account_locator)


# ============================================================================
# Test fqn_to_sql
# ============================================================================


class TestFqnToSql:
    """Tests for fqn_to_sql function."""

    def test_simple_name(self):
        """Test FQN with just a name."""
        fqn = make_fqn("MY_TABLE")
        result = fqn_to_sql(fqn)
        assert result == "MY_TABLE"

    def test_database_and_name(self):
        """Test FQN with database and name."""
        fqn = make_fqn("MY_SCHEMA", database="MY_DB")
        result = fqn_to_sql(fqn)
        assert result == "MY_DB.MY_SCHEMA"

    def test_fully_qualified(self):
        """Test FQN with database, schema, and name."""
        fqn = make_fqn("MY_TABLE", database="MY_DB", schema="MY_SCHEMA")
        result = fqn_to_sql(fqn)
        assert result == "MY_DB.MY_SCHEMA.MY_TABLE"

    def test_quoted_name(self):
        """Test FQN with quoted identifier."""
        fqn = make_fqn('"my_table"')
        result = fqn_to_sql(fqn)
        assert result == '"my_table"'

    def test_special_characters(self):
        """Test FQN with special characters in name."""
        fqn = make_fqn('"table with spaces"', database="MY_DB", schema="MY_SCHEMA")
        result = fqn_to_sql(fqn)
        assert result == 'MY_DB.MY_SCHEMA."table with spaces"'


# ============================================================================
# Test create_resource dispatcher
# ============================================================================


class TestCreateResource:
    """Tests for create_resource dispatcher function."""

    def test_dispatches_to_default_for_unknown_resource(self):
        """Test that unknown resource types use create__default."""
        urn = make_urn(ResourceType.ALERT, "MY_ALERT", database="MY_DB", schema="MY_SCHEMA")
        data = {}
        props = MockProps("")
        result = create_resource(urn, data, props, if_not_exists=True)
        assert "CREATE ALERT IF NOT EXISTS" in result
        assert "MY_DB.MY_SCHEMA.MY_ALERT" in result

    def test_dispatches_to_specialized_function(self):
        """Test that known resource types dispatch to specialized functions."""
        urn = make_urn(ResourceType.DATABASE, "MY_DB")
        data = {}
        props = MockProps("")
        result = create_resource(urn, data, props, if_not_exists=True)
        assert "CREATE DATABASE IF NOT EXISTS" in result


# ============================================================================
# Test create__default
# ============================================================================


class TestCreateDefault:
    """Tests for create__default function."""

    def test_simple_create(self):
        """Test simple CREATE statement."""
        urn = make_urn(ResourceType.WAREHOUSE, "MY_WH")
        data = {}
        props = MockProps("SIZE = 'XSMALL'")
        result = create__default(urn, data, props)
        assert result == "CREATE WAREHOUSE MY_WH SIZE = 'XSMALL'"

    def test_create_if_not_exists(self):
        """Test CREATE IF NOT EXISTS."""
        urn = make_urn(ResourceType.WAREHOUSE, "MY_WH")
        data = {}
        props = MockProps("")
        result = create__default(urn, data, props, if_not_exists=True)
        assert result == "CREATE WAREHOUSE IF NOT EXISTS MY_WH"

    def test_fully_qualified_name(self):
        """Test CREATE with fully qualified name."""
        urn = make_urn(ResourceType.TABLE, "MY_TABLE", database="MY_DB", schema="MY_SCHEMA")
        data = {}
        props = MockProps("(ID INT)")
        result = create__default(urn, data, props)
        assert result == "CREATE TABLE MY_DB.MY_SCHEMA.MY_TABLE (ID INT)"


# ============================================================================
# Test specialized create functions
# ============================================================================


class TestCreateAccountParameter:
    """Tests for create_account_parameter function."""

    def test_string_value(self):
        """Test setting string parameter."""
        urn = make_urn(ResourceType.ACCOUNT_PARAMETER, "TIMEZONE")
        data = {"value": "America/New_York"}
        props = MockProps("")
        result = create_account_parameter(urn, data, props)
        assert result == "ALTER ACCOUNT SET TIMEZONE = 'America/New_York'"

    def test_numeric_value(self):
        """Test setting numeric parameter."""
        urn = make_urn(ResourceType.ACCOUNT_PARAMETER, "STATEMENT_TIMEOUT_IN_SECONDS")
        data = {"value": 3600}
        props = MockProps("")
        result = create_account_parameter(urn, data, props)
        assert result == "ALTER ACCOUNT SET STATEMENT_TIMEOUT_IN_SECONDS = 3600"

    def test_boolean_value(self):
        """Test setting boolean parameter."""
        urn = make_urn(ResourceType.ACCOUNT_PARAMETER, "ENABLE_UNLOAD_PHYSICAL_TYPE_OPTIMIZATION")
        data = {"value": True}
        props = MockProps("")
        result = create_account_parameter(urn, data, props)
        assert result == "ALTER ACCOUNT SET ENABLE_UNLOAD_PHYSICAL_TYPE_OPTIMIZATION = True"


class TestCreateAggregationPolicy:
    """Tests for create_aggregation_policy function."""

    def test_basic_create(self):
        """Test basic aggregation policy creation."""
        urn = make_urn(ResourceType.AGGREGATION_POLICY, "MY_POLICY", database="MY_DB", schema="MY_SCHEMA")
        data = {}
        props = MockProps("MIN_GROUP_SIZE = 5")
        result = create_aggregation_policy(urn, data, props)
        assert "CREATE AGGREGATION POLICY" in result
        assert "MY_DB.MY_SCHEMA.MY_POLICY" in result
        assert "AS () RETURNS AGGREGATION_CONSTRAINT" in result
        assert "MIN_GROUP_SIZE = 5" in result

    def test_if_not_exists(self):
        """Test with IF NOT EXISTS."""
        urn = make_urn(ResourceType.AGGREGATION_POLICY, "MY_POLICY", database="MY_DB", schema="MY_SCHEMA")
        data = {}
        props = MockProps("")
        result = create_aggregation_policy(urn, data, props, if_not_exists=True)
        assert "IF NOT EXISTS" in result


class TestCreateDatabase:
    """Tests for create_database function."""

    def test_basic_create(self):
        """Test basic database creation."""
        urn = make_urn(ResourceType.DATABASE, "MY_DB")
        data = {}
        props = MockProps("DATA_RETENTION_TIME_IN_DAYS = 7")
        result = create_database(urn, data, props)
        assert "CREATE DATABASE" in result
        assert "DATA_RETENTION_TIME_IN_DAYS = 7" in result

    def test_transient_database(self):
        """Test transient database creation."""
        urn = make_urn(ResourceType.DATABASE, "MY_DB")
        data = {"transient": True}
        props = MockProps("")
        result = create_database(urn, data, props)
        assert "CREATE TRANSIENT DATABASE" in result

    def test_if_not_exists(self):
        """Test with IF NOT EXISTS."""
        urn = make_urn(ResourceType.DATABASE, "MY_DB")
        data = {}
        props = MockProps("")
        result = create_database(urn, data, props, if_not_exists=True)
        assert "IF NOT EXISTS" in result


class TestCreateDatabaseRoleGrant:
    """Tests for create_database_role_grant function."""

    def test_grant_to_role(self):
        """Test granting database role to role."""
        urn = make_urn(ResourceType.DATABASE_ROLE_GRANT, "GRANT")
        data = {
            "database_role": "MY_DB.MY_DB_ROLE",
            "to_role": "MY_ROLE",
            "to_database_role": None,
        }
        props = MockProps("")
        result = create_database_role_grant(urn, data, props)
        assert "GRANT DATABASE ROLE MY_DB.MY_DB_ROLE TO ROLE MY_ROLE" in result

    def test_grant_to_database_role(self):
        """Test granting database role to another database role."""
        urn = make_urn(ResourceType.DATABASE_ROLE_GRANT, "GRANT")
        data = {
            "database_role": "MY_DB.SOURCE_ROLE",
            "to_role": None,
            "to_database_role": "MY_DB.TARGET_ROLE",
        }
        props = MockProps("")
        result = create_database_role_grant(urn, data, props)
        assert "GRANT DATABASE ROLE MY_DB.SOURCE_ROLE TO DATABASE ROLE MY_DB.TARGET_ROLE" in result


class TestCreateFunction:
    """Tests for create_function function."""

    def test_basic_function(self):
        """Test basic function creation."""
        urn = make_urn(ResourceType.FUNCTION, "MY_FUNC", database="MY_DB", schema="MY_SCHEMA")
        data = {"name": "MY_FUNC(VARCHAR)"}
        props = MockProps("RETURNS INT LANGUAGE SQL AS 'SELECT 1'")
        result = create_function(urn, data, props)
        assert "CREATE FUNCTION" in result
        assert "MY_DB.MY_SCHEMA.MY_FUNC(VARCHAR)" in result
        assert "RETURNS INT" in result

    def test_if_not_exists(self):
        """Test with IF NOT EXISTS."""
        urn = make_urn(ResourceType.FUNCTION, "MY_FUNC", database="MY_DB", schema="MY_SCHEMA")
        data = {"name": "MY_FUNC()"}
        props = MockProps("RETURNS INT LANGUAGE SQL AS 'SELECT 1'")
        result = create_function(urn, data, props, if_not_exists=True)
        assert "IF NOT EXISTS" in result


class TestCreateGrant:
    """Tests for create_grant function."""

    def test_grant_on_database(self):
        """Test grant on database."""
        urn = make_urn(ResourceType.GRANT, "GRANT")
        data = {
            "priv": "USAGE",
            "on_type": "DATABASE",
            "on": "MY_DB",
            "to_type": "ROLE",
            "to": "MY_ROLE",
            "grant_type": GrantType.OBJECT,
            "grant_option": False,
        }
        props = MockProps("")
        result = create_grant(urn, data, props, if_not_exists=False)
        assert result == "GRANT USAGE ON DATABASE MY_DB TO ROLE MY_ROLE"

    def test_grant_on_account(self):
        """Test grant on account (global privilege)."""
        urn = make_urn(ResourceType.GRANT, "GRANT")
        data = {
            "priv": "CREATE DATABASE",
            "on_type": "ACCOUNT",
            "on": "",
            "to_type": "ROLE",
            "to": "MY_ROLE",
            "grant_type": GrantType.OBJECT,
            "grant_option": False,
        }
        props = MockProps("")
        result = create_grant(urn, data, props, if_not_exists=False)
        # on_type becomes empty for ACCOUNT grants
        assert "GRANT CREATE DATABASE" in result
        assert "TO ROLE MY_ROLE" in result

    def test_grant_with_grant_option(self):
        """Test grant with grant option."""
        urn = make_urn(ResourceType.GRANT, "GRANT")
        data = {
            "priv": "SELECT",
            "on_type": "TABLE",
            "on": "MY_DB.MY_SCHEMA.MY_TABLE",
            "to_type": "ROLE",
            "to": "MY_ROLE",
            "grant_type": GrantType.OBJECT,
            "grant_option": True,
        }
        props = MockProps("")
        result = create_grant(urn, data, props, if_not_exists=False)
        assert "WITH GRANT OPTION" in result

    def test_future_grant(self):
        """Test future grant."""
        urn = make_urn(ResourceType.GRANT, "GRANT")
        data = {
            "priv": "SELECT",
            "on_type": "SCHEMA",
            "on": "MY_DB.MY_SCHEMA",
            "items_type": "TABLE",
            "to_type": "ROLE",
            "to": "MY_ROLE",
            "grant_type": GrantType.FUTURE,
            "grant_option": False,
        }
        props = MockProps("")
        result = create_grant(urn, data, props, if_not_exists=False)
        assert "GRANT SELECT ON FUTURE TABLES IN SCHEMA MY_DB.MY_SCHEMA TO ROLE MY_ROLE" in result

    def test_grant_all(self):
        """Test GRANT ON ALL."""
        urn = make_urn(ResourceType.GRANT, "GRANT")
        data = {
            "priv": "SELECT",
            "on_type": "SCHEMA",
            "on": "MY_DB.MY_SCHEMA",
            "items_type": "table",
            "to_type": "ROLE",
            "to": "MY_ROLE",
            "grant_type": GrantType.ALL,
            "grant_option": False,
        }
        props = MockProps("")
        result = create_grant(urn, data, props, if_not_exists=False)
        assert "ON ALL TABLES IN" in result

    def test_grant_inherited(self):
        """One container-level grant covering current and future objects."""
        urn = make_urn(ResourceType.GRANT, "GRANT")
        data = {
            "priv": "SELECT",
            "on_type": "SCHEMA",
            "on": "MY_DB.MY_SCHEMA",
            "items_type": "TABLE",
            "to_type": "ROLE",
            "to": "MY_ROLE",
            "grant_type": GrantType.INHERITED,
            "grant_option": False,
        }
        props = MockProps("")

        assert create_grant(urn, data, props, if_not_exists=False) == (
            "GRANT INHERITED SELECT ON ALL TABLES IN SCHEMA MY_DB.MY_SCHEMA TO ROLE MY_ROLE"
        )
        assert drop_grant(urn, data) == (
            "REVOKE INHERITED SELECT ON ALL TABLES IN SCHEMA MY_DB.MY_SCHEMA FROM ROLE MY_ROLE"
        )

    def test_grant_inherited_in_account(self):
        """The account container has no name, so it renders as a bare IN ACCOUNT."""
        urn = make_urn(ResourceType.GRANT, "GRANT")
        data = {
            "priv": "SELECT",
            "on_type": ResourceType.ACCOUNT,
            "on": "ACCOUNT",
            "items_type": "TABLE",
            "to_type": "ROLE",
            "to": "MY_ROLE",
            "grant_type": GrantType.INHERITED,
            "grant_option": False,
        }
        props = MockProps("")

        assert create_grant(urn, data, props, if_not_exists=False) == (
            "GRANT INHERITED SELECT ON ALL TABLES IN ACCOUNT TO ROLE MY_ROLE"
        )
        assert drop_grant(urn, data) == "REVOKE INHERITED SELECT ON ALL TABLES IN ACCOUNT FROM ROLE MY_ROLE"

    def test_grant_on_integration(self):
        """Test grant on integration (type normalization)."""
        urn = make_urn(ResourceType.GRANT, "GRANT")
        data = {
            "priv": "USAGE",
            "on_type": "STORAGE INTEGRATION",
            "on": "MY_INTEGRATION",
            "to_type": "ROLE",
            "to": "MY_ROLE",
            "grant_type": GrantType.OBJECT,
            "grant_option": False,
        }
        props = MockProps("")
        result = create_grant(urn, data, props, if_not_exists=False)
        assert "ON INTEGRATION MY_INTEGRATION" in result


class TestCreateMaskingPolicy:
    """Tests for create_masking_policy function."""

    def test_basic_create(self):
        """Test basic masking policy creation."""
        urn = make_urn(ResourceType.MASKING_POLICY, "MY_POLICY", database="MY_DB", schema="MY_SCHEMA")
        data = {}
        props = MockProps("(VAL VARCHAR) RETURNS VARCHAR -> VAL")
        result = create_masking_policy(urn, data, props)
        assert "CREATE MASKING POLICY" in result
        assert "AS" in result


class TestCreateRowAccessPolicy:
    """Tests for create_row_access_policy function."""

    def test_basic_create(self):
        """Test basic row access policy creation."""
        urn = make_urn(ResourceType.ROW_ACCESS_POLICY, "RAP_COUNTRY", database="GOVERNANCE", schema="POLICIES")
        data = {}
        props = MockProps("(COUNTRY_VAL VARCHAR) RETURNS BOOLEAN -> IS_ROLE_IN_SESSION('ADMIN')")
        result = create_row_access_policy(urn, data, props)
        assert "CREATE ROW ACCESS POLICY" in result
        assert "GOVERNANCE.POLICIES.RAP_COUNTRY" in result
        assert "AS" in result

    def test_with_if_not_exists(self):
        """Test row access policy creation with IF NOT EXISTS."""
        urn = make_urn(ResourceType.ROW_ACCESS_POLICY, "RAP_COUNTRY", database="GOVERNANCE", schema="POLICIES")
        data = {}
        props = MockProps("(COUNTRY_VAL VARCHAR) RETURNS BOOLEAN -> TRUE")
        result = create_row_access_policy(urn, data, props, if_not_exists=True)
        assert "IF NOT EXISTS" in result
        assert "CREATE ROW ACCESS POLICY" in result


class TestCreateProcedure:
    """Tests for create_procedure function."""

    def test_basic_create(self):
        """Test basic procedure creation."""
        urn = make_urn(ResourceType.PROCEDURE, "MY_PROC", database="MY_DB", schema="MY_SCHEMA")
        data = {}
        props = MockProps("() RETURNS INT LANGUAGE SQL AS $$ SELECT 1 $$")
        result = create_procedure(urn, data, props)
        assert "CREATE PROCEDURE MY_DB.MY_SCHEMA.MY_PROC" in result

    def test_if_not_exists_raises(self):
        """Test that IF NOT EXISTS raises exception for procedures."""
        urn = make_urn(ResourceType.PROCEDURE, "MY_PROC", database="MY_DB", schema="MY_SCHEMA")
        data = {}
        props = MockProps("")
        with pytest.raises(Exception) as exc_info:
            create_procedure(urn, data, props, if_not_exists=True)
        assert "IF NOT EXISTS not supported" in str(exc_info.value)


class TestCreateRoleGrant:
    """Tests for create_role_grant function."""

    def test_grant_to_role(self):
        """Test granting role to role."""
        urn = make_urn(ResourceType.ROLE_GRANT, "GRANT")
        data = {
            "role": "SOURCE_ROLE",
            "to_role": "TARGET_ROLE",
            "to_user": None,
        }
        props = MockProps("")
        result = create_role_grant(urn, data, props)
        assert result == "GRANT ROLE SOURCE_ROLE TO ROLE TARGET_ROLE"

    def test_grant_to_user(self):
        """Test granting role to user."""
        urn = make_urn(ResourceType.ROLE_GRANT, "GRANT")
        data = {
            "role": "MY_ROLE",
            "to_role": None,
            "to_user": "MY_USER",
        }
        props = MockProps("")
        result = create_role_grant(urn, data, props)
        assert result == "GRANT ROLE MY_ROLE TO USER MY_USER"


class TestCreateScannerPackage:
    """Tests for create_scanner_package function."""

    def test_basic_create(self):
        """Test scanner package creation."""
        urn = make_urn(ResourceType.SCANNER_PACKAGE, "CIS_BENCHMARKS")
        data = {}
        props = MockProps("")
        result = create_scanner_package(urn, data, props)
        assert "CALL SNOWFLAKE.TRUST_CENTER.SET_CONFIGURATION" in result
        assert "'ENABLED'" in result
        assert "'TRUE'" in result
        assert "'CIS_BENCHMARKS'" in result


class TestCreateSchema:
    """Tests for create_schema function."""

    def test_basic_create(self):
        """Test basic schema creation."""
        urn = make_urn(ResourceType.SCHEMA, "MY_SCHEMA", database="MY_DB")
        data = {}
        props = MockProps("DATA_RETENTION_TIME_IN_DAYS = 7")
        result = create_schema(urn, data, props)
        assert "CREATE SCHEMA" in result

    def test_transient_schema(self):
        """Test transient schema creation."""
        urn = make_urn(ResourceType.SCHEMA, "MY_SCHEMA", database="MY_DB")
        data = {"transient": True}
        props = MockProps("")
        result = create_schema(urn, data, props)
        assert "CREATE TRANSIENT SCHEMA" in result


class TestCreateTable:
    """Tests for create_table function."""

    def test_basic_create(self):
        """Test basic table creation."""
        urn = make_urn(ResourceType.TABLE, "MY_TABLE", database="MY_DB", schema="MY_SCHEMA")
        data = {}
        props = MockProps("(ID INT, NAME VARCHAR)")
        result = create_table(urn, data, props)
        assert "CREATE TABLE" in result

    def test_transient_table(self):
        """Test transient table creation."""
        urn = make_urn(ResourceType.TABLE, "MY_TABLE", database="MY_DB", schema="MY_SCHEMA")
        data = {"transient": True}
        props = MockProps("(ID INT)")
        result = create_table(urn, data, props)
        assert "CREATE TRANSIENT TABLE" in result


class TestCreateTagReference:
    """Tests for create_tag_reference function."""

    def test_basic_create(self):
        """Test basic tag reference creation."""
        urn = make_urn(ResourceType.TAG_REFERENCE, "REF")
        data = {
            "object_domain": "TABLE",
            "object_name": "MY_DB.MY_SCHEMA.MY_TABLE",
            "tags": {"env": "prod", "team": "data"},
        }
        props = MockProps("")
        result = create_tag_reference(urn, data, props)
        assert "ALTER TABLE MY_DB.MY_SCHEMA.MY_TABLE SET TAG" in result
        assert "env='prod'" in result
        assert "team='data'" in result


class TestCreateView:
    """Tests for create_view function."""

    def test_basic_create(self):
        """Test basic view creation."""
        urn = make_urn(ResourceType.VIEW, "MY_VIEW", database="MY_DB", schema="MY_SCHEMA")
        data = {}
        props = MockProps("AS SELECT 1")
        result = create_view(urn, data, props)
        assert "CREATE VIEW" in result

    def test_secure_view(self):
        """Test secure view creation."""
        urn = make_urn(ResourceType.VIEW, "MY_VIEW", database="MY_DB", schema="MY_SCHEMA")
        data = {"secure": True}
        props = MockProps("AS SELECT 1")
        result = create_view(urn, data, props)
        assert "CREATE SECURE VIEW" in result

    def test_volatile_view(self):
        """Test volatile view creation."""
        urn = make_urn(ResourceType.VIEW, "MY_VIEW", database="MY_DB", schema="MY_SCHEMA")
        data = {"volatile": True}
        props = MockProps("AS SELECT 1")
        result = create_view(urn, data, props)
        assert "CREATE VOLATILE VIEW" in result

    def test_recursive_view(self):
        """Test recursive view creation."""
        urn = make_urn(ResourceType.VIEW, "MY_VIEW", database="MY_DB", schema="MY_SCHEMA")
        data = {"recursive": True}
        props = MockProps("AS SELECT 1")
        result = create_view(urn, data, props)
        assert "CREATE RECURSIVE VIEW" in result


# ============================================================================
# Test update_resource dispatcher
# ============================================================================


class TestUpdateResource:
    """Tests for update_resource dispatcher function."""

    def test_dispatches_to_default(self):
        """Test that unknown resource types use update__default."""
        urn = make_urn(ResourceType.WAREHOUSE, "MY_WH")
        data = {"size": "LARGE"}
        props = MockProps("SIZE = 'LARGE'")
        result = update_resource(urn, data, props)
        assert "ALTER WAREHOUSE" in result
        assert "SET SIZE = 'LARGE'" in result


# ============================================================================
# Test update__default
# ============================================================================


class TestUpdateDefault:
    """Tests for update__default function."""

    def test_set_property(self):
        """Test setting a property."""
        urn = make_urn(ResourceType.WAREHOUSE, "MY_WH")
        data = {"size": "LARGE"}
        props = MockProps("SIZE = 'LARGE'")
        result = update__default(urn, data, props)
        assert result == "ALTER WAREHOUSE MY_WH SET SIZE = 'LARGE'"

    def test_unset_property(self):
        """Test unsetting a property."""
        urn = make_urn(ResourceType.WAREHOUSE, "MY_WH")
        data = {"comment": None}
        props = MockProps("")
        result = update__default(urn, data, props)
        assert result == "ALTER WAREHOUSE MY_WH UNSET comment"

    def test_rename(self):
        """Test renaming a resource."""
        urn = make_urn(ResourceType.WAREHOUSE, "MY_WH")
        data = {"name": "NEW_WH"}
        props = MockProps("")
        result = update__default(urn, data, props)
        assert result == "ALTER WAREHOUSE MY_WH RENAME TO NEW_WH"

    def test_owner_raises_not_implemented(self):
        """Test that changing owner raises NotImplementedError."""
        urn = make_urn(ResourceType.WAREHOUSE, "MY_WH")
        data = {"owner": "NEW_OWNER"}
        props = MockProps("")
        with pytest.raises(NotImplementedError):
            update__default(urn, data, props)

    def test_set_multiple_properties_in_one_statement(self):
        """Regression: multi-field SET deltas must update all fields, not just one.

        Previously update__default called data.popitem() and silently dropped
        every field except the one popitem returned. This caused security-
        sensitive rotations (e.g. rsa_public_key + comment on a user) to land
        the comment but leave the old key in place, with the apply summary
        still reporting "1 updated" and no error/warning.
        """
        urn = make_urn(ResourceType.USER, "MY_USER")
        data = {"rsa_public_key": "MIIBNEW...", "comment": "rotated 2026-05-31"}
        props = MockProps("RSA_PUBLIC_KEY = $$MIIBNEW...$$ COMMENT = $$rotated 2026-05-31$$")
        result = update__default(urn, data, props)
        assert result.startswith("ALTER USER MY_USER SET ")
        assert "RSA_PUBLIC_KEY = $$MIIBNEW...$$" in result
        assert "COMMENT = $$rotated 2026-05-31$$" in result
        # Must be a single ALTER statement (no semicolons → no multi-statement
        # risk with snowflake-connector-python's default MULTI_STATEMENT_COUNT=1).
        assert result.count("ALTER ") == 1
        assert ";" not in result

    def test_unset_multiple_properties_in_one_statement(self):
        """Multi-field UNSET deltas combine into one ALTER ... UNSET col1, col2."""
        urn = make_urn(ResourceType.WAREHOUSE, "MY_WH")
        data = {"comment": None, "tag": None}
        props = MockProps("")
        result = update__default(urn, data, props)
        assert result == "ALTER WAREHOUSE MY_WH UNSET comment, tag"

    def test_mixed_set_and_unset_raises(self):
        """SET and UNSET cannot share an ALTER statement in Snowflake."""
        urn = make_urn(ResourceType.WAREHOUSE, "MY_WH")
        data = {"size": "LARGE", "comment": None}
        props = MockProps("SIZE = 'LARGE'")
        with pytest.raises(NotImplementedError, match="mix SET and UNSET"):
            update__default(urn, data, props)

    def test_rename_combined_with_other_fields_raises(self):
        """RENAME TO has its own ALTER syntax and can't combine with SET."""
        urn = make_urn(ResourceType.WAREHOUSE, "MY_WH")
        data = {"name": "NEW_WH", "comment": "renamed"}
        props = MockProps("")
        with pytest.raises(NotImplementedError, match="'name'"):
            update__default(urn, data, props)

    def test_multiple_warehouse_properties_combined_in_one_statement(self):
        """Gen2 warehouse fields work with combined ALTER ... SET updates."""
        urn = make_urn(ResourceType.WAREHOUSE, "MY_WH")
        data = {
            "resource_constraint": "STANDARD_GEN_2",
            "generation": "2",
        }
        result = update__default(urn, data, res.Warehouse.props)
        assert result == "ALTER WAREHOUSE MY_WH SET GENERATION = '2' RESOURCE_CONSTRAINT = STANDARD_GEN_2"


# ============================================================================
# Test specialized update functions
# ============================================================================


class TestUpdateAccountParameter:
    """Tests for update_account_parameter function."""

    def test_update_delegates_to_create(self):
        """Test that update just calls create for account parameters."""
        urn = make_urn(ResourceType.ACCOUNT_PARAMETER, "TIMEZONE")
        data = {"value": "UTC"}
        props = MockProps("")
        result = update_account_parameter(urn, data, props)
        assert "ALTER ACCOUNT SET TIMEZONE = 'UTC'" in result


class TestUpdateEventTable:
    """Tests for update_event_table function."""

    def test_update_uses_table_type(self):
        """Test that event table updates use TABLE resource type."""
        urn = make_urn(ResourceType.EVENT_TABLE, "MY_EVENT_TABLE", database="MY_DB", schema="MY_SCHEMA")
        data = {"comment": "New comment"}
        props = MockProps("COMMENT = 'New comment'")
        result = update_event_table(urn, data, props)
        assert "ALTER TABLE" in result


class TestUpdateProcedure:
    """Tests for update_procedure function."""

    def test_update_execute_as(self):
        """Test updating execute_as property."""
        urn = make_urn(ResourceType.PROCEDURE, "MY_PROC", database="MY_DB", schema="MY_SCHEMA")
        data = {"execute_as": "CALLER"}
        props = MockProps("")
        result = update_procedure(urn, data, props)
        assert "ALTER PROCEDURE" in result
        assert "EXECUTE AS CALLER" in result

    def test_update_other_property(self):
        """Test updating other properties falls back to default."""
        urn = make_urn(ResourceType.PROCEDURE, "MY_PROC", database="MY_DB", schema="MY_SCHEMA")
        data = {"comment": "New comment"}
        props = MockProps("COMMENT = 'New comment'")
        result = update_procedure(urn, data, props)
        assert "ALTER PROCEDURE" in result
        assert "SET COMMENT" in result


class TestUpdateRoleGrant:
    """Tests for update_role_grant function."""

    def test_raises_not_implemented(self):
        """Test that role grant updates raise NotImplementedError."""
        urn = make_urn(ResourceType.ROLE_GRANT, "GRANT")
        data = {}
        props = MockProps("")
        with pytest.raises(NotImplementedError):
            update_role_grant(urn, data, props)


class TestUpdateScannerPackage:
    """Tests for update_scanner_package function."""

    def test_update_schedule(self):
        """Test updating schedule."""
        urn = make_urn(ResourceType.SCANNER_PACKAGE, "CIS_BENCHMARKS")
        data = {"schedule": "0 0 * * *"}
        props = MockProps("")
        result = update_scanner_package(urn, data, props)
        assert "CALL SNOWFLAKE.TRUST_CENTER.SET_CONFIGURATION" in result
        assert "'schedule'" in result
        assert "USING CRON" in result

    def test_update_other_property(self):
        """Test updating other property."""
        urn = make_urn(ResourceType.SCANNER_PACKAGE, "CIS_BENCHMARKS")
        data = {"enabled": "TRUE"}
        props = MockProps("")
        result = update_scanner_package(urn, data, props)
        assert "'enabled'" in result
        assert "'TRUE'" in result


class TestUpdateSchema:
    """Tests for update_schema function."""

    def test_unset_property(self):
        """Test unsetting a schema property."""
        urn = make_urn(ResourceType.SCHEMA, "MY_SCHEMA", database="MY_DB")
        data = {"comment": None}
        props = MockProps("")
        result = update_schema(urn, data, props)
        assert result == "ALTER SCHEMA MY_DB.MY_SCHEMA UNSET comment"

    def test_rename(self):
        """Test renaming a schema."""
        urn = make_urn(ResourceType.SCHEMA, "MY_SCHEMA", database="MY_DB")
        data = {"name": "NEW_SCHEMA"}
        props = MockProps("")
        result = update_schema(urn, data, props)
        assert "RENAME TO NEW_SCHEMA" in result

    def test_owner_raises(self):
        """Test that changing owner raises NotImplementedError."""
        urn = make_urn(ResourceType.SCHEMA, "MY_SCHEMA", database="MY_DB")
        data = {"owner": "NEW_OWNER"}
        props = MockProps("")
        with pytest.raises(NotImplementedError):
            update_schema(urn, data, props)

    def test_transient_raises(self):
        """Test that changing transient raises Exception."""
        urn = make_urn(ResourceType.SCHEMA, "MY_SCHEMA", database="MY_DB")
        data = {"transient": True}
        props = MockProps("")
        with pytest.raises(Exception) as exc_info:
            update_schema(urn, data, props)
        assert "Cannot change transient property" in str(exc_info.value)

    def test_enable_managed_access(self):
        """Test enabling managed access."""
        urn = make_urn(ResourceType.SCHEMA, "MY_SCHEMA", database="MY_DB")
        data = {"managed_access": True}
        props = MockProps("")
        result = update_schema(urn, data, props)
        assert "ENABLE MANAGED ACCESS" in result

    def test_disable_managed_access(self):
        """Test disabling managed access."""
        urn = make_urn(ResourceType.SCHEMA, "MY_SCHEMA", database="MY_DB")
        data = {"managed_access": False}
        props = MockProps("")
        result = update_schema(urn, data, props)
        assert "DISABLE MANAGED ACCESS" in result

    def test_set_other_property(self):
        """Test setting other property."""
        urn = make_urn(ResourceType.SCHEMA, "MY_SCHEMA", database="MY_DB")
        data = {"data_retention_time_in_days": 7}
        props = MockProps("")
        result = update_schema(urn, data, props)
        assert "SET data_retention_time_in_days = 7" in result


class TestUpdateTable:
    """Tests for update_table function."""

    def test_columns_raises_not_implemented(self):
        """Test that updating columns raises NotImplementedError."""
        urn = make_urn(ResourceType.TABLE, "MY_TABLE", database="MY_DB", schema="MY_SCHEMA")
        data = {"columns": [{"name": "ID", "type": "INT"}]}
        props = MockProps("")
        with pytest.raises(NotImplementedError):
            update_table(urn, data, props)

    def test_other_property_uses_default(self):
        """Test that other properties use default update."""
        urn = make_urn(ResourceType.TABLE, "MY_TABLE", database="MY_DB", schema="MY_SCHEMA")
        data = {"comment": "New comment"}
        props = MockProps("COMMENT = 'New comment'")
        result = update_table(urn, data, props)
        assert "ALTER TABLE" in result
        assert "SET COMMENT" in result


class TestUpdateTask:
    """Tests for update_task function."""

    def test_update_as(self):
        """Test updating AS clause."""
        urn = make_urn(ResourceType.TASK, "MY_TASK", database="MY_DB", schema="MY_SCHEMA")
        data = {"as_": "SELECT 1"}
        props = MockProps("")
        result = update_task(urn, data, props)
        assert "ALTER TASK" in result
        assert "MODIFY AS SELECT 1" in result

    def test_update_when(self):
        """Test updating WHEN clause."""
        urn = make_urn(ResourceType.TASK, "MY_TASK", database="MY_DB", schema="MY_SCHEMA")
        data = {"when": "SYSTEM$STREAM_HAS_DATA('MY_STREAM')"}
        props = MockProps("")
        result = update_task(urn, data, props)
        assert "MODIFY WHEN" in result

    def test_remove_when(self):
        """Test removing WHEN clause."""
        urn = make_urn(ResourceType.TASK, "MY_TASK", database="MY_DB", schema="MY_SCHEMA")
        data = {"when": None}
        props = MockProps("")
        result = update_task(urn, data, props)
        assert "REMOVE WHEN" in result

    def test_resume_task(self):
        """Test resuming a task."""
        urn = make_urn(ResourceType.TASK, "MY_TASK", database="MY_DB", schema="MY_SCHEMA")
        data = {"state": "STARTED"}
        props = MockProps("")
        result = update_task(urn, data, props)
        assert "RESUME" in result

    def test_suspend_task(self):
        """Test suspending a task."""
        urn = make_urn(ResourceType.TASK, "MY_TASK", database="MY_DB", schema="MY_SCHEMA")
        data = {"state": "SUSPENDED"}
        props = MockProps("")
        result = update_task(urn, data, props)
        assert "SUSPEND" in result

    def test_non_special_delta_delegates_to_default(self):
        """A plain SET-able field routes to update__default, not the bespoke ALTER branches."""
        urn = make_urn(ResourceType.TASK, "MY_TASK", database="MY_DB", schema="MY_SCHEMA")
        result = update_task(urn, {"comment": "hi"}, res.Task.props)
        assert result == "ALTER TASK MY_DB.MY_SCHEMA.MY_TASK SET COMMENT = $$hi$$"

    def test_state_combined_with_other_fields_raises_rather_than_dropping(self):
        """RESUME/SUSPEND can't be combined with a SET; the delta must not be silently truncated."""
        urn = make_urn(ResourceType.TASK, "MY_TASK", database="MY_DB", schema="MY_SCHEMA")
        with pytest.raises(NotImplementedError, match="cannot combine"):
            update_task(urn, {"state": "STARTED", "comment": "hi"}, res.Task.props)


class TestUpdateIcebergTable:
    """Tests for update_iceberg_table function."""

    def test_columns_raises_not_implemented(self):
        """Test that updating columns raises NotImplementedError."""
        urn = make_urn(ResourceType.ICEBERG_TABLE, "MY_TABLE", database="MY_DB", schema="MY_SCHEMA")
        data = {"columns": []}
        props = MockProps("")
        with pytest.raises(NotImplementedError):
            update_iceberg_table(urn, data, props)


# ============================================================================
# Test drop_resource dispatcher
# ============================================================================


class TestDropResource:
    """Tests for drop_resource dispatcher function."""

    def test_dispatches_to_default(self):
        """Test that unknown resource types use drop__default."""
        urn = make_urn(ResourceType.WAREHOUSE, "MY_WH")
        data = {}
        result = drop_resource(urn, data, if_exists=True)
        assert "DROP WAREHOUSE IF EXISTS MY_WH" in result


# ============================================================================
# Test drop__default
# ============================================================================


class TestDropDefault:
    """Tests for drop__default function."""

    def test_simple_drop(self):
        """Test simple DROP statement."""
        urn = make_urn(ResourceType.WAREHOUSE, "MY_WH")
        data = {}
        result = drop__default(urn, data, if_exists=False)
        assert result == "DROP WAREHOUSE MY_WH"

    def test_drop_if_exists(self):
        """Test DROP IF EXISTS."""
        urn = make_urn(ResourceType.WAREHOUSE, "MY_WH")
        data = {}
        result = drop__default(urn, data, if_exists=True)
        assert result == "DROP WAREHOUSE IF EXISTS MY_WH"


# ============================================================================
# Test specialized drop functions
# ============================================================================


class TestDropAccountParameter:
    """Tests for drop_account_parameter function."""

    def test_basic_drop(self):
        """Test dropping account parameter."""
        urn = make_urn(ResourceType.ACCOUNT_PARAMETER, "TIMEZONE")
        data = {}
        result = drop_account_parameter(urn, data, if_exists=False)
        assert result == "ALTER ACCOUNT UNSET TIMEZONE"


class TestDropDatabase:
    """Tests for drop_database function."""

    def test_basic_drop(self):
        """Test dropping database with RESTRICT."""
        urn = make_urn(ResourceType.DATABASE, "MY_DB")
        data = {}
        result = drop_database(urn, data, if_exists=False)
        assert "DROP DATABASE" in result
        assert "RESTRICT" in result

    def test_drop_if_exists(self):
        """Test DROP IF EXISTS."""
        urn = make_urn(ResourceType.DATABASE, "MY_DB")
        data = {}
        result = drop_database(urn, data, if_exists=True)
        assert "IF EXISTS" in result


class TestDropDatabaseRoleGrant:
    """Tests for drop_database_role_grant function."""

    def test_revoke_from_role(self):
        """Test revoking database role from role."""
        urn = make_urn(ResourceType.DATABASE_ROLE_GRANT, "GRANT")
        data = {
            "database_role": "MY_DB_ROLE",
            "to_role": "TARGET_ROLE",
            "to_database_role": None,
        }
        result = drop_database_role_grant(urn, data)
        assert "REVOKE DATABASE ROLE" in result
        assert "FROM ROLE" in result

    def test_revoke_from_database_role(self):
        """Test revoking database role from database role."""
        urn = make_urn(ResourceType.DATABASE_ROLE_GRANT, "GRANT")
        data = {
            "database_role": "SOURCE_ROLE",
            "to_role": None,
            "to_database_role": "TARGET_DB_ROLE",
        }
        result = drop_database_role_grant(urn, data)
        assert "FROM DATABASE ROLE" in result


class TestDropFunction:
    """Tests for drop_function function."""

    def test_basic_drop(self):
        """Test dropping function."""
        urn = make_urn(ResourceType.FUNCTION, "MY_FUNC", database="MY_DB", schema="MY_SCHEMA")
        urn.fqn = make_fqn("MY_FUNC", database="MY_DB", schema="MY_SCHEMA", arg_types=["VARCHAR"])
        data = {}
        result = drop_function(urn, data, if_exists=True)
        assert "DROP FUNCTION IF EXISTS" in result


class TestDropGrant:
    """Tests for drop_grant function."""

    def test_revoke_basic(self):
        """Test basic revoke."""
        urn = make_urn(ResourceType.GRANT, "GRANT")
        data = {
            "priv": "USAGE",
            "on_type": "DATABASE",
            "on": "MY_DB",
            "to": "MY_ROLE",
            "to_type": "ROLE",
            "grant_type": GrantType.OBJECT,
        }
        result = drop_grant(urn, data)
        assert "REVOKE USAGE ON DATABASE MY_DB FROM ROLE MY_ROLE" in result

    def test_revoke_ownership_raises(self):
        """Test that revoking OWNERSHIP raises NotImplementedError."""
        urn = make_urn(ResourceType.GRANT, "GRANT")
        data = {
            "priv": "OWNERSHIP",
            "on_type": "DATABASE",
            "on": "MY_DB",
            "to": "MY_ROLE",
            "grant_type": GrantType.OBJECT,
        }
        with pytest.raises(NotImplementedError):
            drop_grant(urn, data)

    def test_revoke_future_grant(self):
        """Test revoking future grant."""
        urn = make_urn(ResourceType.GRANT, "GRANT")
        data = {
            "priv": "SELECT",
            "on_type": "SCHEMA",
            "on": "MY_DB.MY_SCHEMA",
            "items_type": "TABLE",
            "to": "MY_ROLE",
            "to_type": "ROLE",
            "grant_type": GrantType.FUTURE,
        }
        result = drop_grant(urn, data)
        assert "REVOKE SELECT ON FUTURE TABLES IN SCHEMA MY_DB.MY_SCHEMA FROM ROLE MY_ROLE" in result

    def test_revoke_all_grant(self):
        """Test revoking GRANT ON ALL."""
        urn = make_urn(ResourceType.GRANT, "GRANT")
        data = {
            "priv": "SELECT",
            "on_type": "SCHEMA",
            "on": "MY_DB.MY_SCHEMA",
            "items_type": "TABLE",
            "to": "MY_ROLE",
            "to_type": "ROLE",
            "grant_type": GrantType.ALL,
        }
        result = drop_grant(urn, data)
        assert result == "REVOKE SELECT ON ALL TABLES IN SCHEMA MY_DB.MY_SCHEMA FROM ROLE MY_ROLE"

    def test_revoke_future_grant_from_database_role(self):
        """Test revoking future grant from database role."""
        urn = make_urn(ResourceType.GRANT, "GRANT")
        data = {
            "priv": "SELECT",
            "on_type": "SCHEMA",
            "on": "MY_DB.MY_SCHEMA",
            "items_type": "TABLE",
            "to": "MY_DB.MY_DB_ROLE",
            "to_type": "DATABASE ROLE",
            "grant_type": GrantType.FUTURE,
        }
        result = drop_grant(urn, data)
        assert "REVOKE SELECT ON FUTURE TABLES IN SCHEMA MY_DB.MY_SCHEMA FROM DATABASE ROLE MY_DB.MY_DB_ROLE" in result

    def test_revoke_basic_from_database_role(self):
        """Test basic revoke from database role."""
        urn = make_urn(ResourceType.GRANT, "GRANT")
        data = {
            "priv": "USAGE",
            "on_type": "SCHEMA",
            "on": "MY_DB.MY_SCHEMA",
            "to": "MY_DB.MY_DB_ROLE",
            "to_type": "DATABASE ROLE",
            "grant_type": GrantType.OBJECT,
        }
        result = drop_grant(urn, data)
        assert "REVOKE USAGE ON SCHEMA MY_DB.MY_SCHEMA FROM DATABASE ROLE MY_DB.MY_DB_ROLE" in result


class TestDropProcedure:
    """Tests for drop_procedure function."""

    def test_basic_drop(self):
        """Test dropping procedure."""
        urn = make_urn(ResourceType.PROCEDURE, "MY_PROC", database="MY_DB", schema="MY_SCHEMA")
        data = {}
        result = drop_procedure(urn, data, if_exists=True)
        assert "DROP PROCEDURE IF EXISTS" in result


class TestDropRoleGrant:
    """Tests for drop_role_grant function."""

    def test_revoke_from_role(self):
        """Test revoking role from role."""
        urn = make_urn(ResourceType.ROLE_GRANT, "GRANT")
        data = {
            "role": "SOURCE_ROLE",
            "to_role": "TARGET_ROLE",
            "to_user": None,
        }
        result = drop_role_grant(urn, data)
        assert "REVOKE ROLE SOURCE_ROLE FROM ROLE TARGET_ROLE" in result

    def test_revoke_from_user(self):
        """Test revoking role from user."""
        urn = make_urn(ResourceType.ROLE_GRANT, "GRANT")
        data = {
            "role": "MY_ROLE",
            "to_role": None,
            "to_user": "MY_USER",
        }
        result = drop_role_grant(urn, data)
        assert "REVOKE ROLE MY_ROLE FROM USER MY_USER" in result


class TestDropScannerPackage:
    """Tests for drop_scanner_package function."""

    def test_basic_drop(self):
        """Test dropping (disabling) scanner package."""
        urn = make_urn(ResourceType.SCANNER_PACKAGE, "CIS_BENCHMARKS")
        data = {}
        result = drop_scanner_package(urn, data)
        assert "CALL SNOWFLAKE.TRUST_CENTER.SET_CONFIGURATION" in result
        assert "'ENABLED'" in result
        assert "'FALSE'" in result


# ============================================================================
# Test transfer_resource
# ============================================================================


class TestTransferResource:
    """Tests for transfer_resource and transfer__default functions."""

    def test_basic_transfer(self):
        """Test basic ownership transfer."""
        urn = make_urn(ResourceType.DATABASE, "MY_DB")
        result = transfer_resource(urn, "NEW_OWNER", ResourceType.ROLE)
        assert "GRANT OWNERSHIP ON DATABASE" in result
        assert "TO ROLE NEW_OWNER" in result

    def test_transfer_with_copy_grants(self):
        """Test transfer with COPY CURRENT GRANTS."""
        urn = make_urn(ResourceType.TABLE, "MY_TABLE", database="MY_DB", schema="MY_SCHEMA")
        result = transfer_resource(urn, "NEW_OWNER", ResourceType.ROLE, copy_current_grants=True)
        assert "COPY CURRENT GRANTS" in result

    def test_transfer_with_revoke_grants(self):
        """Test transfer with REVOKE CURRENT GRANTS."""
        urn = make_urn(ResourceType.TABLE, "MY_TABLE", database="MY_DB", schema="MY_SCHEMA")
        result = transfer_resource(urn, "NEW_OWNER", ResourceType.ROLE, revoke_current_grants=True)
        assert "REVOKE CURRENT GRANTS" in result

    def test_transfer_default(self):
        """Test transfer__default directly."""
        urn = make_urn(ResourceType.SCHEMA, "MY_SCHEMA", database="MY_DB")
        result = transfer__default(urn, "NEW_OWNER", ResourceType.DATABASE_ROLE)
        assert "GRANT OWNERSHIP ON SCHEMA" in result
        # ResourceType.DATABASE_ROLE renders as "DATABASE ROLE"
        assert "TO DATABASE ROLE NEW_OWNER" in result


# ============================================================================
# Test tag masking policy reference functions
# ============================================================================


class TestCreateTagMaskingPolicyReference:
    """Tests for create_tag_masking_policy_reference function."""

    def test_basic_create(self):
        """Test basic tag masking policy reference creation."""
        urn = make_urn(ResourceType.TAG_MASKING_POLICY_REFERENCE, "PII")
        data = {
            "tag_name": "MY_DB.MY_SCHEMA.PII",
            "masking_policy_name": "MY_DB.MY_SCHEMA.MASK_PII",
        }
        props = MockProps("")
        result = create_tag_masking_policy_reference(urn, data, props)
        assert result == "ALTER TAG MY_DB.MY_SCHEMA.PII SET MASKING POLICY MY_DB.MY_SCHEMA.MASK_PII"

    def test_with_different_schemas(self):
        """Test tag masking policy reference with tag and policy in different schemas."""
        urn = make_urn(ResourceType.TAG_MASKING_POLICY_REFERENCE, "SENSITIVE")
        data = {
            "tag_name": "GOVERNANCE_DB.TAGS.SENSITIVE",
            "masking_policy_name": "SECURITY_DB.POLICIES.MASK_SENSITIVE",
        }
        props = MockProps("")
        result = create_tag_masking_policy_reference(urn, data, props)
        assert "ALTER TAG GOVERNANCE_DB.TAGS.SENSITIVE" in result
        assert "SET MASKING POLICY SECURITY_DB.POLICIES.MASK_SENSITIVE" in result


class TestDropTagMaskingPolicyReference:
    """Tests for drop_tag_masking_policy_reference function."""

    def test_basic_drop(self):
        """Test basic tag masking policy reference removal."""
        urn = make_urn(ResourceType.TAG_MASKING_POLICY_REFERENCE, "PII")
        data = {
            "tag_name": "MY_DB.MY_SCHEMA.PII",
            "masking_policy_name": "MY_DB.MY_SCHEMA.MASK_PII",
        }
        result = drop_tag_masking_policy_reference(urn, data)
        assert result == "ALTER TAG MY_DB.MY_SCHEMA.PII UNSET MASKING POLICY MY_DB.MY_SCHEMA.MASK_PII"

    def test_with_different_schemas(self):
        """Test tag masking policy reference removal with different schemas."""
        urn = make_urn(ResourceType.TAG_MASKING_POLICY_REFERENCE, "SENSITIVE")
        data = {
            "tag_name": "GOVERNANCE_DB.TAGS.SENSITIVE",
            "masking_policy_name": "SECURITY_DB.POLICIES.MASK_SENSITIVE",
        }
        result = drop_tag_masking_policy_reference(urn, data)
        assert "ALTER TAG GOVERNANCE_DB.TAGS.SENSITIVE" in result
        assert "UNSET MASKING POLICY SECURITY_DB.POLICIES.MASK_SENSITIVE" in result


class TestUpdateTagMaskingPolicyReference:
    """
    Tests for update_tag_masking_policy_reference.

    The bug: update__default interpolates urn.fqn into DDL, but
    TagMaskingPolicyReference.fqn is in URN query-string form
    (TAG?masking_policy=POLICY), producing malformed SQL:

        ALTER TAG MASKING POLICY REFERENCE GOVERNANCE.TAGS.HR_PII?masking_policy=... SET

    Snowflake rejects this with error 001003 (42000).

    The fix emits valid DDL by extracting the tag name via fqn_to_sql (which
    strips FQN params) and the old policy from urn.fqn.params.
    """

    def test_emits_unset_with_valid_sql(self):
        """UNSET statement must not contain the '?masking_policy=' query-string suffix."""
        urn = make_urn_with_params(
            ResourceType.TAG_MASKING_POLICY_REFERENCE,
            name="HR_PII",
            database="GOVERNANCE",
            schema="TAGS",
            params={"masking_policy": "GOVERNANCE.POLICIES.MASK_HR_PII_TIMESTAMP_NTZ"},
        )
        data = {"masking_policy_name": "GOVERNANCE.POLICIES.MASK_HR_PII_STRING"}
        props = MockProps("")
        result = update_tag_masking_policy_reference(urn, data, props)

        assert "?" not in result, f"malformed SQL contains '?': {result!r}"
        assert "UNSET MASKING POLICY" in result
        assert "GOVERNANCE.TAGS.HR_PII" in result
        assert "GOVERNANCE.POLICIES.MASK_HR_PII_TIMESTAMP_NTZ" in result

    def test_uses_old_policy_from_urn_params_for_unset(self):
        """UNSET must reference the OLD masking policy (from urn.fqn.params), not the new one."""
        old_policy = "MY_DB.MY_SCHEMA.MASK_PII_V1"
        new_policy = "MY_DB.MY_SCHEMA.MASK_PII_V2"
        urn = make_urn_with_params(
            ResourceType.TAG_MASKING_POLICY_REFERENCE,
            name="PII",
            database="MY_DB",
            schema="MY_SCHEMA",
            params={"masking_policy": old_policy},
        )
        data = {"masking_policy_name": new_policy}
        props = MockProps("")
        result = update_tag_masking_policy_reference(urn, data, props)

        assert old_policy in result
        assert new_policy not in result
        assert "UNSET MASKING POLICY" in result

    def test_update_dispatched_via_update_resource(self):
        """update_resource dispatcher must route TAG_MASKING_POLICY_REFERENCE to the dedicated handler."""
        urn = make_urn_with_params(
            ResourceType.TAG_MASKING_POLICY_REFERENCE,
            name="PII",
            database="MY_DB",
            schema="MY_SCHEMA",
            params={"masking_policy": "MY_DB.MY_SCHEMA.MASK_OLD"},
        )
        data = {"masking_policy_name": "MY_DB.MY_SCHEMA.MASK_NEW"}
        props = MockProps("")
        result = update_resource(urn, data, props)

        assert "?" not in result, f"dispatcher produced malformed SQL: {result!r}"
        assert "UNSET MASKING POLICY" in result


class TestUpdateMCPServer:
    """
    Tests for update_mcp_server.

    Snowflake has no ALTER MCP SERVER command, so a specification change is applied
    by dropping and recreating the server with CREATE OR REPLACE. Renaming is not
    supported at all: no command exists to change an MCP server's name in place.
    """

    def test_specification_change_uses_create_or_replace(self):
        """A specification delta must produce CREATE OR REPLACE, never ALTER MCP SERVER."""
        urn = make_urn(ResourceType.MCP_SERVER, "MY_SERVER", database="MY_DB", schema="MY_SCHEMA")
        data = {"specification": "tools:\n- name: query_data\n  type: SYSTEM_EXECUTE_SQL\nversion: 1\n"}
        result = update_mcp_server(urn, data, res.MCPServer.props)

        assert result.startswith("CREATE OR REPLACE MCP SERVER")
        assert "FROM SPECIFICATION $$" in result
        assert "ALTER MCP SERVER" not in result

    def test_rename_raises_targeted_error(self):
        """Renaming an MCP server has no Snowflake command and must raise, never ALTER ... RENAME TO."""
        urn = make_urn(ResourceType.MCP_SERVER, "MY_SERVER", database="MY_DB", schema="MY_SCHEMA")
        data = {"name": "NEW_SERVER"}
        props = MockProps("")

        with pytest.raises(NotImplementedError, match="MCP server"):
            update_mcp_server(urn, data, props)

    def test_rename_combined_with_specification_still_raises(self):
        """Rename is impossible regardless of any other field in the delta, including specification."""
        urn = make_urn(ResourceType.MCP_SERVER, "MY_SERVER", database="MY_DB", schema="MY_SCHEMA")
        data = {"name": "NEW_SERVER", "specification": "tools:\n- name: foo\n  type: SYSTEM_EXECUTE_SQL\n"}
        props = MockProps("")

        with pytest.raises(NotImplementedError, match="MCP server"):
            update_mcp_server(urn, data, props)

    def test_update_resource_dispatches_to_mcp_server_handler(self):
        """update_resource dispatcher must route MCP_SERVER to update_mcp_server, not update__default."""
        urn = make_urn(ResourceType.MCP_SERVER, "MY_SERVER", database="MY_DB", schema="MY_SCHEMA")
        data = {"specification": "tools:\n- name: query_data\n  type: SYSTEM_EXECUTE_SQL\nversion: 1\n"}
        result = update_resource(urn, data, res.MCPServer.props)

        assert result.startswith("CREATE OR REPLACE MCP SERVER")
        assert "ALTER MCP SERVER" not in result

    def test_update_resource_dispatches_alert_state_to_resume(self):
        """Issue #57: an alert's state change routes to ALTER ALERT ... RESUME/SUSPEND."""
        urn = make_urn(ResourceType.ALERT, "MY_ALERT", database="MY_DB", schema="MY_SCHEMA")
        assert (
            update_resource(urn, {"state": "STARTED"}, res.Alert.props) == "ALTER ALERT MY_DB.MY_SCHEMA.MY_ALERT RESUME"
        )
        assert (
            update_resource(urn, {"state": "SUSPENDED"}, res.Alert.props)
            == "ALTER ALERT MY_DB.MY_SCHEMA.MY_ALERT SUSPEND"
        )

    def test_update_alert_non_state_delta_delegates_to_default(self):
        """A non-state alert field routes to update__default (multi-field SET), not popitem."""
        urn = make_urn(ResourceType.ALERT, "MY_ALERT", database="MY_DB", schema="MY_SCHEMA")
        result = update_resource(urn, {"comment": "hi"}, res.Alert.props)
        assert result == "ALTER ALERT MY_DB.MY_SCHEMA.MY_ALERT SET COMMENT = $$hi$$"

    def test_update_alert_state_with_other_fields_raises_rather_than_dropping(self):
        """state can't be combined with a SET; the other field must not be silently dropped."""
        urn = make_urn(ResourceType.ALERT, "MY_ALERT", database="MY_DB", schema="MY_SCHEMA")
        with pytest.raises(NotImplementedError, match="cannot combine"):
            update_resource(urn, {"state": "STARTED", "comment": "hi"}, res.Alert.props)


class TestCreateMCPServer:
    """create_resource needs no MCP server override; create__default already produces valid DDL."""

    def test_create_uses_from_specification(self):
        urn = make_urn(ResourceType.MCP_SERVER, "MY_SERVER", database="MY_DB", schema="MY_SCHEMA")
        data = {
            "name": "MY_SERVER",
            "specification": "tools:\n- name: query_data\n  type: SYSTEM_EXECUTE_SQL\nversion: 1\n",
            "owner": "SYSADMIN",
        }
        result = create_resource(urn, data, res.MCPServer.props)

        assert result.startswith("CREATE MCP SERVER MY_DB.MY_SCHEMA.MY_SERVER")
        assert "FROM SPECIFICATION $$" in result
        assert "OR REPLACE" not in result


class TestDropMCPServer:
    """drop_resource needs no MCP server override; drop__default already produces valid DDL."""

    def test_drop_if_exists(self):
        urn = make_urn(ResourceType.MCP_SERVER, "MY_SERVER", database="MY_DB", schema="MY_SCHEMA")
        result = drop_resource(urn, {}, if_exists=True)

        assert result == "DROP MCP SERVER IF EXISTS MY_DB.MY_SCHEMA.MY_SERVER"


# ============================================================================
# Test SnowflakeCustomOAuthSecurityIntegration lifecycle
# ============================================================================


class TestCreateSnowflakeCustomOAuthSecurityIntegration:
    """create_sql, the OAUTH/CUSTOM resolver, and field validation for SnowflakeCustomOAuthSecurityIntegration."""

    def test_resolver_returns_custom_class(self):
        """The OAUTH/CUSTOM resolver branch must no longer raise NotImplementedError."""
        resource_cls = res.Resource.resolve_resource_cls(
            ResourceType.SECURITY_INTEGRATION, {"type": "OAUTH", "oauth_client": "CUSTOM"}
        )
        assert resource_cls is res.SnowflakeCustomOAuthSecurityIntegration

    def test_missing_oauth_client_type_raises(self):
        """oauth_client_type is required at CREATE."""
        with pytest.raises(ValueError):
            res.SnowflakeCustomOAuthSecurityIntegration(
                name="TEST_INTEGRATION", oauth_redirect_uri="https://example.com/cb"
            )

    def test_missing_oauth_redirect_uri_raises(self):
        """oauth_redirect_uri is required at CREATE."""
        with pytest.raises(ValueError):
            res.SnowflakeCustomOAuthSecurityIntegration(name="TEST_INTEGRATION", oauth_client_type="CONFIDENTIAL")

    def test_string_and_enum_oauth_client_type_produce_same_dict(self):
        """oauth_client_type accepts either the raw string or the enum member."""
        from snowcap.resources.security_integration import OAuthClientType, OAuthUseSecondaryRoles

        by_string = res.SnowflakeCustomOAuthSecurityIntegration(
            name="TEST_INTEGRATION", oauth_client_type="CONFIDENTIAL", oauth_redirect_uri="https://example.com/cb"
        )
        by_enum = res.SnowflakeCustomOAuthSecurityIntegration(
            name="TEST_INTEGRATION",
            oauth_client_type=OAuthClientType.CONFIDENTIAL,
            oauth_redirect_uri="https://example.com/cb",
        )
        assert by_string.to_dict() == by_enum.to_dict()
        assert by_string._data.oauth_use_secondary_roles == OAuthUseSecondaryRoles.NONE

    def test_role_lists_are_sorted(self):
        """pre_authorized_roles_list and blocked_roles_list must be canonicalized to sorted order."""
        integration = res.SnowflakeCustomOAuthSecurityIntegration(
            name="TEST_INTEGRATION",
            oauth_client_type="CONFIDENTIAL",
            oauth_redirect_uri="https://example.com/cb",
            pre_authorized_roles_list=["SYSADMIN", "ANALYST"],
            blocked_roles_list=["SYSADMIN", "ANALYST"],
        )
        data = integration.to_dict()
        assert data["pre_authorized_roles_list"] == ["ANALYST", "SYSADMIN"]
        assert data["blocked_roles_list"] == ["ANALYST", "SYSADMIN"]

    def test_role_lists_are_case_normalized(self):
        """Unquoted role names are uppercased so a lowercase manifest doesn't drift against DESC."""
        integration = res.SnowflakeCustomOAuthSecurityIntegration(
            name="TEST_INTEGRATION",
            oauth_client_type="CONFIDENTIAL",
            oauth_redirect_uri="https://example.com/cb",
            blocked_roles_list=["sysadmin"],
        )
        assert integration.to_dict()["blocked_roles_list"] == ["SYSADMIN"]

    def test_quoted_role_names_keep_case(self):
        """A quoted, case-sensitive role keeps its case (quotes stripped), matching
        what the fetch side produces for the same role."""
        integration = res.SnowflakeCustomOAuthSecurityIntegration(
            name="TEST_INTEGRATION",
            oauth_client_type="CONFIDENTIAL",
            oauth_redirect_uri="https://example.com/cb",
            pre_authorized_roles_list=['"my_role"', "ANALYST"],
            blocked_roles_list=['"my_role"', "SYSADMIN"],
        )
        data = integration.to_dict()
        assert data["pre_authorized_roles_list"] == ["ANALYST", "my_role"]
        assert data["blocked_roles_list"] == ["SYSADMIN", "my_role"]

    def test_blocked_roles_list_rejects_always_blocked_roles(self):
        """ACCOUNTADMIN/ORGADMIN/GLOBALORGADMIN/SECURITYADMIN are always blocked by Snowflake
        and must not be listed, or every plan/apply would see a perpetual delta."""
        with pytest.raises(ValueError):
            res.SnowflakeCustomOAuthSecurityIntegration(
                name="TEST_INTEGRATION",
                oauth_client_type="CONFIDENTIAL",
                oauth_redirect_uri="https://example.com/cb",
                blocked_roles_list=["ACCOUNTADMIN", "SYSADMIN"],
            )

    def test_create_sql(self):
        """CREATE SECURITY INTEGRATION renders every field, with a quoted client type and parenthesized quoted lists."""
        integration = res.SnowflakeCustomOAuthSecurityIntegration(
            name="CLAUDE_MCP_OAUTH",
            enabled=True,
            oauth_client_type="CONFIDENTIAL",
            oauth_redirect_uri="https://example.com/cb",
            oauth_alternate_redirect_uris=["https://example.com/cb2"],
            oauth_issue_refresh_tokens=True,
            oauth_refresh_token_validity=7776000,
            oauth_use_secondary_roles="NONE",
            oauth_enforce_pkce=True,
            blocked_roles_list=["SYSADMIN", "ANALYST"],
            comment="test comment",
        )
        sql = integration.create_sql()
        assert sql == (
            "CREATE SECURITY INTEGRATION CLAUDE_MCP_OAUTH type = OAUTH ENABLED = TRUE "
            "oauth_client = CUSTOM oauth_client_type = 'CONFIDENTIAL' "
            "OAUTH_REDIRECT_URI = $$https://example.com/cb$$ "
            "OAUTH_ALLOW_NON_TLS_REDIRECT_URI = FALSE "
            "OAUTH_ALTERNATE_REDIRECT_URIS = ($$https://example.com/cb2$$) "
            "OAUTH_ISSUE_REFRESH_TOKENS = TRUE OAUTH_REFRESH_TOKEN_VALIDITY = 7776000 "
            "OAUTH_SINGLE_USE_REFRESH_TOKENS_REQUIRED = FALSE "
            "oauth_use_secondary_roles = NONE oauth_any_role_mode = DISABLE "
            "OAUTH_ENFORCE_PKCE = TRUE OAUTH_ENABLE_ROLE_SELECTION = FALSE "
            "BLOCKED_ROLES_LIST = ($$ANALYST$$, $$SYSADMIN$$) COMMENT = $$test comment$$"
        )


class TestUpdateSnowflakeCustomOAuthSecurityIntegration:
    """update_set_sql and replacement/fetchable metadata for SnowflakeCustomOAuthSecurityIntegration."""

    def test_metadata(self):
        """oauth_client_type triggers replacement; oauth_alternate_redirect_uris is create-only."""
        spec = res.SnowflakeCustomOAuthSecurityIntegration.spec
        oauth_client_type_metadata = spec.get_metadata("oauth_client_type")
        assert oauth_client_type_metadata.triggers_replacement is True
        # The plan-time error must explain why snowcap refuses to recreate.
        assert "client_id and client_secret" in oauth_client_type_metadata.replacement_message
        assert spec.get_metadata("oauth_alternate_redirect_uris").fetchable is False
        # oauth_enable_role_selection is CREATE-only: DESC never returns it, so it must be
        # unfetchable or it drifts "set to default" on every plan.
        assert spec.get_metadata("oauth_enable_role_selection").fetchable is False

    def test_update_set_sql(self):
        """A single-field delta renders as ALTER SECURITY INTEGRATION ... SET, never CREATE OR REPLACE."""
        urn = make_urn(ResourceType.SECURITY_INTEGRATION, "CLAUDE_MCP_OAUTH")
        data = {"oauth_refresh_token_validity": 86400}
        result = update_resource(urn, data, res.SnowflakeCustomOAuthSecurityIntegration.props)
        assert result == "ALTER SECURITY INTEGRATION CLAUDE_MCP_OAUTH SET OAUTH_REFRESH_TOKEN_VALIDITY = 86400"
