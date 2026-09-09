"""
Unit tests for snowcap/data_provider.py

Tests the data provider functions without requiring a real Snowflake connection.
All functions are tested with mocked execute() results.
"""

import pytest
from unittest.mock import MagicMock, patch, PropertyMock

from snowcap.client import reset_cache
from snowcap.data_provider import (
    # Helper functions
    _ACCOUNT_USAGE_GRANTS_CACHE,
    _fetch_grant_to_role,
    _grant_name_key,
    _grants_by_role_index,
    _list_schema_scoped_from_account_usage,
    _show_all_grants_to_role,
    reset_account_usage_caches,
    _quote_snowflake_identifier,
    _get_owner_identifier,
    _desc_result_to_dict,
    _desc_type2_result_to_dict,
    _desc_type3_result_to_dict,
    _desc_type4_result_to_dict,
    _fail_if_not_granted,
    _filter_result,
    _convert_to_gmt,
    _parse_cluster_keys,
    _parse_function_arguments,
    _parse_function_arguments_2023_compat,
    _parse_list_property,
    _parse_signature,
    _parse_comma_separated_values,
    _parse_packages,
    _parse_storage_location,
    _parse_pat_policy_property,
    _suppress_default_pat_policy,
    _cast_param_value,
    _show_future_grants_to_role,
    params_result_to_dict,
    options_result_to_list,
    remove_none_values,
    # Dispatcher functions
    fetch_grant,
    fetch_resource,
    fetch_database,
    fetch_shared_database,
    fetch_security_integration,
    fetch_task,
    fetch_warehouse,
    fetch_streamlit,
    list_resource,
    list_account_scoped_resource,
    list_schema_scoped_resource,
    list_stages,
    list_tables,
    list_views,
    # Session functions
    fetch_account_locator,
    fetch_region,
)
from snowcap.identifiers import FQN, URN
from snowcap.resource_name import ResourceName
from snowcap.enums import GrantType, ResourceType
from snowcap import resources as res
from snowcap.resources.warehouse import ADAPTIVE_UNSUPPORTED_FIELDS

import datetime
import json
import logging
import pytz


class TestQuoteSnowflakeIdentifier:
    """Tests for _quote_snowflake_identifier helper function."""

    def test_uppercase_identifier(self):
        # Uppercase identifiers pass through without quotes
        result = _quote_snowflake_identifier("MY_TABLE")
        assert str(result) == "MY_TABLE"

    def test_lowercase_identifier_gets_quoted(self):
        # Lowercase identifiers from Snowflake metadata get quoted
        result = _quote_snowflake_identifier("my_table")
        assert str(result) == '"my_table"'

    def test_identifier_with_special_chars(self):
        result = _quote_snowflake_identifier("my-table")
        assert str(result) == '"my-table"'

    def test_already_quoted_identifier(self):
        result = _quote_snowflake_identifier('"MyTable"')
        assert str(result) == '"MyTable"'

    def test_string_input(self):
        # resource_name_from_snowflake_metadata requires string input
        result = _quote_snowflake_identifier("MY_SCHEMA")
        assert str(result) == "MY_SCHEMA"


class TestGetOwnerIdentifier:
    """Tests for _get_owner_identifier helper function."""

    def test_simple_owner(self):
        data = {"owner": "ACCOUNTADMIN"}
        result = _get_owner_identifier(data)
        assert result == "ACCOUNTADMIN"

    def test_database_role_owner(self):
        # Lowercase names from Snowflake metadata get quoted
        data = {"owner": "my_role", "owner_role_type": "DATABASE_ROLE", "database_name": "my_db"}
        result = _get_owner_identifier(data)
        assert result == '"my_db"."my_role"'

    def test_database_role_owner_uppercase(self):
        # Uppercase names pass through without quotes
        data = {"owner": "MY_ROLE", "owner_role_type": "DATABASE_ROLE", "database_name": "MY_DB"}
        result = _get_owner_identifier(data)
        assert result == "MY_DB.MY_ROLE"

    def test_role_type_owner(self):
        data = {"owner": "SYSADMIN", "owner_role_type": "ROLE"}
        result = _get_owner_identifier(data)
        assert result == "SYSADMIN"

    def test_empty_owner_with_role_type(self):
        data = {"owner": "", "owner_role_type": "ROLE"}
        result = _get_owner_identifier(data)
        assert result == ""

    def test_missing_owner_without_role_type(self):
        # SYSTEM$SHOW_IMPORTED_DATABASES may omit the owner field on some editions;
        # a missing owner must degrade to drift, not crash the plan with a KeyError.
        result = _get_owner_identifier({"name": "GONG"})
        assert result == ""

    def test_empty_owner_without_role_type(self):
        result = _get_owner_identifier({"owner": ""})
        assert result == ""

    def test_unsupported_owner_role_type_raises(self):
        data = {"owner": "my_role", "owner_role_type": "UNKNOWN_TYPE", "database_name": "my_db"}
        with pytest.raises(Exception, match="Unsupported owner role type"):
            _get_owner_identifier(data)


class TestDescResultToDict:
    """Tests for _desc_result_to_dict helper function."""

    def test_basic_desc_result(self):
        desc_result = [
            {"property": "NAME", "value": "test_table"},
            {"property": "TYPE", "value": "TABLE"},
        ]
        result = _desc_result_to_dict(desc_result)
        assert result == {"NAME": "test_table", "TYPE": "TABLE"}

    def test_lower_properties(self):
        desc_result = [
            {"property": "NAME", "value": "test_table"},
            {"property": "TYPE", "value": "TABLE"},
        ]
        result = _desc_result_to_dict(desc_result, lower_properties=True)
        assert result == {"name": "test_table", "type": "TABLE"}

    def test_empty_result(self):
        result = _desc_result_to_dict([])
        assert result == {}


class TestDescType2ResultToDict:
    """Tests for _desc_type2_result_to_dict helper function."""

    def test_boolean_property(self):
        desc_result = [{"property": "ENABLED", "property_value": "true", "property_type": "Boolean"}]
        result = _desc_type2_result_to_dict(desc_result)
        assert result["ENABLED"] is True

    def test_boolean_false(self):
        desc_result = [{"property": "ENABLED", "property_value": "false", "property_type": "Boolean"}]
        result = _desc_type2_result_to_dict(desc_result)
        assert result["ENABLED"] is False

    def test_long_property(self):
        desc_result = [{"property": "SIZE", "property_value": "1024", "property_type": "Long"}]
        result = _desc_type2_result_to_dict(desc_result)
        assert result["SIZE"] == "1024"

    def test_long_empty_value(self):
        desc_result = [{"property": "SIZE", "property_value": "", "property_type": "Long"}]
        result = _desc_type2_result_to_dict(desc_result)
        assert result["SIZE"] is None

    def test_integer_property(self):
        desc_result = [{"property": "COUNT", "property_value": "42", "property_type": "Integer"}]
        result = _desc_type2_result_to_dict(desc_result)
        assert result["COUNT"] == 42

    def test_string_property(self):
        desc_result = [{"property": "NAME", "property_value": "my_name", "property_type": "String"}]
        result = _desc_type2_result_to_dict(desc_result)
        assert result["NAME"] == "my_name"

    def test_string_empty_value(self):
        desc_result = [{"property": "NAME", "property_value": "", "property_type": "String"}]
        result = _desc_type2_result_to_dict(desc_result)
        assert result["NAME"] is None

    def test_list_property(self):
        desc_result = [{"property": "ROLES", "property_value": "[role1, role2]", "property_type": "List"}]
        result = _desc_type2_result_to_dict(desc_result)
        assert result["ROLES"] == ["role1", "role2"]

    def test_object_property(self):
        desc_result = [{"property": "CONFIG", "property_value": "[a, b, c]", "property_type": "Object"}]
        result = _desc_type2_result_to_dict(desc_result)
        assert result["CONFIG"] == ["a", "b", "c"]


class TestDescType3ResultToDict:
    """Tests for _desc_type3_result_to_dict helper function."""

    def test_flat_property(self):
        desc_result = [{"parent_property": "", "property": "NAME", "property_value": "test", "property_type": "String"}]
        result = _desc_type3_result_to_dict(desc_result)
        assert result["NAME"] == "test"

    def test_nested_property(self):
        desc_result = [
            {"parent_property": "CONFIG", "property": "SIZE", "property_value": "10", "property_type": "Integer"}
        ]
        result = _desc_type3_result_to_dict(desc_result)
        assert result["CONFIG"]["SIZE"] == 10

    def test_multiple_nested_properties(self):
        desc_result = [
            {"parent_property": "CONFIG", "property": "SIZE", "property_value": "10", "property_type": "Integer"},
            {"parent_property": "CONFIG", "property": "ENABLED", "property_value": "true", "property_type": "Boolean"},
        ]
        result = _desc_type3_result_to_dict(desc_result)
        assert result["CONFIG"]["SIZE"] == 10
        assert result["CONFIG"]["ENABLED"] is True


class TestDescType4ResultToDict:
    """Tests for _desc_type4_result_to_dict helper function."""

    def test_basic_result(self):
        desc_result = [
            {"name": "param1", "value": "value1"},
            {"name": "param2", "value": "value2"},
        ]
        result = _desc_type4_result_to_dict(desc_result)
        assert result == {"param1": "value1", "param2": "value2"}

    def test_lower_properties(self):
        desc_result = [
            {"name": "PARAM1", "value": "value1"},
        ]
        result = _desc_type4_result_to_dict(desc_result, lower_properties=True)
        assert result == {"param1": "value1"}


class TestFailIfNotGranted:
    """Tests for _fail_if_not_granted helper function."""

    def test_empty_result_raises(self):
        with pytest.raises(Exception, match="Failed to create grant"):
            _fail_if_not_granted([])

    def test_insufficient_privileges_raises(self):
        result = [{"status": "Grant not executed: Insufficient privileges."}]
        with pytest.raises(Exception, match="Insufficient privileges"):
            _fail_if_not_granted(result)

    def test_success_does_not_raise(self):
        result = [{"status": "Grant succeeded."}]
        _fail_if_not_granted(result)  # Should not raise


class TestFilterResult:
    """Tests for _filter_result helper function."""

    def test_filter_by_single_key(self):
        result = [
            {"name": "TABLE1", "type": "TABLE"},
            {"name": "TABLE2", "type": "VIEW"},
        ]
        filtered = _filter_result(result, type="TABLE")
        assert len(filtered) == 1
        assert filtered[0]["name"] == "TABLE1"

    def test_filter_by_name_resource_name(self):
        result = [
            {"name": "MY_TABLE", "type": "TABLE"},
            {"name": "OTHER_TABLE", "type": "TABLE"},
        ]
        filtered = _filter_result(result, name="my_table")
        assert len(filtered) == 1
        assert filtered[0]["name"] == "MY_TABLE"

    def test_filter_by_multiple_keys(self):
        result = [
            {"name": "TABLE1", "database_name": "DB1", "type": "TABLE"},
            {"name": "TABLE1", "database_name": "DB2", "type": "TABLE"},
            {"name": "TABLE2", "database_name": "DB1", "type": "VIEW"},
        ]
        filtered = _filter_result(result, name="TABLE1", database_name="DB1")
        assert len(filtered) == 1
        assert filtered[0]["database_name"] == "DB1"

    def test_filter_ignores_none_values(self):
        result = [
            {"name": "TABLE1", "type": "TABLE"},
            {"name": "TABLE2", "type": "VIEW"},
        ]
        filtered = _filter_result(result, name=None, type="TABLE")
        assert len(filtered) == 1


class TestConvertToGmt:
    """Tests for _convert_to_gmt helper function."""

    def test_convert_pst_to_gmt(self):
        pst = pytz.timezone("America/Los_Angeles")
        dt = pst.localize(datetime.datetime(2024, 1, 15, 12, 0, 0))
        result = _convert_to_gmt(dt)
        assert result == "2024-01-15 20:00:00"

    def test_none_input_returns_none(self):
        result = _convert_to_gmt(None)
        assert result is None

    def test_custom_format(self):
        pst = pytz.timezone("America/Los_Angeles")
        dt = pst.localize(datetime.datetime(2024, 1, 15, 12, 30, 45))
        result = _convert_to_gmt(dt, fmt_str="%Y-%m-%d %H:%M")
        assert result == "2024-01-15 20:30"


class TestParseClusterKeys:
    """Tests for _parse_cluster_keys helper function."""

    def test_simple_cluster_keys(self):
        result = _parse_cluster_keys("LINEAR(C1, C3)")
        assert result == ["C1", "C3"]

    def test_expression_cluster_keys(self):
        # Note: The function uses simple comma split, so nested expressions get split
        result = _parse_cluster_keys("LINEAR(SUBSTRING(C2, 5, 15), CAST(C1 AS DATE))")
        # This shows the current behavior - nested commas are also split
        assert len(result) > 0
        assert "SUBSTRING(C2" in result[0]

    def test_none_returns_none(self):
        result = _parse_cluster_keys(None)
        assert result is None

    def test_empty_string_returns_none(self):
        result = _parse_cluster_keys("")
        assert result is None


class TestParseFunctionArguments:
    """Tests for _parse_function_arguments helper function."""

    def test_simple_function(self):
        identifier, returns = _parse_function_arguments("FETCH_DATABASE(VARCHAR) RETURN OBJECT")
        # The FQN name field holds just the function name, sig is in the FQN
        assert str(identifier.name) == "FETCH_DATABASE"
        assert returns == "OBJECT"

    def test_multiple_arguments(self):
        identifier, returns = _parse_function_arguments("MY_FUNC(VARCHAR, NUMBER) RETURN TABLE")
        assert str(identifier.name) == "MY_FUNC"
        assert returns == "TABLE"

    def test_returns_fqn_with_arg_types(self):
        identifier, returns = _parse_function_arguments("FETCH_DATABASE(VARCHAR) RETURN OBJECT")
        # The FQN should contain the argument types
        assert identifier.arg_types == ["VARCHAR"]


class TestParseFunctionArguments2023Compat:
    """Tests for _parse_function_arguments_2023_compat helper function."""

    def test_optional_arguments(self):
        identifier, returns = _parse_function_arguments_2023_compat("FETCH_DATABASE(OBJECT [, BOOLEAN]) RETURN OBJECT")
        # Optional brackets are removed
        assert str(identifier.name) == "FETCH_DATABASE"
        assert identifier.arg_types == ["OBJECT", "BOOLEAN"]
        assert returns == "OBJECT"


class TestParseListProperty:
    """Tests for _parse_list_property helper function."""

    def test_simple_list(self):
        result = _parse_list_property("[a, b, c]")
        assert result == ["a", "b", "c"]

    def test_empty_list(self):
        result = _parse_list_property("[]")
        assert result == []

    def test_none_returns_none(self):
        result = _parse_list_property(None)
        assert result is None

    def test_empty_string_returns_none(self):
        result = _parse_list_property("")
        assert result is None

    def test_trims_whitespace(self):
        result = _parse_list_property("[ item1 ,  item2 ]")
        assert result == ["item1", "item2"]


class TestParsePatPolicyProperty:
    """Tests for _parse_pat_policy_property helper function."""

    def test_parses_brace_map(self):
        result = _parse_pat_policy_property(
            "{NETWORK_POLICY_EVALUATION=ENFORCED_NOT_REQUIRED, DEFAULT_EXPIRY_IN_DAYS=30, "
            "MAX_EXPIRY_IN_DAYS=180, REQUIRE_ROLE_RESTRICTION_FOR_SERVICE_USERS=false}"
        )
        assert result == {
            "network_policy_evaluation": "ENFORCED_NOT_REQUIRED",
            "default_expiry_in_days": 30,
            "max_expiry_in_days": 180,
            "require_role_restriction_for_service_users": False,
        }

    def test_coerces_boolean_case_insensitively(self):
        result = _parse_pat_policy_property(
            "{NETWORK_POLICY_EVALUATION=ENFORCED_REQUIRED, DEFAULT_EXPIRY_IN_DAYS=15, "
            "MAX_EXPIRY_IN_DAYS=365, REQUIRE_ROLE_RESTRICTION_FOR_SERVICE_USERS=TRUE}"
        )
        assert result["require_role_restriction_for_service_users"] is True

    def test_invalid_boolean_raises(self):
        with pytest.raises(ValueError):
            _parse_pat_policy_property(
                "{NETWORK_POLICY_EVALUATION=ENFORCED_REQUIRED, DEFAULT_EXPIRY_IN_DAYS=15, "
                "MAX_EXPIRY_IN_DAYS=365, REQUIRE_ROLE_RESTRICTION_FOR_SERVICE_USERS=MAYBE}"
            )

    def test_drops_unknown_keys(self):
        result = _parse_pat_policy_property(
            "{NETWORK_POLICY_EVALUATION=ENFORCED_REQUIRED, DEFAULT_EXPIRY_IN_DAYS=15, "
            "MAX_EXPIRY_IN_DAYS=365, REQUIRE_ROLE_RESTRICTION_FOR_SERVICE_USERS=true, "
            "SOME_FUTURE_SETTING=42}"
        )
        assert "some_future_setting" not in result
        assert result == {
            "network_policy_evaluation": "ENFORCED_REQUIRED",
            "default_expiry_in_days": 15,
            "max_expiry_in_days": 365,
            "require_role_restriction_for_service_users": True,
        }

    def test_none_returns_none(self):
        assert _parse_pat_policy_property(None) is None

    def test_empty_string_returns_none(self):
        assert _parse_pat_policy_property("") is None

    def test_null_string_returns_none(self):
        assert _parse_pat_policy_property("null") is None

    def test_whitespace_variants_parse_identically(self):
        result = _parse_pat_policy_property(
            "{ NETWORK_POLICY_EVALUATION = ENFORCED_NOT_REQUIRED, DEFAULT_EXPIRY_IN_DAYS = 30, "
            "MAX_EXPIRY_IN_DAYS = 180, REQUIRE_ROLE_RESTRICTION_FOR_SERVICE_USERS = false }"
        )
        assert result == {
            "network_policy_evaluation": "ENFORCED_NOT_REQUIRED",
            "default_expiry_in_days": 30,
            "max_expiry_in_days": 180,
            "require_role_restriction_for_service_users": False,
        }

    def test_no_braces_raises(self):
        with pytest.raises(ValueError):
            _parse_pat_policy_property("ENFORCED_REQUIRED")

    def test_unterminated_braces_raises(self):
        with pytest.raises(ValueError):
            _parse_pat_policy_property("{GARBAGE")

    def test_partial_keys_raises(self):
        with pytest.raises(ValueError):
            _parse_pat_policy_property("{DEFAULT_EXPIRY_IN_DAYS=30, MAX_EXPIRY_IN_DAYS=180}")

    def test_missing_boolean_key_raises(self):
        with pytest.raises(ValueError):
            _parse_pat_policy_property(
                "{NETWORK_POLICY_EVALUATION=ENFORCED_REQUIRED, DEFAULT_EXPIRY_IN_DAYS=15, MAX_EXPIRY_IN_DAYS=365}"
            )


class TestSuppressDefaultPatPolicy:
    """Tests for _suppress_default_pat_policy helper function."""

    def test_suppresses_default(self):
        result = _suppress_default_pat_policy(
            {
                "network_policy_evaluation": "ENFORCED_REQUIRED",
                "default_expiry_in_days": 15,
                "max_expiry_in_days": 365,
                "require_role_restriction_for_service_users": True,
            }
        )
        assert result is None

    def test_passes_through_non_default(self):
        pat_policy = {
            "network_policy_evaluation": "ENFORCED_NOT_REQUIRED",
            "default_expiry_in_days": 30,
            "max_expiry_in_days": 180,
            "require_role_restriction_for_service_users": False,
        }
        result = _suppress_default_pat_policy(pat_policy)
        assert result == pat_policy

    def test_passes_through_default_except_boolean(self):
        pat_policy = {
            "network_policy_evaluation": "ENFORCED_REQUIRED",
            "default_expiry_in_days": 15,
            "max_expiry_in_days": 365,
            "require_role_restriction_for_service_users": False,
        }
        result = _suppress_default_pat_policy(pat_policy)
        assert result == pat_policy

    def test_none_returns_none(self):
        assert _suppress_default_pat_policy(None) is None

    def test_declared_defaults_match_fetched_defaults(self):
        """Test the declared spec and the fetch layer suppress the exact defaults identically.

        Regression test: __post_init__ previously kept a declared-defaults dict while fetch
        suppressed the echoed defaults to None, so the comparison never converged (permanent
        drift, contradicting the AuthenticationPolicy docstring).
        """
        import snowcap.resources as res

        fetched = _suppress_default_pat_policy(
            _parse_pat_policy_property(
                "{NETWORK_POLICY_EVALUATION=ENFORCED_REQUIRED, DEFAULT_EXPIRY_IN_DAYS=15, "
                "MAX_EXPIRY_IN_DAYS=365, REQUIRE_ROLE_RESTRICTION_FOR_SERVICE_USERS=true}"
            )
        )
        declared = res.AuthenticationPolicy(
            name="p",
            pat_policy={
                "network_policy_evaluation": "ENFORCED_REQUIRED",
                "default_expiry_in_days": 15,
                "max_expiry_in_days": 365,
                "require_role_restriction_for_service_users": True,
            },
        ).to_dict()["pat_policy"]
        assert fetched is None
        assert declared is None


class TestParseSignature:
    """Tests for _parse_signature helper function."""

    def test_simple_signature(self):
        result = _parse_signature("(col1 VARCHAR, col2 NUMBER)")
        assert len(result) == 2

    def test_empty_signature(self):
        result = _parse_signature("()")
        assert result == []


class TestParseCommaSeparatedValues:
    """Tests for _parse_comma_separated_values helper function."""

    def test_simple_values(self):
        result = _parse_comma_separated_values("a, b, c")
        assert result == ["a", "b", "c"]

    def test_none_returns_none(self):
        result = _parse_comma_separated_values(None)
        assert result is None

    def test_empty_string_returns_none(self):
        result = _parse_comma_separated_values("")
        assert result is None


class TestParsePackages:
    """Tests for _parse_packages helper function."""

    def test_simple_packages(self):
        result = _parse_packages("['numpy', 'pandas']")
        assert result == ["numpy", "pandas"]

    def test_none_returns_none(self):
        result = _parse_packages(None)
        assert result is None

    def test_empty_string_returns_none(self):
        result = _parse_packages("")
        assert result is None


class TestParseStorageLocation:
    """Tests for _parse_storage_location helper function."""

    def test_s3_storage_location(self):
        storage_str = '{"name": "loc1", "storage_provider": "S3", "storage_base_url": "s3://bucket/path", "storage_aws_role_arn": "arn:aws:iam::123:role/test"}'
        result = _parse_storage_location(storage_str)
        assert result["name"] == "loc1"
        assert result["storage_provider"] == "S3"
        assert result["storage_base_url"] == "s3://bucket/path"

    def test_with_encryption(self):
        storage_str = '{"name": "loc1", "storage_provider": "S3", "encryption_type": "SSE_S3"}'
        result = _parse_storage_location(storage_str)
        assert result["encryption"]["type"] == "SSE_S3"

    def test_none_returns_none(self):
        result = _parse_storage_location(None)
        assert result is None

    def test_empty_string_returns_none(self):
        result = _parse_storage_location("")
        assert result is None


class TestCastParamValue:
    """Tests for _cast_param_value helper function."""

    def test_boolean_true(self):
        result = _cast_param_value("true", "BOOLEAN")
        assert result is True

    def test_boolean_false(self):
        result = _cast_param_value("false", "BOOLEAN")
        assert result is False

    def test_number_integer(self):
        result = _cast_param_value("42", "NUMBER")
        assert result == 42
        assert isinstance(result, int)

    def test_number_float(self):
        result = _cast_param_value("3.14", "NUMBER")
        assert result == 3.14
        assert isinstance(result, float)

    def test_string(self):
        result = _cast_param_value("hello", "STRING")
        assert result == "hello"

    def test_string_empty(self):
        result = _cast_param_value("", "STRING")
        assert result is None

    def test_unknown_type_returns_raw(self):
        result = _cast_param_value("value", "UNKNOWN")
        assert result == "value"

    def test_invalid_number_raises(self):
        with pytest.raises(Exception, match="Unsupported number type"):
            _cast_param_value("not_a_number", "NUMBER")

    def test_float(self):
        """SHOW PARAMETERS reports INITIAL_REPLICATION_SIZE_LIMIT_IN_TB (and other
        decimal-valued parameters) with type FLOAT, not NUMBER. Falling through to the
        raw-string default left the fetched value a str while the YAML-declared value
        parses to a Python float, so plan compared "10.0" != 10.0 and proposed an UPDATE
        that never converges."""
        result = _cast_param_value("10.0", "FLOAT")
        assert result == 10.0
        assert isinstance(result, float)

    def test_invalid_float_raises(self):
        with pytest.raises(Exception, match="Unsupported float type"):
            _cast_param_value("not_a_float", "FLOAT")


class TestParamsResultToDict:
    """Tests for params_result_to_dict helper function."""

    def test_basic_params(self):
        params_result = [
            {"key": "PARAM1", "value": "true", "type": "BOOLEAN"},
            {"key": "PARAM2", "value": "42", "type": "NUMBER"},
            {"key": "PARAM3", "value": "hello", "type": "STRING"},
        ]
        result = params_result_to_dict(params_result)
        assert result["param1"] is True
        assert result["param2"] == 42
        assert result["param3"] == "hello"


class TestFetchAccountParameter:
    """Regression test for the exact reported symptom: `snowcap apply` proposed an UPDATE
    for INITIAL_REPLICATION_SIZE_LIMIT_IN_TB on every run because SHOW PARAMETERS reports
    it with type FLOAT, which _cast_param_value didn't handle."""

    @patch("snowcap.data_provider.execute")
    def test_fetches_float_typed_parameter_as_a_float(self, mock_execute):
        from snowcap.data_provider import fetch_account_parameter
        from snowcap.identifiers import FQN
        from snowcap.resource_name import ResourceName

        mock_execute.return_value = [
            {
                "key": "INITIAL_REPLICATION_SIZE_LIMIT_IN_TB",
                "value": "10.0",
                "default": "10.0",
                "level": "ACCOUNT",
                "type": "FLOAT",
            }
        ]
        fqn = FQN(name=ResourceName("INITIAL_REPLICATION_SIZE_LIMIT_IN_TB"))

        result = fetch_account_parameter(MagicMock(), fqn)

        assert result is not None
        assert result["value"] == 10.0
        assert isinstance(result["value"], float)


class TestOptionsResultToList:
    """Tests for options_result_to_list helper function."""

    def test_simple_options(self):
        result = options_result_to_list("option1, option2, option3")
        assert result == ["option1", "option2", "option3"]


class TestRemoveNoneValues:
    """Tests for remove_none_values helper function."""

    def test_removes_none_at_top_level(self):
        d = {"a": 1, "b": None, "c": "hello"}
        result = remove_none_values(d)
        assert result == {"a": 1, "c": "hello"}

    def test_removes_none_in_nested_dict(self):
        d = {"a": {"b": 1, "c": None}}
        result = remove_none_values(d)
        assert result == {"a": {"b": 1}}

    def test_removes_none_in_list_of_dicts(self):
        d = {"items": [{"a": 1, "b": None}, {"c": 2}]}
        result = remove_none_values(d)
        assert result["items"][0] == {"a": 1}
        assert result["items"][1] == {"c": 2}

    def test_keeps_non_none_values(self):
        d = {"a": 0, "b": False, "c": ""}
        result = remove_none_values(d)
        assert result == {"a": 0, "b": False, "c": ""}


class TestFetchResource:
    """Tests for fetch_resource dispatcher function."""

    @patch("snowcap.data_provider.fetch_database")
    def test_dispatches_to_correct_fetch_function(self, mock_fetch_database):
        mock_fetch_database.return_value = {"name": "MY_DB"}
        mock_session = MagicMock()

        urn = URN(resource_type=ResourceType.DATABASE, account_locator="ABC123", fqn=FQN(name=ResourceName("MY_DB")))

        result = fetch_resource(mock_session, urn)

        mock_fetch_database.assert_called_once_with(mock_session, urn.fqn)
        assert result == {"name": "MY_DB"}

    @patch("snowcap.data_provider.fetch_schema")
    def test_dispatches_to_schema_fetch(self, mock_fetch_schema):
        mock_fetch_schema.return_value = {"name": "MY_SCHEMA"}
        mock_session = MagicMock()

        urn = URN(
            resource_type=ResourceType.SCHEMA,
            account_locator="ABC123",
            fqn=FQN(database=ResourceName("MY_DB"), name=ResourceName("MY_SCHEMA")),
        )

        result = fetch_resource(mock_session, urn)

        mock_fetch_schema.assert_called_once()
        assert result == {"name": "MY_SCHEMA"}

    @patch("snowcap.data_provider.fetch_role")
    def test_returns_none_on_does_not_exist_error(self, mock_fetch_role):
        from snowflake.connector.errors import ProgrammingError

        mock_fetch_role.side_effect = ProgrammingError(errno=2003)
        mock_session = MagicMock()

        urn = URN(resource_type=ResourceType.ROLE, account_locator="ABC123", fqn=FQN(name=ResourceName("MISSING_ROLE")))

        result = fetch_resource(mock_session, urn)
        assert result is None

    @patch("snowcap.data_provider.fetch_role")
    def test_raises_other_programming_errors(self, mock_fetch_role):
        from snowflake.connector.errors import ProgrammingError

        mock_fetch_role.side_effect = ProgrammingError(errno=1234)
        mock_session = MagicMock()

        urn = URN(resource_type=ResourceType.ROLE, account_locator="ABC123", fqn=FQN(name=ResourceName("MY_ROLE")))

        with pytest.raises(ProgrammingError):
            fetch_resource(mock_session, urn)


def _database_show_row(**overrides):
    row = {
        "name": "MY_DB",
        "kind": "STANDARD",
        "owner": "SYSADMIN",
        "owner_role_type": "ROLE",
        "retention_time": "1",
        "comment": "",
        "options": "",
    }
    row.update(overrides)
    return row


class TestFetchDatabase:
    """Tests for fetch_database's imported-database delegation."""

    @patch("snowcap.data_provider.fetch_shared_database")
    @patch("snowcap.data_provider._show_resource_parameters")
    @patch("snowcap.data_provider._show_resources")
    def test_imported_database_delegates_to_fetch_shared_database(
        self, mock_show_resources, mock_show_params, mock_fetch_shared_database
    ):
        mock_show_resources.return_value = [_database_show_row(kind="IMPORTED DATABASE", name="GONG")]
        mock_fetch_shared_database.return_value = {
            "name": "GONG",
            "from_share": "provider_account.share_name",
            "owner": "ACCOUNTADMIN",
        }
        mock_session = MagicMock()
        fqn = FQN(name=ResourceName("GONG"))

        result = fetch_database(mock_session, fqn)

        mock_fetch_shared_database.assert_called_once_with(mock_session, fqn)
        mock_show_params.assert_not_called()
        assert result == mock_fetch_shared_database.return_value
        assert "data_retention_time_in_days" not in result

    @patch("snowcap.data_provider._show_resource_parameters")
    @patch("snowcap.data_provider._show_resources")
    def test_standard_database_returns_full_shape(self, mock_show_resources, mock_show_params):
        mock_show_resources.return_value = [_database_show_row()]
        mock_show_params.return_value = {"default_ddl_collation": ""}
        mock_session = MagicMock()

        result = fetch_database(mock_session, FQN(name=ResourceName("MY_DB")))

        assert result["name"] == "MY_DB"
        assert result["data_retention_time_in_days"] == 1
        assert result["owner"] == "SYSADMIN"
        assert result["transient"] is False


class TestFetchSharedDatabase:
    """Tests for fetch_shared_database's handling of SYSTEM$SHOW_IMPORTED_DATABASES output."""

    @staticmethod
    def _mock_show_imported_databases(rows):
        return [{"SYSTEM$SHOW_IMPORTED_DATABASES()": json.dumps(rows)}]

    @patch("snowcap.data_provider.execute")
    def test_missing_owner_field_reports_pinned_owner(self, mock_execute):
        # SYSTEM$SHOW_IMPORTED_DATABASES' owner output is undocumented and may be absent
        # on some editions. The fetch never reads it: owner is pinned to ACCOUNTADMIN
        # (ownership of an imported database cannot change), so a missing field must not
        # crash the plan with a KeyError.
        mock_execute.return_value = self._mock_show_imported_databases(
            [{"name": "GONG", "origin": "PROVIDER_ACCOUNT.SHARE_NAME"}]
        )
        mock_session = MagicMock()

        result = fetch_shared_database(mock_session, FQN(name=ResourceName("GONG")))

        assert result == {
            "name": "GONG",
            "from_share": "PROVIDER_ACCOUNT.SHARE_NAME",
            "owner": "ACCOUNTADMIN",
        }

    @patch("snowcap.data_provider.execute")
    def test_reported_owner_is_ignored(self, mock_execute):
        # Even if the undocumented owner field is present with some other value, the
        # fetch reports the pinned ACCOUNTADMIN owner -- owner is non-fetchable on
        # SharedDatabase and never drift-tracked.
        mock_execute.return_value = self._mock_show_imported_databases(
            [{"name": "GONG", "origin": "PROVIDER_ACCOUNT.SHARE_NAME", "owner": "SOME_OTHER_ROLE"}]
        )
        mock_session = MagicMock()

        result = fetch_shared_database(mock_session, FQN(name=ResourceName("GONG")))

        assert result == {
            "name": "GONG",
            "from_share": "PROVIDER_ACCOUNT.SHARE_NAME",
            "owner": "ACCOUNTADMIN",
        }


def _imported_privileges_grant_fqn():
    return FQN(
        name=ResourceName("GRANT"),
        params={"priv": "IMPORTED PRIVILEGES", "on": "database/gong", "to": "role/gong_r"},
    )


def _grant_to_role_row(**overrides):
    row = {
        "created_on": "2024-01-01",
        "privilege": "USAGE",
        "granted_on": "DATABASE",
        "name": "GONG",
        "granted_to": "ROLE",
        "grantee_name": "GONG_R",
        "grant_option": "false",
        "granted_by": "ACCOUNTADMIN",
    }
    row.update(overrides)
    return row


class TestFetchGrantImportedPrivilegesQuirk:
    """Tests for fetch_grant's IMPORTED PRIVILEGES/USAGE reporting quirk on shared databases."""

    @patch("snowcap.data_provider._show_resources")
    @patch("snowcap.data_provider._show_grants_to_role")
    def test_matches_when_reported_as_usage_on_imported_database(self, mock_show_grants, mock_show_resources):
        mock_show_grants.return_value = [_grant_to_role_row(privilege="USAGE")]
        mock_show_resources.return_value = [_database_show_row(kind="IMPORTED DATABASE", name="GONG")]
        mock_session = MagicMock()

        result = fetch_grant(mock_session, _imported_privileges_grant_fqn())

        assert result is not None
        assert result["priv"] == "IMPORTED PRIVILEGES"

    @patch("snowcap.data_provider._show_resources")
    @patch("snowcap.data_provider._show_grants_to_role")
    def test_matches_when_reported_verbatim(self, mock_show_grants, mock_show_resources):
        mock_show_grants.return_value = [_grant_to_role_row(privilege="IMPORTED PRIVILEGES")]
        mock_session = MagicMock()

        result = fetch_grant(mock_session, _imported_privileges_grant_fqn())

        assert result is not None
        assert result["priv"] == "IMPORTED PRIVILEGES"
        # Exact match succeeded, so the USAGE fallback (and its kind check) never ran.
        mock_show_resources.assert_not_called()

    @patch("snowcap.data_provider._show_resources")
    @patch("snowcap.data_provider._show_grants_to_role")
    def test_returns_none_when_grant_genuinely_absent(self, mock_show_grants, mock_show_resources):
        mock_show_grants.return_value = []
        mock_show_resources.return_value = [_database_show_row(kind="IMPORTED DATABASE", name="GONG")]
        mock_session = MagicMock()

        result = fetch_grant(mock_session, _imported_privileges_grant_fqn())

        assert result is None

    @patch("snowcap.data_provider._show_resources")
    @patch("snowcap.data_provider._show_grants_to_role")
    def test_plain_usage_grant_on_regular_database_unaffected(self, mock_show_grants, mock_show_resources):
        mock_show_grants.return_value = [_grant_to_role_row(privilege="USAGE")]
        mock_session = MagicMock()
        fqn = FQN(
            name=ResourceName("GRANT"),
            params={"priv": "USAGE", "on": "database/gong", "to": "role/gong_r"},
        )

        result = fetch_grant(mock_session, fqn)

        assert result is not None
        assert result["priv"] == "USAGE"
        # Exact match succeeded for the requested privilege, so the imported-database
        # kind check (which only applies to the IMPORTED PRIVILEGES fallback) never ran.
        mock_show_resources.assert_not_called()

    @patch("snowcap.data_provider._show_resources")
    @patch("snowcap.data_provider._show_grants_to_role")
    def test_does_not_false_match_usage_on_regular_database(self, mock_show_grants, mock_show_resources):
        # A REGULAR database with a plain USAGE grant must not be mistaken for an
        # IMPORTED PRIVILEGES grant -- that would mask a genuine config error.
        mock_show_grants.return_value = [_grant_to_role_row(privilege="USAGE")]
        mock_show_resources.return_value = [_database_show_row(kind="STANDARD", name="GONG")]
        mock_session = MagicMock()

        result = fetch_grant(mock_session, _imported_privileges_grant_fqn())

        assert result is None


def _warehouse_show_row(**overrides):
    row = {
        "name": "WH",
        "owner": "SYSADMIN",
        "owner_role_type": "ROLE",
        "type": "STANDARD",
        "size": "X-SMALL",
        "auto_suspend": 600,
        "auto_resume": "true",
        "comment": "",
        "resource_monitor": "null",
    }
    row.update(overrides)
    return row


class TestFetchTask:
    """Tests for fetch_task round-trip."""

    @patch("snowcap.data_provider.execute")
    @patch("snowcap.data_provider._show_resources")
    def test_when_is_read_from_condition_column(self, mock_show_resources, mock_execute):
        """A task's WHEN lives in the SHOW TASKS 'condition' column; fetch must read it back,
        else a triggered task drifts 'MODIFY WHEN ...' on every apply."""
        mock_show_resources.return_value = [
            {
                "name": "T1",
                "warehouse": "",
                "schedule": "",
                "config": None,
                "allow_overlapping_execution": "false",
                "error_integration": "null",
                "success_integration": "null",
                "state": "suspended",
                "condition": "system$stream_has_data('dynamic_table_stream')",
                "target_completion_interval": "1 minutes",
                "owner": "SYSADMIN",
                "owner_role_type": "ROLE",
            }
        ]
        mock_execute.return_value = [
            {"task_relations": '{"Predecessors":[]}', "comment": None, "definition": "SELECT 1"}
        ]

        result = fetch_task(
            MagicMock(),
            FQN(name=ResourceName("T1"), database=ResourceName("DB"), schema=ResourceName("SCH")),
            include_params=False,
        )
        assert result["when"] == "system$stream_has_data('dynamic_table_stream')"

    @patch("snowcap.data_provider.execute")
    @patch("snowcap.data_provider._show_resources")
    def test_empty_condition_becomes_none(self, mock_show_resources, mock_execute):
        mock_show_resources.return_value = [
            {
                "name": "T1",
                "warehouse": "",
                "schedule": "",
                "config": None,
                "allow_overlapping_execution": "false",
                "error_integration": "null",
                "success_integration": "null",
                "state": "suspended",
                "condition": "",
                "target_completion_interval": "",
                "owner": "SYSADMIN",
                "owner_role_type": "ROLE",
            }
        ]
        mock_execute.return_value = [
            {"task_relations": '{"Predecessors":[]}', "comment": None, "definition": "SELECT 1"}
        ]

        result = fetch_task(
            MagicMock(),
            FQN(name=ResourceName("T1"), database=ResourceName("DB"), schema=ResourceName("SCH")),
            include_params=False,
        )
        assert result["when"] is None


class TestFetchWarehouse:
    """Tests for fetch_warehouse normalization."""

    @patch("snowcap.data_provider._show_resources")
    def test_fetches_generation_and_resource_constraint(self, mock_show_resources):
        mock_show_resources.return_value = [
            _warehouse_show_row(
                generation="2",
                resource_constraint="STANDARD_GEN_2",
                enable_query_acceleration="false",
                query_acceleration_max_scale_factor="8",
            )
        ]
        mock_session = MagicMock()

        result = fetch_warehouse(mock_session, FQN(name=ResourceName("WH")), include_params=False)

        assert result["generation"] == "2"
        assert result["resource_constraint"] == "STANDARD_GEN_2"
        assert result["enable_query_acceleration"] is False
        assert result["query_acceleration_max_scale_factor"] == "8"
        assert result["max_query_performance_level"] is None

    @patch("snowcap.data_provider._show_resources")
    def test_derives_standard_constraint_from_generation(self, mock_show_resources):
        mock_show_resources.return_value = [_warehouse_show_row(generation="2")]
        mock_session = MagicMock()

        result = fetch_warehouse(mock_session, FQN(name=ResourceName("WH")), include_params=False)

        assert result["generation"] == "2"
        assert result["resource_constraint"] == "STANDARD_GEN_2"
        assert result["max_query_performance_level"] is None

    @patch("snowcap.data_provider._show_resources")
    def test_derives_generation_from_standard_constraint(self, mock_show_resources):
        mock_show_resources.return_value = [_warehouse_show_row(resource_constraint="STANDARD_GEN_1")]
        mock_session = MagicMock()

        result = fetch_warehouse(mock_session, FQN(name=ResourceName("WH")), include_params=False)

        assert result["generation"] == "1"
        assert result["resource_constraint"] == "STANDARD_GEN_1"
        assert result["max_query_performance_level"] is None

    @patch("snowcap.data_provider._show_resources")
    def test_treats_null_and_missing_generation_fields_as_none(self, mock_show_resources):
        mock_show_resources.return_value = [
            _warehouse_show_row(
                generation="null",
                resource_constraint="",
                enable_query_acceleration="null",
                query_acceleration_max_scale_factor="null",
            )
        ]
        mock_session = MagicMock()

        result = fetch_warehouse(mock_session, FQN(name=ResourceName("WH")), include_params=False)

        assert result["generation"] is None
        assert result["resource_constraint"] is None
        assert result["enable_query_acceleration"] is None
        assert result["query_acceleration_max_scale_factor"] is None
        assert result["max_query_performance_level"] is None

    @patch("snowcap.data_provider._show_resources")
    def test_preserves_snowpark_memory_constraint(self, mock_show_resources):
        mock_show_resources.return_value = [
            _warehouse_show_row(
                type="SNOWPARK-OPTIMIZED",
                size="X-SMALL",
                resource_constraint="MEMORY_16X_x86",
            )
        ]
        mock_session = MagicMock()

        result = fetch_warehouse(mock_session, FQN(name=ResourceName("WH")), include_params=False)

        assert result["warehouse_type"] == "SNOWPARK-OPTIMIZED"
        assert result["generation"] is None
        assert result["resource_constraint"] == "MEMORY_16X_X86"
        assert result["max_query_performance_level"] is None

    @patch("snowcap.data_provider._show_resources")
    def test_fetch_warehouse_adaptive(self, mock_show_resources):
        mock_show_resources.return_value = [
            _warehouse_show_row(
                type="ADAPTIVE",
                size="",
                max_query_performance_level="LARGE",
                query_throughput_multiplier=2,
                max_cluster_count=4,
                min_cluster_count=2,
                scaling_policy="ECONOMY",
            )
        ]
        mock_session = MagicMock()

        result = fetch_warehouse(mock_session, FQN(name=ResourceName("WH")), include_params=False)

        assert result["warehouse_type"] == "ADAPTIVE"
        assert result["max_query_performance_level"] == "LARGE"
        assert result["query_throughput_multiplier"] == 2
        for field_name in ADAPTIVE_UNSUPPORTED_FIELDS:
            assert result.get(field_name) is None, field_name

    @patch("snowcap.data_provider._show_resources")
    def test_fetch_warehouse_adaptive_missing_columns(self, mock_show_resources):
        # Stale SHOW WAREHOUSES output that lacks the adaptive-only columns entirely.
        mock_show_resources.return_value = [_warehouse_show_row(type="ADAPTIVE", size="")]
        mock_session = MagicMock()

        result = fetch_warehouse(mock_session, FQN(name=ResourceName("WH")), include_params=False)

        assert result["max_query_performance_level"] is None
        assert result["warehouse_size"] is None
        assert result["query_throughput_multiplier"] is None

    @patch("snowcap.data_provider._show_resources")
    def test_fetch_warehouse_adaptive_size_does_not_raise(self, mock_show_resources):
        mock_show_resources.return_value = [_warehouse_show_row(type="ADAPTIVE", size="null")]
        mock_session = MagicMock()

        result = fetch_warehouse(mock_session, FQN(name=ResourceName("WH")), include_params=False)

        assert result["warehouse_size"] is None

    @patch("snowcap.data_provider._show_resources")
    def test_fetch_warehouse_adaptive_round_trip(self, mock_show_resources):
        # No spurious drift: a declared ADAPTIVE spec fed through SHOW WAREHOUSES output for the
        # same warehouse must fetch back to matching values on every field it sets.
        warehouse = res.Warehouse(
            name="WH",
            warehouse_type="ADAPTIVE",
            max_query_performance_level="LARGE",
            comment="adaptive warehouse",
        )
        spec_dict = warehouse.to_dict()

        mock_show_resources.return_value = [
            _warehouse_show_row(
                type="ADAPTIVE",
                size="",
                max_query_performance_level="LARGE",
                comment="adaptive warehouse",
            )
        ]
        mock_session = MagicMock()

        result = fetch_warehouse(mock_session, FQN(name=ResourceName("WH")), include_params=False)

        # initially_suspended is metadata={"fetchable": False} -- SHOW WAREHOUSES has no such
        # column, so fetch_warehouse never returns it.
        for field_name, value in spec_dict.items():
            if field_name == "initially_suspended":
                continue
            assert result[field_name] == value, field_name
        assert result["query_throughput_multiplier"] is None

    @patch("snowcap.data_provider.execute")
    @patch("snowcap.data_provider._show_resources")
    def test_fetch_warehouse_adaptive_params_omit_max_concurrency_level(self, mock_show_resources, mock_execute):
        # Live ADAPTIVE warehouses return exactly these four parameters from SHOW
        # PARAMETERS; max_concurrency_level is absent (issue #55), so an unconditional
        # params["max_concurrency_level"] read raises KeyError.
        mock_show_resources.return_value = [_warehouse_show_row(type="ADAPTIVE", size="")]
        mock_execute.return_value = [
            {"key": "ENABLE_USE_STABLE_PATH", "value": "true", "type": "BOOLEAN"},
            {"key": "FALLBACK_WAREHOUSE", "value": "", "type": "STRING"},
            {"key": "STATEMENT_QUEUED_TIMEOUT_IN_SECONDS", "value": "0", "type": "NUMBER"},
            {"key": "STATEMENT_TIMEOUT_IN_SECONDS", "value": "172800", "type": "NUMBER"},
        ]
        mock_session = MagicMock()

        result = fetch_warehouse(mock_session, FQN(name=ResourceName("WH")), include_params=True)

        assert result["max_concurrency_level"] is None
        assert result["statement_queued_timeout_in_seconds"] == 0
        assert result["statement_timeout_in_seconds"] == 172800


def _security_integration_show_row(**overrides):
    row = {
        "name": "CUSTOM_OAUTH",
        "type": "OAUTH - CUSTOM",
        "enabled": "true",
        "comment": "",
    }
    row.update(overrides)
    return row


def _custom_oauth_desc_rows(blocked_roles_list="[]", pre_authorized_roles_list="[]"):
    def row(property, value, property_type):
        return {"property": property, "property_value": value, "property_type": property_type}

    return [
        row("OAUTH_CLIENT_TYPE", "CONFIDENTIAL", "String"),
        row("OAUTH_REDIRECT_URI", "https://example.com/callback", "String"),
        row("OAUTH_ALLOW_NON_TLS_REDIRECT_URI", "false", "Boolean"),
        row("OAUTH_ISSUE_REFRESH_TOKENS", "true", "Boolean"),
        row("OAUTH_REFRESH_TOKEN_VALIDITY", "7776000", "Long"),
        row("OAUTH_SINGLE_USE_REFRESH_TOKENS_REQUIRED", "false", "Boolean"),
        row("OAUTH_USE_SECONDARY_ROLES", "NONE", "String"),
        row("OAUTH_ANY_ROLE_MODE", "DISABLE", "String"),
        row("OAUTH_ENFORCE_PKCE", "false", "Boolean"),
        row("NETWORK_POLICY", "", "String"),
        row("PRE_AUTHORIZED_ROLES_LIST", pre_authorized_roles_list, "List"),
        row("BLOCKED_ROLES_LIST", blocked_roles_list, "List"),
    ]


class TestFetchSecurityIntegration:
    """Tests for fetch_security_integration's OAUTH branch."""

    def _mock_execute(self, desc_rows, show_row=None):
        show_row = show_row or _security_integration_show_row()

        def execute(session, sql, cacheable=False):
            if sql.startswith("SHOW SECURITY INTEGRATIONS"):
                return [show_row]
            return desc_rows

        return execute

    @patch("snowcap.data_provider._fetch_owner")
    @patch("snowcap.data_provider.execute")
    def test_custom_oauth_admin_only_blocked_roles_normalizes_to_none(self, mock_execute, mock_fetch_owner):
        mock_fetch_owner.return_value = "ACCOUNTADMIN"
        mock_execute.side_effect = self._mock_execute(
            _custom_oauth_desc_rows(blocked_roles_list="[ACCOUNTADMIN, SECURITYADMIN]")
        )

        result = fetch_security_integration(MagicMock(), FQN(name=ResourceName("CUSTOM_OAUTH")))

        assert result["blocked_roles_list"] is None

    @patch("snowcap.data_provider._fetch_owner")
    @patch("snowcap.data_provider.execute")
    def test_custom_oauth_blocked_roles_strips_admin_roles(self, mock_execute, mock_fetch_owner):
        mock_fetch_owner.return_value = "ACCOUNTADMIN"
        mock_execute.side_effect = self._mock_execute(
            _custom_oauth_desc_rows(blocked_roles_list="[ACCOUNTADMIN, SECURITYADMIN, SYSADMIN]")
        )

        result = fetch_security_integration(MagicMock(), FQN(name=ResourceName("CUSTOM_OAUTH")))

        assert result["blocked_roles_list"] == ["SYSADMIN"]

    @patch("snowcap.data_provider._fetch_owner")
    @patch("snowcap.data_provider.execute")
    def test_custom_oauth_blocked_roles_sorted_regardless_of_desc_order(self, mock_execute, mock_fetch_owner):
        mock_fetch_owner.return_value = "ACCOUNTADMIN"
        mock_execute.side_effect = self._mock_execute(
            _custom_oauth_desc_rows(blocked_roles_list="[SECURITYADMIN, SYSADMIN, ACCOUNTADMIN, ANALYST]")
        )

        result = fetch_security_integration(MagicMock(), FQN(name=ResourceName("CUSTOM_OAUTH")))

        assert result["blocked_roles_list"] == ["ANALYST", "SYSADMIN"]

    @patch("snowcap.data_provider._fetch_owner")
    @patch("snowcap.data_provider.execute")
    def test_custom_oauth_quoted_roles_canonicalized_like_spec(self, mock_execute, mock_fetch_owner):
        """A quoted, case-sensitive role from DESC must canonicalize exactly like the
        spec side (_canonicalize_role_name), or it would drift on every plan."""
        mock_fetch_owner.return_value = "ACCOUNTADMIN"
        mock_execute.side_effect = self._mock_execute(
            _custom_oauth_desc_rows(
                blocked_roles_list='[ACCOUNTADMIN, "my_role", SYSADMIN]',
                pre_authorized_roles_list='["my_role", ANALYST]',
            )
        )

        result = fetch_security_integration(MagicMock(), FQN(name=ResourceName("CUSTOM_OAUTH")))

        # The quote characters are stripped and the case-sensitive name keeps its case,
        # matching what the spec produces for blocked_roles_list=['"my_role"', ...].
        assert result["blocked_roles_list"] == ["SYSADMIN", "my_role"]
        assert result["pre_authorized_roles_list"] == ["ANALYST", "my_role"]

    @patch("snowcap.data_provider._fetch_owner")
    @patch("snowcap.data_provider.execute")
    def test_custom_oauth_lowercase_roles_canonicalized_like_spec(self, mock_execute, mock_fetch_owner):
        """An unquoted role from DESC is uppercased, matching the spec side."""
        mock_fetch_owner.return_value = "ACCOUNTADMIN"
        mock_execute.side_effect = self._mock_execute(
            _custom_oauth_desc_rows(blocked_roles_list="[ACCOUNTADMIN, sysadmin]")
        )

        result = fetch_security_integration(MagicMock(), FQN(name=ResourceName("CUSTOM_OAUTH")))

        assert result["blocked_roles_list"] == ["SYSADMIN"]

    @patch("snowcap.data_provider._fetch_owner")
    @patch("snowcap.data_provider.execute")
    def test_custom_oauth_empty_pre_authorized_roles_normalizes_to_none(self, mock_execute, mock_fetch_owner):
        mock_fetch_owner.return_value = "ACCOUNTADMIN"
        mock_execute.side_effect = self._mock_execute(_custom_oauth_desc_rows())

        result = fetch_security_integration(MagicMock(), FQN(name=ResourceName("CUSTOM_OAUTH")))

        assert result["pre_authorized_roles_list"] is None
        assert result["oauth_client"] == "CUSTOM"
        assert result["oauth_refresh_token_validity"] == 7776000
        assert result["network_policy"] is None

    @patch("snowcap.data_provider._fetch_owner")
    @patch("snowcap.data_provider.execute")
    def test_custom_oauth_omitted_refresh_token_validity_degrades_to_none(self, mock_execute, mock_fetch_owner):
        """If DESC omits OAUTH_REFRESH_TOKEN_VALIDITY, fetch must return None
        instead of raising KeyError, like every sibling field."""
        mock_fetch_owner.return_value = "ACCOUNTADMIN"
        desc_rows = [row for row in _custom_oauth_desc_rows() if row["property"] != "OAUTH_REFRESH_TOKEN_VALIDITY"]
        mock_execute.side_effect = self._mock_execute(desc_rows)

        result = fetch_security_integration(MagicMock(), FQN(name=ResourceName("CUSTOM_OAUTH")))

        assert result["oauth_refresh_token_validity"] is None

    @patch("snowcap.data_provider._fetch_owner")
    @patch("snowcap.data_provider.execute")
    def test_snowservices_ingress_still_fetches_as_before(self, mock_execute, mock_fetch_owner):
        mock_fetch_owner.return_value = "ACCOUNTADMIN"
        mock_execute.side_effect = self._mock_execute(
            desc_rows=[],
            show_row=_security_integration_show_row(name="SNOWSERVICES", type="OAUTH - SNOWSERVICES_INGRESS"),
        )

        result = fetch_security_integration(MagicMock(), FQN(name=ResourceName("SNOWSERVICES")))

        assert result == {
            "name": "SNOWSERVICES",
            "type": "OAUTH",
            "oauth_client": "SNOWSERVICES_INGRESS",
            "enabled": True,
            "owner": "ACCOUNTADMIN",
        }

    @patch("snowcap.data_provider._fetch_owner")
    @patch("snowcap.data_provider.execute")
    def test_custom_oauth_new_fields_round_trip(self, mock_execute, mock_fetch_owner):
        """The serverless-OAuth toggles read back from DESC so they don't drift on every plan."""
        mock_fetch_owner.return_value = "ACCOUNTADMIN"
        mock_execute.side_effect = self._mock_execute(_custom_oauth_desc_rows())

        result = fetch_security_integration(MagicMock(), FQN(name=ResourceName("CUSTOM_OAUTH")))

        assert result["oauth_allow_non_tls_redirect_uri"] is False
        assert result["oauth_single_use_refresh_tokens_required"] is False
        assert result["oauth_any_role_mode"] == "DISABLE"
        # oauth_enable_role_selection is CREATE-only (not in DESC), so fetch omits it.
        assert "oauth_enable_role_selection" not in result

    @patch("snowcap.data_provider._fetch_owner")
    @patch("snowcap.data_provider.execute")
    def test_unmodeled_type_returns_none_with_warning(self, mock_execute, mock_fetch_owner, caplog):
        """A type snowcap doesn't model (e.g. SAML2) must not raise: it would break list/export
        whenever the account holds one. Return None and warn instead."""
        mock_fetch_owner.return_value = "ACCOUNTADMIN"
        mock_execute.side_effect = self._mock_execute(
            desc_rows=[],
            show_row=_security_integration_show_row(name="MY_SAML", type="SAML2"),
        )

        with caplog.at_level("WARNING", logger="snowcap"):
            result = fetch_security_integration(MagicMock(), FQN(name=ResourceName("MY_SAML")))

        assert result is None
        assert "unsupported security integration type" in caplog.text.lower()

    @patch("snowcap.data_provider._fetch_owner")
    @patch("snowcap.data_provider.execute")
    def test_partner_oauth_still_raises(self, mock_execute, mock_fetch_owner):
        """Partner OAuth is modeled/declarable but not fetchable, so it must still raise:
        returning None would make a declared partner integration look absent and churn a CREATE."""
        mock_fetch_owner.return_value = "ACCOUNTADMIN"
        mock_execute.side_effect = self._mock_execute(
            desc_rows=[],
            show_row=_security_integration_show_row(name="TABLEAU", type="OAUTH - TABLEAU_DESKTOP"),
        )

        with pytest.raises(Exception, match="cannot read back partner OAuth"):
            fetch_security_integration(MagicMock(), FQN(name=ResourceName("TABLEAU")))


class TestListResource:
    """Tests for list_resource dispatcher function."""

    @patch("snowcap.data_provider.list_databases")
    def test_dispatches_to_correct_list_function(self, mock_list_databases):
        mock_list_databases.return_value = [FQN(name=ResourceName("DB1")), FQN(name=ResourceName("DB2"))]
        mock_session = MagicMock()

        result = list_resource(mock_session, "database")

        mock_list_databases.assert_called_once_with(mock_session)
        assert len(result) == 2

    @patch("snowcap.data_provider.list_schemas")
    def test_dispatches_to_schemas_list(self, mock_list_schemas):
        mock_list_schemas.return_value = [FQN(database=ResourceName("DB1"), name=ResourceName("S1"))]
        mock_session = MagicMock()

        result = list_resource(mock_session, "schema")

        mock_list_schemas.assert_called_once_with(mock_session)
        assert len(result) == 1

    @patch("snowcap.data_provider.list_tables")
    def test_pluralizes_resource_label(self, mock_list_tables):
        mock_list_tables.return_value = []
        mock_session = MagicMock()

        list_resource(mock_session, "table")

        mock_list_tables.assert_called_once()


class TestListAccountScopedResource:
    """Tests for list_account_scoped_resource helper function."""

    @patch("snowcap.data_provider.execute")
    def test_lists_account_scoped_resources(self, mock_execute):
        mock_execute.return_value = [
            {"name": "RESOURCE1"},
            {"name": "RESOURCE2"},
        ]
        mock_session = MagicMock()

        result = list_account_scoped_resource(mock_session, "WAREHOUSES")

        mock_execute.assert_called_once_with(mock_session, "SHOW WAREHOUSES", cacheable=True)
        assert len(result) == 2
        assert str(result[0].name) == "RESOURCE1"
        assert str(result[1].name) == "RESOURCE2"


class TestListSchemaScopedResource:
    """Tests for list_schema_scoped_resource helper function."""

    @patch("snowcap.data_provider.execute")
    def test_lists_schema_scoped_resources(self, mock_execute):
        mock_execute.return_value = [
            {"name": "TABLE1", "database_name": "DB1", "schema_name": "SCHEMA1"},
            {"name": "TABLE2", "database_name": "DB1", "schema_name": "SCHEMA1"},
        ]
        mock_session = MagicMock()

        result = list_schema_scoped_resource(mock_session, "TABLES")

        mock_execute.assert_called_once_with(mock_session, "SHOW TABLES IN ACCOUNT", cacheable=True)
        assert len(result) == 2

    @patch("snowcap.data_provider.execute")
    def test_filters_system_databases(self, mock_execute):
        mock_execute.return_value = [
            {"name": "TABLE1", "database_name": "MY_DB", "schema_name": "SCHEMA1"},
            {"name": "SYS_TABLE", "database_name": "SNOWFLAKE", "schema_name": "ACCOUNT_USAGE"},
        ]
        mock_session = MagicMock()

        result = list_schema_scoped_resource(mock_session, "TABLES")

        assert len(result) == 1
        assert str(result[0].database) == "MY_DB"


class TestFetchAccountLocator:
    """Tests for fetch_account_locator function."""

    @patch("snowcap.data_provider.execute")
    def test_returns_account_locator(self, mock_execute):
        mock_execute.return_value = [{"ACCOUNT_LOCATOR": "ABC123"}]
        mock_session = MagicMock()

        result = fetch_account_locator(mock_session)

        assert result == "ABC123"


class TestFetchRegion:
    """Tests for fetch_region function."""

    @patch("snowcap.data_provider.execute")
    def test_returns_region(self, mock_execute):
        mock_execute.return_value = [{"CURRENT_REGION()": "AWS_US_WEST_2"}]
        mock_session = MagicMock()

        result = fetch_region(mock_session)

        assert result == {"CURRENT_REGION()": "AWS_US_WEST_2"}


# ================================
# ACCOUNT_USAGE Unit Tests
# ================================


class TestHasAccountUsageAccess:
    """Tests for _has_account_usage_access function."""

    @patch("snowcap.data_provider.execute")
    def test_returns_true_when_access_granted(self, mock_execute):
        """When ACCOUNT_USAGE query succeeds, function returns True."""
        from snowcap.data_provider import _has_account_usage_access

        mock_execute.return_value = [{"1": 1}]  # Query succeeds
        mock_session = MagicMock()

        result = _has_account_usage_access(mock_session)

        assert result is True
        mock_execute.assert_called_once()
        assert "SNOWFLAKE.ACCOUNT_USAGE.GRANTS_TO_ROLES" in mock_execute.call_args[0][1]

    @patch("snowcap.data_provider.execute")
    def test_returns_false_on_access_control_error(self, mock_execute):
        """When ACCOUNT_USAGE query fails with ACCESS_CONTROL_ERR, returns False."""
        from snowflake.connector.errors import ProgrammingError
        from snowcap.data_provider import _has_account_usage_access
        from snowcap.client import ACCESS_CONTROL_ERR

        mock_execute.side_effect = ProgrammingError(errno=ACCESS_CONTROL_ERR)
        mock_session = MagicMock()

        result = _has_account_usage_access(mock_session)

        assert result is False

    @patch("snowcap.data_provider.execute")
    def test_raises_on_other_programming_errors(self, mock_execute):
        """Other ProgrammingErrors should be re-raised."""
        from snowflake.connector.errors import ProgrammingError
        from snowcap.data_provider import _has_account_usage_access

        mock_execute.side_effect = ProgrammingError(errno=1234)
        mock_session = MagicMock()

        with pytest.raises(ProgrammingError):
            _has_account_usage_access(mock_session)

    @patch("snowcap.data_provider.execute")
    def test_caches_result_per_session(self, mock_execute):
        """Result should be cached per session to avoid repeated queries."""
        from snowcap.data_provider import _has_account_usage_access

        mock_execute.return_value = [{"1": 1}]
        mock_session = MagicMock()

        # First call
        result1 = _has_account_usage_access(mock_session)
        # Second call - should use cache
        result2 = _has_account_usage_access(mock_session)

        assert result1 is True
        assert result2 is True
        # Should only be called once due to caching
        assert mock_execute.call_count == 1

    @patch("snowcap.data_provider.execute")
    def test_different_sessions_have_independent_cache(self, mock_execute):
        """Different sessions should have independent cache entries."""
        from snowcap.data_provider import _has_account_usage_access

        mock_execute.return_value = [{"1": 1}]
        session1 = MagicMock()
        session2 = MagicMock()

        _has_account_usage_access(session1)
        _has_account_usage_access(session2)

        # Both sessions should trigger their own query
        assert mock_execute.call_count == 2


class TestFetchGrantsFromAccountUsage:
    """Tests for _fetch_grants_from_account_usage function."""

    @patch("snowcap.data_provider.execute")
    def test_returns_normalized_grants(self, mock_execute):
        """Grants should be normalized to match SHOW GRANTS structure."""
        from snowcap.data_provider import _fetch_grants_from_account_usage
        from datetime import datetime

        mock_execute.return_value = [
            {
                "CREATED_ON": datetime(2024, 1, 1, 12, 0, 0),
                "PRIVILEGE": "SELECT",
                "GRANTED_ON": "TABLE",
                "NAME": "MY_DB.MY_SCHEMA.MY_TABLE",
                "GRANTED_TO": "ACCOUNT ROLE",
                "GRANTEE_NAME": "MY_ROLE",
                "GRANT_OPTION": True,
                "GRANTED_BY": "SYSADMIN",
            }
        ]
        mock_session = MagicMock()

        result = _fetch_grants_from_account_usage(mock_session)

        assert result is not None
        assert len(result) == 1
        grant = result[0]
        # Check lowercase keys
        assert "privilege" in grant
        assert "granted_on" in grant
        # Check ACCOUNT ROLE -> ROLE conversion
        assert grant["granted_to"] == "ROLE"
        # Check boolean -> string conversion
        assert grant["grant_option"] == "true"

    @patch("snowcap.data_provider.execute")
    def test_converts_database_role_granted_to(self, mock_execute):
        """DATABASE_ROLE should be converted to DATABASE ROLE."""
        from snowcap.data_provider import _fetch_grants_from_account_usage
        from datetime import datetime

        mock_execute.return_value = [
            {
                "CREATED_ON": datetime(2024, 1, 1, 12, 0, 0),
                "PRIVILEGE": "USAGE",
                "GRANTED_ON": "DATABASE",
                "NAME": "MY_DB",
                "GRANTED_TO": "DATABASE_ROLE",
                "GRANTEE_NAME": "MY_DB.MY_DB_ROLE",
                "GRANT_OPTION": False,
                "GRANTED_BY": "SYSADMIN",
            }
        ]
        mock_session = MagicMock()

        result = _fetch_grants_from_account_usage(mock_session)

        assert result is not None
        assert result[0]["granted_to"] == "DATABASE ROLE"
        assert result[0]["grant_option"] == "false"

    @patch("snowcap.data_provider.execute")
    def test_returns_none_on_access_control_error(self, mock_execute):
        """Returns None on permission error (signaling fallback needed)."""
        from snowflake.connector.errors import ProgrammingError
        from snowcap.data_provider import _fetch_grants_from_account_usage
        from snowcap.client import ACCESS_CONTROL_ERR

        mock_execute.side_effect = ProgrammingError(errno=ACCESS_CONTROL_ERR)
        mock_session = MagicMock()

        result = _fetch_grants_from_account_usage(mock_session)

        assert result is None

    @patch("snowcap.data_provider.execute")
    def test_returns_none_on_unexpected_error(self, mock_execute):
        """Returns None on unexpected error (signaling fallback needed)."""
        from snowcap.data_provider import _fetch_grants_from_account_usage

        mock_execute.side_effect = Exception("Unexpected error")
        mock_session = MagicMock()

        result = _fetch_grants_from_account_usage(mock_session)

        assert result is None

    @patch("snowcap.data_provider.execute")
    def test_marks_fallback_on_error(self, mock_execute):
        """On error, should mark fallback cache for this session."""
        from snowcap.data_provider import (
            _fetch_grants_from_account_usage,
            _ACCOUNT_USAGE_FALLBACK_CACHE,
        )

        mock_execute.side_effect = Exception("Unexpected error")
        mock_session = MagicMock()

        _fetch_grants_from_account_usage(mock_session)

        # Fallback should be marked
        assert _ACCOUNT_USAGE_FALLBACK_CACHE.get(id(mock_session)) is True


class TestFetchRoleGrantsToUsersFromAccountUsage:
    """Tests for _fetch_role_grants_to_users_from_account_usage function."""

    @patch("snowcap.data_provider.execute")
    def test_returns_normalized_user_grants(self, mock_execute):
        """User grants should be normalized to match SHOW GRANTS OF ROLE structure."""
        from snowcap.data_provider import _fetch_role_grants_to_users_from_account_usage
        from datetime import datetime

        mock_execute.return_value = [
            {
                "CREATED_ON": datetime(2024, 1, 1, 12, 0, 0),
                "ROLE": "MY_ROLE",
                "GRANTED_TO": "USER",
                "GRANTEE_NAME": "MY_USER",
                "GRANTED_BY": "SECURITYADMIN",
            }
        ]
        mock_session = MagicMock()

        result = _fetch_role_grants_to_users_from_account_usage(mock_session)

        assert result is not None
        assert len(result) == 1
        grant = result[0]
        assert "role" in grant
        assert grant["role"] == "MY_ROLE"
        assert grant["granted_to"] == "USER"
        assert grant["grantee_name"] == "MY_USER"

    @patch("snowcap.data_provider.execute")
    def test_returns_none_on_error(self, mock_execute):
        """Returns None on error (signaling fallback needed)."""
        from snowcap.data_provider import _fetch_role_grants_to_users_from_account_usage

        mock_execute.side_effect = Exception("Unexpected error")
        mock_session = MagicMock()

        result = _fetch_role_grants_to_users_from_account_usage(mock_session)

        assert result is None


class TestShouldUseAccountUsage:
    """Tests for _should_use_account_usage helper function."""

    @patch("snowcap.data_provider._has_account_usage_access")
    def test_returns_false_when_config_disabled(self, mock_has_access):
        """Returns False when use_account_usage config is False."""
        from snowcap.data_provider import _should_use_account_usage

        mock_session = MagicMock()

        result = _should_use_account_usage(mock_session, use_account_usage=False)

        assert result is False
        # Should not even check access when config is disabled
        mock_has_access.assert_not_called()

    @patch("snowcap.data_provider._has_account_usage_access")
    def test_returns_false_when_fallback_cached(self, mock_has_access):
        """Returns False when session has previous ACCOUNT_USAGE failures."""
        from snowcap.data_provider import (
            _should_use_account_usage,
            _ACCOUNT_USAGE_FALLBACK_CACHE,
        )

        mock_session = MagicMock()
        _ACCOUNT_USAGE_FALLBACK_CACHE[id(mock_session)] = True

        result = _should_use_account_usage(mock_session, use_account_usage=True)

        assert result is False
        # Should not check access when fallback is cached
        mock_has_access.assert_not_called()

    @patch("snowcap.data_provider._has_account_usage_access")
    def test_returns_access_check_result_when_enabled(self, mock_has_access):
        """Returns result of _has_account_usage_access when config is enabled."""
        from snowcap.data_provider import _should_use_account_usage

        mock_session = MagicMock()
        mock_has_access.return_value = True

        result = _should_use_account_usage(mock_session, use_account_usage=True)

        assert result is True
        mock_has_access.assert_called_once_with(mock_session)

    @patch("snowcap.data_provider._has_account_usage_access")
    def test_returns_false_when_no_access(self, mock_has_access):
        """Returns False when session doesn't have ACCOUNT_USAGE access."""
        from snowcap.data_provider import _should_use_account_usage

        mock_session = MagicMock()
        mock_has_access.return_value = False

        result = _should_use_account_usage(mock_session, use_account_usage=True)

        assert result is False


class TestMarkAccountUsageFallback:
    """Tests for _mark_account_usage_fallback function."""

    def test_marks_session_for_fallback(self):
        """Should mark session ID in fallback cache."""
        from snowcap.data_provider import (
            _mark_account_usage_fallback,
            _ACCOUNT_USAGE_FALLBACK_CACHE,
        )

        mock_session = MagicMock()

        _mark_account_usage_fallback(mock_session)

        assert _ACCOUNT_USAGE_FALLBACK_CACHE.get(id(mock_session)) is True


class TestFetchRolePrivilegesAccountUsage:
    """Tests for fetch_role_privileges with ACCOUNT_USAGE integration."""

    @patch("snowcap.data_provider._should_use_account_usage")
    @patch("snowcap.data_provider._fetch_grants_from_account_usage")
    @patch("snowcap.data_provider._show_grants_to_role")
    def test_uses_account_usage_when_enabled_and_available(self, mock_show_grants, mock_fetch_au, mock_should_use):
        """When ACCOUNT_USAGE is enabled and available, uses ACCOUNT_USAGE."""
        from snowcap.data_provider import fetch_role_privileges
        from datetime import datetime

        mock_should_use.return_value = True
        mock_fetch_au.return_value = [
            {
                "created_on": datetime(2024, 1, 1, 12, 0, 0),
                "privilege": "USAGE",
                "granted_on": "DATABASE",
                "name": "MY_DB",
                "granted_to": "ROLE",
                "grantee_name": "MY_ROLE",
                "grant_option": "false",
                "granted_by": "SYSADMIN",
            }
        ]
        mock_session = MagicMock()
        roles = {"MY_ROLE": MagicMock()}

        result = fetch_role_privileges(mock_session, roles, use_account_usage=True)

        mock_should_use.assert_called_once()
        mock_fetch_au.assert_called_once()
        # SHOW GRANTS should not be called when ACCOUNT_USAGE succeeds
        mock_show_grants.assert_not_called()
        assert "MY_ROLE" in result

    @patch("snowcap.data_provider._should_use_account_usage")
    @patch("snowcap.data_provider._show_grants_to_role")
    def test_falls_back_to_show_when_disabled(self, mock_show_grants, mock_should_use):
        """When ACCOUNT_USAGE is disabled, uses SHOW GRANTS."""
        from snowcap.data_provider import fetch_role_privileges

        mock_should_use.return_value = False
        mock_show_grants.return_value = []
        mock_session = MagicMock()
        roles = {"MY_ROLE": MagicMock()}

        fetch_role_privileges(mock_session, roles, use_account_usage=False)

        mock_show_grants.assert_called()

    @patch("snowcap.data_provider._should_use_account_usage")
    @patch("snowcap.data_provider._fetch_grants_from_account_usage")
    @patch("snowcap.data_provider._show_grants_to_role")
    def test_falls_back_when_account_usage_returns_none(self, mock_show_grants, mock_fetch_au, mock_should_use):
        """When ACCOUNT_USAGE query fails (returns None), falls back to SHOW."""
        from snowcap.data_provider import fetch_role_privileges

        mock_should_use.return_value = True
        mock_fetch_au.return_value = None  # Signals failure
        mock_show_grants.return_value = []
        mock_session = MagicMock()
        roles = {"MY_ROLE": MagicMock()}

        fetch_role_privileges(mock_session, roles, use_account_usage=True)

        # Both should be called - ACCOUNT_USAGE first, then fallback
        mock_fetch_au.assert_called_once()
        mock_show_grants.assert_called()


class TestBlueprintConfigUseAccountUsage:
    """Tests for use_account_usage config flag in BlueprintConfig."""

    def test_default_is_false(self):
        """use_account_usage should default to False for performance (small manifests)."""
        from snowcap.blueprint_config import BlueprintConfig

        config = BlueprintConfig()

        assert config.use_account_usage is False

    def test_can_be_set_to_false(self):
        """use_account_usage can be explicitly set to False."""
        from snowcap.blueprint_config import BlueprintConfig

        config = BlueprintConfig(use_account_usage=False)

        assert config.use_account_usage is False


def _streamlit_show_row(**overrides):
    row = {
        "name": "MY_APP",
        "owner": "SYSADMIN",
        "owner_role_type": "ROLE",
        "query_warehouse": "MY_WH",
        "comment": "",
    }
    row.update(overrides)
    return row


class TestFetchStreamlit:
    """Tests for fetch_streamlit normalization."""

    @patch("snowcap.data_provider.execute")
    @patch("snowcap.data_provider._show_resources")
    def test_maps_default_main_file_and_omits_from(self, mock_show_resources, mock_execute):
        mock_show_resources.return_value = [_streamlit_show_row()]
        # DESC STREAMLIT returns the Snowflake default main_file plus a title.
        mock_execute.return_value = [{"main_file": "streamlit_app.py", "title": "My App"}]

        result = fetch_streamlit(MagicMock(), FQN(name=ResourceName("MY_APP")))

        # Default main_file collapses to None so an omitted field doesn't drift.
        assert result["main_file"] is None
        assert result["title"] == "My App"
        assert result["query_warehouse"] == "MY_WH"
        # from_ and version are non-fetchable / not comparable -> never returned.
        assert "from_" not in result
        assert result["version"] is None

    @patch("snowcap.data_provider.execute")
    @patch("snowcap.data_provider._show_resources")
    def test_keeps_non_default_main_file(self, mock_show_resources, mock_execute):
        mock_show_resources.return_value = [_streamlit_show_row()]
        mock_execute.return_value = [{"main_file": "app.py", "title": None}]

        result = fetch_streamlit(MagicMock(), FQN(name=ResourceName("MY_APP")))

        assert result["main_file"] == "app.py"
        assert result["title"] is None

    @patch("snowcap.data_provider.execute")
    @patch("snowcap.data_provider._show_resources")
    def test_empty_desc_result_does_not_raise(self, mock_show_resources, mock_execute):
        mock_show_resources.return_value = [_streamlit_show_row()]
        # An empty DESC result must not IndexError.
        mock_execute.return_value = []

        result = fetch_streamlit(MagicMock(), FQN(name=ResourceName("MY_APP")))

        assert result["main_file"] is None
        assert result["title"] is None
        assert result["name"] == "MY_APP"

    @patch("snowcap.data_provider._show_resources")
    def test_missing_streamlit_returns_none(self, mock_show_resources):
        mock_show_resources.return_value = []

        assert fetch_streamlit(MagicMock(), FQN(name=ResourceName("MY_APP"))) is None


class TestInheritedGrants:
    """
    Tests for how Snowcap reads inherited grants (GRANT INHERITED ...) from remote state.

    Inherited grants are container-level grants that apply to every current and future
    object of a type in a container. Snowflake reports them in SHOW GRANTS and
    ACCOUNT_USAGE.GRANTS_TO_ROLES with IS_INHERITED set, an empty NAME, and the container
    in the INHERITED_FROM columns. They are kept apart from object grants throughout, since
    an inherited grant is revoked with REVOKE INHERITED against its container rather than
    with a per-object REVOKE.
    """

    def _inherited_row(self, **overrides):
        row = {
            "privilege": "SELECT",
            "granted_on": "TABLE",
            "name": "",
            "granted_to": "ROLE",
            "grantee_name": "MY_ROLE",
            "grant_option": "false",
            "granted_by": "SECURITYADMIN",
            "is_inherited": "true",
            "inherited_from": "DATABASE",
            "inherited_from_database": "MY_DB",
            "inherited_from_schema": "",
        }
        row.update(overrides)
        return row

    def _regular_row(self, **overrides):
        row = {
            "privilege": "SELECT",
            "granted_on": "TABLE",
            "name": "MY_DB.MY_SCHEMA.MY_TABLE",
            "granted_to": "ROLE",
            "grantee_name": "MY_ROLE",
            "grant_option": "false",
            "granted_by": "SYSADMIN",
            "is_inherited": "false",
        }
        row.update(overrides)
        return row

    @pytest.mark.parametrize(
        "row,expected",
        [
            ({"is_inherited": "true"}, True),
            ({"is_inherited": "TRUE"}, True),
            ({"is_inherited": True}, True),
            ({"IS_INHERITED": True}, True),
            ({"IS_INHERITED": "true"}, True),
            ({"is_inherited": "false"}, False),
            ({"is_inherited": False}, False),
            ({"is_inherited": None}, False),
            ({"IS_INHERITED": None}, False),
            # Accounts without the preview, and Snowflake versions without the column,
            # simply do not return it.
            ({}, False),
        ],
    )
    def test_is_inherited_grant_reads_both_casings_and_shapes(self, row, expected):
        from snowcap.data_provider import _is_inherited_grant

        assert _is_inherited_grant(row) is expected

    def test_drop_inherited_grants_keeps_regular_grants(self):
        from snowcap.data_provider import _drop_inherited_grants

        rows = [self._regular_row(), self._inherited_row(), self._regular_row(privilege="INSERT")]

        kept = _drop_inherited_grants(rows, "test")

        assert len(kept) == 2
        assert all(row["name"] for row in kept)

    def test_drop_inherited_grants_is_a_noop_without_the_column(self):
        from snowcap.data_provider import _drop_inherited_grants

        rows = [{"privilege": "SELECT", "granted_on": "TABLE", "name": "MY_DB.MY_SCHEMA.MY_TABLE"}]

        assert _drop_inherited_grants(rows, "test") == rows

    @patch("snowcap.data_provider.execute")
    def test_show_grants_to_role_filters_inherited_rows(self, mock_execute):
        from snowcap.data_provider import _show_grants_to_role

        mock_execute.return_value = [self._regular_row(), self._inherited_row()]

        grants = _show_grants_to_role(MagicMock(), ResourceName("MY_ROLE"))

        assert len(grants) == 1
        assert grants[0]["name"] == "MY_DB.MY_SCHEMA.MY_TABLE"

    def _account_usage_rows(self):
        from datetime import datetime

        return [
            {
                "CREATED_ON": datetime(2024, 1, 1, 12, 0, 0),
                "PRIVILEGE": "SELECT",
                "GRANTED_ON": "TABLE",
                "NAME": "MY_TABLE",
                "TABLE_CATALOG": "MY_DB",
                "TABLE_SCHEMA": "MY_SCHEMA",
                "GRANTED_TO": "ACCOUNT ROLE",
                "GRANTEE_NAME": "MY_ROLE",
                "GRANT_OPTION": False,
                "GRANTED_BY": "SYSADMIN",
                "IS_INHERITED": False,
                "INHERITED_FROM": None,
                "INHERITED_FROM_DATABASE": None,
                "INHERITED_FROM_SCHEMA": None,
            },
            {
                "CREATED_ON": datetime(2024, 1, 1, 12, 0, 0),
                "PRIVILEGE": "SELECT",
                "GRANTED_ON": "TABLE",
                "NAME": None,
                "TABLE_CATALOG": None,
                "TABLE_SCHEMA": None,
                "GRANTED_TO": "ACCOUNT ROLE",
                "GRANTEE_NAME": "MY_ROLE",
                "GRANT_OPTION": False,
                "GRANTED_BY": "SECURITYADMIN",
                "IS_INHERITED": True,
                "INHERITED_FROM": "DATABASE",
                "INHERITED_FROM_DATABASE": "MY_DB",
                "INHERITED_FROM_SCHEMA": None,
            },
        ]

    @patch("snowcap.data_provider.execute")
    def test_account_usage_query_requests_the_container_columns(self, mock_execute):
        from snowcap.data_provider import _fetch_grants_from_account_usage

        mock_execute.return_value = []

        _fetch_grants_from_account_usage(MagicMock())

        query = mock_execute.call_args[0][1]
        for column in ("IS_INHERITED", "INHERITED_FROM", "INHERITED_FROM_DATABASE", "INHERITED_FROM_SCHEMA"):
            assert column in query

    @patch("snowcap.data_provider.execute")
    def test_account_usage_keeps_inherited_rows_tagged(self, mock_execute):
        """Both kinds are cached together so a role's grants are fetched once; the split
        happens at read time."""
        from snowcap.data_provider import _fetch_grants_from_account_usage

        mock_execute.return_value = self._account_usage_rows()

        result = _fetch_grants_from_account_usage(MagicMock())

        assert result is not None
        assert len(result) == 2
        regular, inherited = result
        assert regular["name"] == "MY_DB.MY_SCHEMA.MY_TABLE"
        assert regular["is_inherited"] is False
        assert inherited["is_inherited"] is True
        assert inherited["inherited_from"] == "DATABASE"
        assert inherited["inherited_from_database"] == "MY_DB"

    @patch("snowcap.data_provider.execute")
    def test_object_and_inherited_readers_split_the_same_rows(self, mock_execute):
        from snowcap.data_provider import _show_grants_to_role, _show_inherited_grants_to_role

        mock_execute.return_value = [self._regular_row(), self._inherited_row()]
        session = MagicMock()

        object_grants = _show_grants_to_role(session, ResourceName("MY_ROLE"))
        inherited_grants = _show_inherited_grants_to_role(session, ResourceName("MY_ROLE"))

        assert [g["name"] for g in object_grants] == ["MY_DB.MY_SCHEMA.MY_TABLE"]
        assert [g["inherited_from_database"] for g in inherited_grants] == ["MY_DB"]

    @patch("snowcap.data_provider.execute")
    def test_account_usage_retries_without_the_column_when_unsupported(self, mock_execute):
        """Snowflake versions without IS_INHERITED must not push the whole session onto the
        slower per-role SHOW GRANTS path."""
        from snowflake.connector.errors import ProgrammingError

        from snowcap.client import INVALID_COLUMN_ERR
        from snowcap.data_provider import _fetch_grants_from_account_usage

        mock_execute.side_effect = [ProgrammingError(errno=INVALID_COLUMN_ERR), []]

        result = _fetch_grants_from_account_usage(MagicMock())

        assert result == []
        assert mock_execute.call_count == 2
        assert "IS_INHERITED" in mock_execute.call_args_list[0][0][1]
        assert "IS_INHERITED" not in mock_execute.call_args_list[1][0][1]

    @patch("snowcap.data_provider.execute")
    def test_account_usage_still_falls_back_on_access_denied(self, mock_execute):
        from snowflake.connector.errors import ProgrammingError

        from snowcap.client import ACCESS_CONTROL_ERR
        from snowcap.data_provider import _fetch_grants_from_account_usage

        mock_execute.side_effect = ProgrammingError(errno=ACCESS_CONTROL_ERR)

        assert _fetch_grants_from_account_usage(MagicMock()) is None
        assert mock_execute.call_count == 1

    @pytest.mark.parametrize(
        "row_overrides,expected_on",
        [
            (
                {"inherited_from": "ACCOUNT", "inherited_from_database": "", "inherited_from_schema": ""},
                "account/ACCOUNT.<TABLE>",
            ),
            (
                {"inherited_from": "DATABASE", "inherited_from_database": "MY_DB", "inherited_from_schema": ""},
                "database/MY_DB.<TABLE>",
            ),
            (
                {"inherited_from": "SCHEMA", "inherited_from_database": "MY_DB", "inherited_from_schema": "MY_SCHEMA"},
                "schema/MY_DB.MY_SCHEMA.<TABLE>",
            ),
        ],
    )
    def test_inherited_grant_fqn_encodes_each_container(self, row_overrides, expected_on):
        from snowcap.data_provider import inherited_grant_fqn

        fqn = inherited_grant_fqn(self._inherited_row(**row_overrides), "role", "MY_ROLE")

        assert fqn is not None
        assert fqn.params["grant_type"] == "INHERITED"
        assert fqn.params["on"] == expected_on
        assert fqn.params["to"] == "role/MY_ROLE"

    def test_inherited_grant_fqn_normalizes_synonym_object_types(self):
        """SHOW GRANTS reports CORTEX_AGENT_SERVER for what GRANT/CREATE call an MCP SERVER.
        The fetched URN must use the canonical MCP_SERVER type so it matches the declared
        grant instead of forcing a non-converging DROP+CREATE that revokes inherited access."""
        from snowcap.data_provider import inherited_grant_fqn

        fqn = inherited_grant_fqn(
            self._inherited_row(granted_on="CORTEX_AGENT_SERVER", inherited_from="SCHEMA", inherited_from_schema="SCH"),
            "role",
            "MY_ROLE",
        )

        assert fqn is not None
        assert fqn.params["on"] == "schema/MY_DB.SCH.<MCP_SERVER>"

    def test_normalize_future_grant_name_maps_synonym_object_types(self):
        """A SHOW FUTURE GRANTS name embeds <OBJECT_TYPE>; a synonym (CORTEX_AGENT_SERVER)
        must map to the manifest's canonical MCP_SERVER so the future grant converges instead
        of being dropped and re-created each sync. Non-synonym and unknown types are untouched."""
        from snowcap.data_provider import _normalize_future_grant_name

        assert _normalize_future_grant_name("RAW.<SCHEMA>") == "RAW.<SCHEMA>"
        assert _normalize_future_grant_name("DB.SCH.<TABLE>") == "DB.SCH.<TABLE>"
        assert _normalize_future_grant_name("DB.SCH.<CORTEX_AGENT_SERVER>") == "DB.SCH.<MCP_SERVER>"
        assert _normalize_future_grant_name("DB.SCH.<SOMETHING_NEW>") == "DB.SCH.<SOMETHING_NEW>"

    def test_inherited_grant_fqn_skips_unrecognized_containers(self):
        """An unknown container would produce a grant Snowcap could not revoke, so it is
        left alone rather than guessed at."""
        from snowcap.data_provider import inherited_grant_fqn

        assert inherited_grant_fqn(self._inherited_row(inherited_from="SOMETHING_NEW"), "role", "MY_ROLE") is None

    @patch("snowcap.data_provider.list_database_roles")
    @patch("snowcap.data_provider._should_use_account_usage")
    @patch("snowcap.data_provider.execute")
    def test_list_grants_reports_inherited_grants_as_inherited(
        self, mock_execute, mock_should_use, mock_list_database_roles
    ):
        """A grant sync run must never treat an inherited grant as an object grant: there is
        no object name to revoke it on, and it can only be removed with REVOKE INHERITED."""
        from snowcap.data_provider import list_grants

        mock_should_use.return_value = False
        mock_list_database_roles.return_value = []

        def execute_side_effect(session, query, **kwargs):
            if "SHOW DATABASES" in query:
                return []
            if "SHOW ROLES" in query:
                return [{"name": "MY_ROLE"}]
            return [self._regular_row(), self._inherited_row()]

        mock_execute.side_effect = execute_side_effect

        grants = list_grants(MagicMock(), include_future_grants=False)

        by_type = {fqn.params["grant_type"]: fqn for fqn in grants}
        assert set(by_type) == {"OBJECT", "INHERITED"}
        assert by_type["OBJECT"].params["on"] == "table/MY_DB.MY_SCHEMA.MY_TABLE"
        assert by_type["INHERITED"].params["on"] == "database/MY_DB.<TABLE>"
        assert by_type["INHERITED"].params["priv"] == "SELECT"

    @patch("snowcap.data_provider.execute")
    def test_fetch_inherited_grant_matches_its_container(self, mock_execute):
        from snowcap.data_provider import fetch_inherited_grant
        from snowcap.identifiers import FQN

        mock_execute.return_value = [self._regular_row(), self._inherited_row()]
        fqn = FQN(
            name=ResourceName("GRANT"),
            params={
                "grant_type": "INHERITED",
                "priv": "SELECT",
                "on": "database/MY_DB.<TABLE>",
                "to": "role/MY_ROLE",
            },
        )

        data = fetch_inherited_grant(MagicMock(), fqn)

        assert data is not None
        assert data["grant_type"] == GrantType.INHERITED
        assert data["on"] == "MY_DB"
        assert data["on_type"] == "DATABASE"
        assert data["items_type"] == "TABLE"
        assert data["grant_option"] is False

    @patch("snowcap.data_provider.execute")
    def test_fetch_inherited_grant_does_not_match_another_container(self, mock_execute):
        from snowcap.data_provider import fetch_inherited_grant
        from snowcap.identifiers import FQN

        mock_execute.return_value = [self._inherited_row(inherited_from_database="OTHER_DB")]
        fqn = FQN(
            name=ResourceName("GRANT"),
            params={
                "grant_type": "INHERITED",
                "priv": "SELECT",
                "on": "database/MY_DB.<TABLE>",
                "to": "role/MY_ROLE",
            },
        )

        assert fetch_inherited_grant(MagicMock(), fqn) is None

    @patch("snowcap.data_provider.execute")
    def test_fetch_inherited_grant_reads_the_account_container(self, mock_execute):
        from snowcap.data_provider import fetch_inherited_grant
        from snowcap.identifiers import FQN

        mock_execute.return_value = [
            self._inherited_row(inherited_from="ACCOUNT", inherited_from_database="", inherited_from_schema="")
        ]
        fqn = FQN(
            name=ResourceName("GRANT"),
            params={
                "grant_type": "INHERITED",
                "priv": "SELECT",
                "on": "account/ACCOUNT.<TABLE>",
                "to": "role/MY_ROLE",
            },
        )

        data = fetch_inherited_grant(MagicMock(), fqn)

        assert data is not None
        assert data["on"] == "ACCOUNT"
        assert data["on_type"] == "ACCOUNT"

    @pytest.mark.parametrize(
        "value,expected",
        [("ENABLED", True), ("enabled", True), ("DISABLED", False), ("", False)],
    )
    @patch("snowcap.data_provider.execute")
    def test_feature_flag_probe_reads_the_parameter(self, mock_execute, value, expected):
        from snowcap.data_provider import fetch_inherited_grants_enabled

        mock_execute.return_value = [{"key": "FEATURE_RBAC_INHERITED_GRANTS", "value": value}]

        assert fetch_inherited_grants_enabled(MagicMock()) is expected

    @patch("snowcap.data_provider.execute")
    def test_feature_flag_probe_is_undetermined_when_unreadable(self, mock_execute):
        """The parameter does not exist on older Snowflake versions, and reading account
        parameters needs privileges the session may not have. Neither should block a run."""
        from snowcap.data_provider import fetch_inherited_grants_enabled

        mock_execute.side_effect = Exception("Insufficient privileges")

        assert fetch_inherited_grants_enabled(MagicMock()) is None

    @pytest.mark.parametrize(
        "status,expected",
        [
            ("Preview access is ENABLED for this account", True),
            ("Preview access is DISABLED for this account", False),
            ("something unexpected", None),
        ],
    )
    @patch("snowcap.data_provider.execute")
    def test_preview_access_status_is_read_from_the_system_function(self, mock_execute, status, expected):
        from snowcap.data_provider import fetch_preview_access_enabled

        mock_execute.return_value = [{"STATUS": status}]

        assert fetch_preview_access_enabled(MagicMock()) is expected

    @patch("snowcap.data_provider.execute")
    def test_preview_access_status_is_undetermined_when_unreadable(self, mock_execute):
        from snowcap.data_provider import fetch_preview_access_enabled

        mock_execute.side_effect = Exception("Insufficient privileges")

        assert fetch_preview_access_enabled(MagicMock()) is None


class TestDatabaseRoleGrantsAreNotListedAsGrants:
    """Snowflake reports a database role granted to an account role as a USAGE grant held
    by the grantee. Snowcap models that as a DatabaseRoleGrant, so listing it as a Grant
    too describes one Snowflake fact under two resource types: the declared
    DatabaseRoleGrant never matches, sync proposes dropping the stray Grant on every run,
    and the revoke it builds -- REVOKE USAGE ON DATABASE ROLE -- is rejected by Snowflake
    as an unsupported feature, which aborts the apply."""

    def _row(self, **overrides):
        row = {
            "privilege": "USAGE",
            "granted_on": "DATABASE_ROLE",
            "name": "GREAT_BAY_DEV.DR_READER_ROLE",
            "granted_to": "ROLE",
            "grantee_name": "MY_ROLE",
            "grant_option": "false",
            "granted_by": "SECURITYADMIN",
            "is_inherited": "false",
        }
        row.update(overrides)
        return row

    @pytest.mark.parametrize(
        "granted_on,expected",
        [
            ("DATABASE_ROLE", True),
            ("DATABASE ROLE", True),
            ("ROLE", True),
            ("TABLE", False),
            ("DATABASE", False),
            ("MCP_SERVER", False),
        ],
    )
    def test_role_hierarchy_rows_are_recognized_in_both_spellings(self, granted_on, expected):
        """ACCOUNT_USAGE spells it DATABASE_ROLE, SHOW GRANTS spells it DATABASE ROLE, and
        an underscore in an unrelated object type must not be mistaken for either."""
        from snowcap.data_provider import _is_role_hierarchy_grant

        assert _is_role_hierarchy_grant({"granted_on": granted_on}) is expected

    @patch("snowcap.data_provider.list_database_roles")
    @patch("snowcap.data_provider._should_use_account_usage")
    @patch("snowcap.data_provider.execute")
    def test_list_grants_omits_database_role_grants(self, mock_execute, mock_should_use, mock_list_database_roles):
        from snowcap.data_provider import list_grants

        mock_should_use.return_value = False
        mock_list_database_roles.return_value = []

        def execute_side_effect(session, query, **kwargs):
            if "SHOW DATABASES" in query:
                return []
            if "SHOW ROLES" in query:
                return [{"name": "MY_ROLE"}]
            return [
                self._row(),
                self._row(granted_on="DATABASE ROLE", name="SNOWFLAKE.CORTEX_USER"),
                {
                    "privilege": "SELECT",
                    "granted_on": "TABLE",
                    "name": "MY_DB.MY_SCHEMA.MY_TABLE",
                    "granted_to": "ROLE",
                    "grantee_name": "MY_ROLE",
                    "grant_option": "false",
                    "granted_by": "SYSADMIN",
                    "is_inherited": "false",
                },
            ]

        mock_execute.side_effect = execute_side_effect

        grants = list_grants(MagicMock(), include_future_grants=False)

        on_values = [fqn.params["on"] for fqn in grants]
        assert on_values == ["table/MY_DB.MY_SCHEMA.MY_TABLE"]
        assert not [on for on in on_values if "database_role" in on]


class TestDatabaseRoleGrantToDatabaseRole:
    """Snowflake reports a DATABASE_ROLE grantee unqualified when it's in the same database
    as the role granting it, but the manifest side always builds a fully qualified
    DB.ROLE string. Comparing the two directly never matches, so plan re-issues the grant
    as a no-op CREATE on every run."""

    @patch("snowcap.data_provider.execute")
    def test_fetch_matches_unqualified_grantee_in_same_database(self, mock_execute):
        from snowcap.data_provider import fetch_database_role_grant
        from snowcap.identifiers import FQN
        from snowcap.resource_name import ResourceName

        mock_execute.return_value = [
            {
                "role": "GREAT_BAY_DEV.DR_READER_ROLE",
                "granted_to": "DATABASE_ROLE",
                "grantee_name": "DR_WRITER_ROLE",
                "granted_by": "SECURITYADMIN",
            }
        ]
        fqn = FQN(
            name=ResourceName("DR_READER_ROLE"),
            database=ResourceName("GREAT_BAY_DEV"),
            params={"database_role": "GREAT_BAY_DEV.DR_WRITER_ROLE"},
        )

        result = fetch_database_role_grant(MagicMock(), fqn)

        assert result is not None
        assert result["to_database_role"] == "GREAT_BAY_DEV.DR_WRITER_ROLE"

    @patch("snowcap.data_provider.execute")
    def test_fetch_matches_qualified_grantee_in_another_database(self, mock_execute):
        from snowcap.data_provider import fetch_database_role_grant
        from snowcap.identifiers import FQN
        from snowcap.resource_name import ResourceName

        mock_execute.return_value = [
            {
                "role": "GREAT_BAY_DEV.DR_READER_ROLE",
                "granted_to": "DATABASE_ROLE",
                "grantee_name": "OTHER_DB.DR_WRITER_ROLE",
                "granted_by": "SECURITYADMIN",
            }
        ]
        fqn = FQN(
            name=ResourceName("DR_READER_ROLE"),
            database=ResourceName("GREAT_BAY_DEV"),
            params={"database_role": "OTHER_DB.DR_WRITER_ROLE"},
        )

        result = fetch_database_role_grant(MagicMock(), fqn)

        assert result is not None
        assert result["to_database_role"] == "OTHER_DB.DR_WRITER_ROLE"

    @patch("snowcap.data_provider.execute")
    def test_fetch_does_not_false_match_grantee_in_a_different_database(self, mock_execute):
        """OTHERDB.DR_WRITER_ROLE must not match a target of DB.DR_WRITER_ROLE just because
        the bare role name is the same."""
        from snowcap.data_provider import fetch_database_role_grant
        from snowcap.identifiers import FQN
        from snowcap.resource_name import ResourceName

        mock_execute.return_value = [
            {
                "role": "GREAT_BAY_DEV.DR_READER_ROLE",
                "granted_to": "DATABASE_ROLE",
                "grantee_name": "OTHER_DB.DR_WRITER_ROLE",
                "granted_by": "SECURITYADMIN",
            }
        ]
        fqn = FQN(
            name=ResourceName("DR_READER_ROLE"),
            database=ResourceName("GREAT_BAY_DEV"),
            params={"database_role": "GREAT_BAY_DEV.DR_WRITER_ROLE"},
        )

        assert fetch_database_role_grant(MagicMock(), fqn) is None

    @patch("snowcap.data_provider.execute")
    def test_fetch_regression_grant_to_account_role(self, mock_execute):
        from snowcap.data_provider import fetch_database_role_grant
        from snowcap.identifiers import FQN
        from snowcap.resource_name import ResourceName

        mock_execute.return_value = [
            {
                "role": "GREAT_BAY_DEV.DR_READER_ROLE",
                "granted_to": "ROLE",
                "grantee_name": "GREAT_BAY_DEV__READER",
                "granted_by": "SECURITYADMIN",
            }
        ]
        fqn = FQN(
            name=ResourceName("DR_READER_ROLE"),
            database=ResourceName("GREAT_BAY_DEV"),
            params={"role": "GREAT_BAY_DEV__READER"},
        )

        result = fetch_database_role_grant(MagicMock(), fqn)

        assert result is not None
        assert result["to_role"] == "GREAT_BAY_DEV__READER"

    @patch("snowcap.data_provider._should_use_account_usage")
    @patch("snowcap.data_provider.execute")
    def test_list_show_path_qualifies_same_database_grantee(self, mock_execute, mock_should_use):
        from snowcap.data_provider import list_database_role_grants

        mock_should_use.return_value = False

        def execute_side_effect(session, query, **kwargs):
            if "SHOW DATABASE ROLES IN DATABASE" in query:
                return [{"name": "DR_READER_ROLE"}]
            if "SHOW GRANTS OF DATABASE ROLE" in query:
                return [
                    {
                        "role": "GREAT_BAY_DEV.DR_READER_ROLE",
                        "granted_to": "DATABASE_ROLE",
                        "grantee_name": "DR_WRITER_ROLE",
                        "granted_by": "SECURITYADMIN",
                    }
                ]
            raise AssertionError(f"unexpected query: {query}")

        mock_execute.side_effect = execute_side_effect

        grants = list_database_role_grants(MagicMock(), database="GREAT_BAY_DEV")

        assert len(grants) == 1
        assert grants[0].params == {"database_role": "GREAT_BAY_DEV.DR_WRITER_ROLE"}

    @patch("snowcap.data_provider._should_use_account_usage")
    @patch("snowcap.data_provider.execute")
    def test_list_account_usage_path_recognizes_underscore_granted_on(self, mock_execute, mock_should_use):
        """SNOWFLAKE.ACCOUNT_USAGE.GRANTS_TO_ROLES spells the object type GRANTED_ON =
        'DATABASE_ROLE' (underscore). _fetch_grants_from_account_usage must normalize that
        to 'DATABASE ROLE' (matching SHOW GRANTS) or list_database_role_grants's filter on
        granted_on never matches and this path always returns zero results."""
        from datetime import datetime

        from snowcap.data_provider import list_database_role_grants

        mock_should_use.return_value = True
        mock_execute.return_value = [
            {
                "CREATED_ON": datetime(2024, 1, 1),
                "PRIVILEGE": "USAGE",
                "GRANTED_ON": "DATABASE_ROLE",
                "NAME": "DR_READER_ROLE",
                "TABLE_CATALOG": "GREAT_BAY_DEV",
                "GRANTED_TO": "DATABASE_ROLE",
                "GRANTEE_NAME": "DR_WRITER_ROLE",
                "GRANT_OPTION": False,
                "GRANTED_BY": "SECURITYADMIN",
            }
        ]

        grants = list_database_role_grants(MagicMock(), database="GREAT_BAY_DEV", use_account_usage=True)

        assert len(grants) == 1
        assert grants[0].params == {"database_role": "GREAT_BAY_DEV.DR_WRITER_ROLE"}

    def test_account_usage_and_show_paths_return_identical_fqns(self):
        """The two list paths are interchangeable sources for the same diff, so they must
        agree on the FQN they produce for the same underlying grant."""
        from snowcap.data_provider import list_database_role_grants

        au_row = {
            "privilege": "USAGE",
            "granted_on": "DATABASE ROLE",  # as normalized by _fetch_grants_from_account_usage
            "name": "GREAT_BAY_DEV.DR_READER_ROLE",
            "granted_to": "DATABASE_ROLE",
            "grantee_name": "DR_WRITER_ROLE",
        }
        show_row = {
            "role": "GREAT_BAY_DEV.DR_READER_ROLE",
            "granted_to": "DATABASE_ROLE",
            "grantee_name": "DR_WRITER_ROLE",
            "granted_by": "SECURITYADMIN",
        }

        with (
            patch("snowcap.data_provider._should_use_account_usage", return_value=True),
            patch("snowcap.data_provider._fetch_grants_from_account_usage", return_value=[au_row]),
        ):
            au_grants = list_database_role_grants(MagicMock(), database="GREAT_BAY_DEV", use_account_usage=True)

        def show_side_effect(session, query, **kwargs):
            if "SHOW DATABASE ROLES IN DATABASE" in query:
                return [{"name": "DR_READER_ROLE"}]
            if "SHOW GRANTS OF DATABASE ROLE" in query:
                return [show_row]
            raise AssertionError(f"unexpected query: {query}")

        with (
            patch("snowcap.data_provider._should_use_account_usage", return_value=False),
            patch("snowcap.data_provider.execute", side_effect=show_side_effect),
        ):
            show_grants = list_database_role_grants(MagicMock(), database="GREAT_BAY_DEV")

        assert len(au_grants) == 1
        assert len(show_grants) == 1
        assert au_grants[0] == show_grants[0]
        assert au_grants[0].params == {"database_role": "GREAT_BAY_DEV.DR_WRITER_ROLE"}

    def test_fetched_grant_matches_declared_manifest_fqn(self):
        """The actual reported symptom: plan compares the fetched FQN against the FQN the
        manifest builds for the same declared grant. They must be equal, or plan proposes a
        CREATE for a grant that already exists."""
        from snowcap import resources as res
        from snowcap.resources.grant import database_role_grant_fqn
        from snowcap.data_provider import list_database_role_grants

        grant = res.DatabaseRoleGrant(
            database_role="great_bay_dev.dr_reader_role",
            to_database_role="great_bay_dev.dr_writer_role",
        )
        declared_fqn = database_role_grant_fqn(grant._data)

        def show_side_effect(session, query, **kwargs):
            if "SHOW DATABASE ROLES IN DATABASE" in query:
                return [{"name": "DR_READER_ROLE"}]
            if "SHOW GRANTS OF DATABASE ROLE" in query:
                return [
                    {
                        "role": "GREAT_BAY_DEV.DR_READER_ROLE",
                        "granted_to": "DATABASE_ROLE",
                        "grantee_name": "DR_WRITER_ROLE",
                        "granted_by": "SECURITYADMIN",
                    }
                ]
            raise AssertionError(f"unexpected query: {query}")

        with (
            patch("snowcap.data_provider._should_use_account_usage", return_value=False),
            patch("snowcap.data_provider.execute", side_effect=show_side_effect),
        ):
            fetched_grants = list_database_role_grants(MagicMock(), database="GREAT_BAY_DEV")

        assert len(fetched_grants) == 1
        assert fetched_grants[0] == declared_fqn


class TestGrantsReportedUnderASynonym:
    """Snowflake reports a grant on an MCP server as CORTEX_AGENT_SERVER, while GRANT and
    CREATE call the object an MCP SERVER. Remote state and the manifest have to identify it
    the same way, or every plan both creates and drops the grant -- and drops run after
    creates, so applying takes the access away."""

    def _row(self, granted_on, name, **overrides):
        row = {
            "privilege": "USAGE",
            "granted_on": granted_on,
            "name": name,
            "granted_to": "ROLE",
            "grantee_name": "Z_MCP__DATACOVES",
            "grant_option": "false",
            "granted_by": "ACCOUNTADMIN",
            "is_inherited": "false",
        }
        row.update(overrides)
        return row

    @pytest.mark.parametrize(
        "granted_on,expected",
        [
            ("CORTEX_AGENT_SERVER", "mcp_server"),
            ("MCP_SERVER", "mcp_server"),
            ("TABLE", "table"),
            ("MATERIALIZED_VIEW", "materialized_view"),
            ("IMAGE_REPOSITORY", "image_repository"),
            # Unknown to ResourceType: behaves exactly as the raw lowercase did
            ("SOMETHING_SNOWFLAKE_ADDED_LATER", "something_snowflake_added_later"),
        ],
    )
    def test_granted_on_label_matches_the_manifest_spelling(self, granted_on, expected):
        from snowcap.data_provider import _granted_on_label

        assert _granted_on_label(granted_on) == expected

    def test_label_agrees_with_grant_fqn(self):
        """The whole point is agreeing with the manifest, so assert against it directly
        rather than against a hardcoded string."""
        from snowcap.data_provider import _granted_on_label
        from snowcap.resources.grant import Grant, grant_fqn

        grant = Grant(priv="USAGE", on="mcp server ADMIN_DB.MCPS.DATACOVES", to="Z_MCP__DATACOVES")
        manifest_on = grant_fqn(grant._data).params["on"]

        assert manifest_on.split("/")[0] == _granted_on_label("CORTEX_AGENT_SERVER")

    @patch("snowcap.data_provider.list_database_roles")
    @patch("snowcap.data_provider._should_use_account_usage")
    @patch("snowcap.data_provider.execute")
    def test_list_grants_reports_a_cortex_agent_server_as_an_mcp_server(
        self, mock_execute, mock_should_use, mock_list_database_roles
    ):
        from snowcap.data_provider import list_grants

        mock_should_use.return_value = False
        mock_list_database_roles.return_value = []

        def execute_side_effect(session, query, **kwargs):
            if "SHOW DATABASES" in query:
                return []
            if "SHOW ROLES" in query:
                return [{"name": "Z_MCP__DATACOVES"}]
            return [self._row("CORTEX_AGENT_SERVER", "ADMIN_DB.MCPS.DATACOVES")]

        mock_execute.side_effect = execute_side_effect

        grants = list_grants(MagicMock(), include_future_grants=False)

        assert [fqn.params["on"] for fqn in grants] == ["mcp_server/ADMIN_DB.MCPS.DATACOVES"]


class TestIntrinsicDatabaseRoleUsage:
    """Creating a database role gives it USAGE on the database it belongs to. Snowflake
    reports that like any other grant but with an empty granted_by, because no role granted
    it -- it is part of the role existing, the way OWNERSHIP is. Nothing can revoke it:
    REVOKE reports success and leaves it in place even when run as the database owner. So
    listing it puts a row in remote state no config can declare away and no apply can
    remove, and sync proposes the same drop on every run forever."""

    def _row(self, **overrides):
        row = {
            "privilege": "USAGE",
            "granted_on": "DATABASE",
            "name": "GREAT_BAY",
            "granted_to": "DATABASE_ROLE",
            "grantee_name": "GREAT_BAY.DR_CREATE_ROLE",
            "grant_option": "false",
            "granted_by": "",
            "is_inherited": "false",
        }
        row.update(overrides)
        return row

    @pytest.mark.parametrize(
        "row_overrides,grantee,expected,because",
        [
            ({}, "GREAT_BAY.DR_CREATE_ROLE", True, "usage on its own database"),
            ({"name": "OTHER_DB"}, "GREAT_BAY.DR_CREATE_ROLE", False, "usage on a different database is real"),
            (
                {"granted_on": "SCHEMA", "name": "GREAT_BAY.PUBLIC"},
                "GREAT_BAY.DR_CREATE_ROLE",
                False,
                "schema usage is real",
            ),
            ({"privilege": "SELECT"}, "GREAT_BAY.DR_CREATE_ROLE", False, "only USAGE is intrinsic"),
            ({}, "ANALYST", False, "an account role has no own database"),
        ],
    )
    def test_only_the_roles_own_database_usage_is_intrinsic(self, row_overrides, grantee, expected, because):
        from snowcap.data_provider import _is_intrinsic_database_role_usage

        assert _is_intrinsic_database_role_usage(self._row(**row_overrides), grantee) is expected, because

    def test_an_explicit_grant_is_indistinguishable_and_also_skipped(self):
        """Snowflake keeps a second row with granted_by populated when the same usage is
        granted explicitly. Both reduce to one grant URN, so both are skipped and a declared
        usage on a database role's own database simply re-grants -- the role already has it."""
        from snowcap.data_provider import _is_intrinsic_database_role_usage

        explicit = self._row(granted_by="TRANSFORMER_DBT")

        assert _is_intrinsic_database_role_usage(explicit, "GREAT_BAY.DR_CREATE_ROLE") is True

    @patch("snowcap.data_provider.list_database_roles")
    @patch("snowcap.data_provider._should_use_account_usage")
    @patch("snowcap.data_provider.execute")
    def test_list_grants_omits_it_but_keeps_real_grants(self, mock_execute, mock_should_use, mock_list_database_roles):
        from snowcap.data_provider import list_grants
        from snowcap.identifiers import FQN
        from snowcap.resource_name import ResourceName

        mock_should_use.return_value = False
        mock_list_database_roles.return_value = [
            FQN(name=ResourceName("DR_CREATE_ROLE"), database=ResourceName("GREAT_BAY"))
        ]

        def execute_side_effect(session, query, **kwargs):
            if "SHOW DATABASES" in query:
                return []
            if "SHOW ROLES" in query:
                return []
            return [
                self._row(),  # intrinsic, must not be listed
                self._row(granted_on="SCHEMA", name="GREAT_BAY.COVE_MARKETING", granted_by="TRANSFORMER_DBT"),
            ]

        mock_execute.side_effect = execute_side_effect

        grants = list_grants(MagicMock(), include_future_grants=False)

        assert [fqn.params["on"] for fqn in grants] == ["schema/GREAT_BAY.COVE_MARKETING"]


class TestShareBackedDatabaseGrants:
    """GRANT IMPORTED PRIVILEGES ON DATABASE <db> is how access to a shared database is
    given, and Snowflake reports the resulting grant on the database as plain USAGE.
    Identifying it as USAGE means the declared grant never matches the one read back, so
    every plan proposes creating it again -- forever, and invisibly, since re-granting
    changes nothing. fetch_grant already resolved this, but syncing a resource type builds
    remote state from list_* alone and discards manifest URNs, so that path never ran."""

    SHARED = {"SNOWFLAKE", "SNOWFLAKE_SAMPLE_DATA", "COVID19_EPIDEMIOLOGICAL_DATA"}

    def _row(self, **overrides):
        row = {
            "privilege": "USAGE",
            "granted_on": "DATABASE",
            "name": "SNOWFLAKE_SAMPLE_DATA",
            "granted_to": "ROLE",
            "grantee_name": "Z_DB__SNOWFLAKE_SAMPLE_DATA",
            "grant_option": "false",
            "granted_by": "ACCOUNTADMIN",
            "is_inherited": "false",
        }
        row.update(overrides)
        return row

    @pytest.mark.parametrize(
        "overrides,expected,because",
        [
            ({}, "IMPORTED PRIVILEGES", "usage on a shared database is imported privileges"),
            ({"name": "SNOWFLAKE"}, "IMPORTED PRIVILEGES", "the SNOWFLAKE database is share-backed too"),
            ({"name": "BALBOA"}, None, "on an ordinary database USAGE means USAGE"),
            ({"privilege": "SELECT"}, None, "only USAGE is reported in place of imported privileges"),
            (
                {"granted_on": "SCHEMA", "name": "SNOWFLAKE.ACCOUNT_USAGE"},
                None,
                "the substitution is for the database grant, not objects inside it",
            ),
        ],
    )
    def test_only_database_usage_on_a_shared_database_is_rewritten(self, overrides, expected, because):
        from snowcap.data_provider import _imported_privileges_priv

        assert _imported_privileges_priv(self._row(**overrides), self.SHARED) == expected, because

    @patch("snowcap.data_provider.list_shared_database_names")
    @patch("snowcap.data_provider.list_database_roles")
    @patch("snowcap.data_provider._should_use_account_usage")
    @patch("snowcap.data_provider.execute")
    def test_list_grants_reports_it_the_way_config_declares_it(
        self, mock_execute, mock_should_use, mock_list_database_roles, mock_shared
    ):
        from snowcap.data_provider import list_grants

        mock_should_use.return_value = False
        mock_list_database_roles.return_value = []
        mock_shared.return_value = self.SHARED

        def execute_side_effect(session, query, **kwargs):
            if "SHOW DATABASES" in query:
                return []
            if "SHOW ROLES" in query:
                return [{"name": "Z_DB__SNOWFLAKE_SAMPLE_DATA"}]
            return [
                self._row(),
                self._row(name="BALBOA"),  # ordinary database, must stay USAGE
            ]

        mock_execute.side_effect = execute_side_effect

        grants = list_grants(MagicMock(), include_future_grants=False)
        by_on = {fqn.params["on"]: fqn.params["priv"] for fqn in grants}

        assert by_on["database/SNOWFLAKE_SAMPLE_DATA"] == "IMPORTED PRIVILEGES"
        assert by_on["database/BALBOA"] == "USAGE"


class TestGrantFetchMatchesOnObjectType:
    """fetch_grant compared granted_on as a raw string, so a grant Snowflake reports under
    a different name than its DDL uses -- CORTEX_AGENT_SERVER for an MCP SERVER -- never
    matched the declared grant, and the plan proposed creating it on every run."""

    def _grants(self):
        return [
            {
                "privilege": "USAGE",
                "granted_on": "CORTEX_AGENT_SERVER",
                "name": "ADMIN_DB.MCPS.DATACOVES",
                "granted_to": "ROLE",
                "grantee_name": "Z_MCP__DATACOVES",
                "grant_option": "false",
                "granted_by": "ACCOUNTADMIN",
            }
        ]

    @patch("snowcap.data_provider._show_grants_to_role")
    def test_a_grant_reported_under_a_synonym_is_found(self, mock_show):
        from snowcap.data_provider import _fetch_grant_to_role
        from snowcap.enums import GrantType, ResourceType
        from snowcap.resource_name import ResourceName

        mock_show.return_value = self._grants()

        found = _fetch_grant_to_role(
            MagicMock(),
            grant_type=GrantType.OBJECT,
            role=ResourceName("Z_MCP__DATACOVES"),
            granted_on="MCP_SERVER",
            on_name="ADMIN_DB.MCPS.DATACOVES",
            privilege="USAGE",
            role_type=ResourceType.ROLE,
        )

        assert found is not None
        assert found["granted_on"] == "CORTEX_AGENT_SERVER"

    @patch("snowcap.data_provider._show_grants_to_role")
    def test_an_unrelated_object_type_still_does_not_match(self, mock_show):
        from snowcap.data_provider import _fetch_grant_to_role
        from snowcap.enums import GrantType, ResourceType
        from snowcap.resource_name import ResourceName

        mock_show.return_value = self._grants()

        assert (
            _fetch_grant_to_role(
                MagicMock(),
                grant_type=GrantType.OBJECT,
                role=ResourceName("Z_MCP__DATACOVES"),
                granted_on="TABLE",
                on_name="ADMIN_DB.MCPS.DATACOVES",
                privilege="USAGE",
                role_type=ResourceType.ROLE,
            )
            is None
        )


class TestFetchGrant:
    """Tests for fetch_grant grant-matching logic with mocked SHOW results."""

    def _fqn(self, priv, on, to, grant_type=None):
        params = {"priv": priv, "on": on, "to": to}
        if grant_type is not None:
            params["grant_type"] = grant_type
        return FQN(name=ResourceName("GRANT"), params=params)

    def _future_grant_row(self, privilege, name, granted_on, grant_to="ROLE"):
        """Row shape of _show_future_grants_to_role output (granted_on already inferred)."""
        row = _grant_to_role_row(
            privilege=privilege, name=name, granted_on=granted_on, granted_to=grant_to, grantee_name="DBT_DEVELOPER"
        )
        row.update({"grant_on": granted_on, "grant_to": grant_to})
        return row

    @patch("snowcap.data_provider._show_grants_to_role")
    @patch("snowcap.data_provider._show_future_grants_to_role")
    def test_fetch_grant_all_future_schemas_in_database(self, mock_future_grants, mock_show_grants):
        """ALL on FUTURE SCHEMAS in DATABASE must query SHOW FUTURE GRANTS, not SHOW GRANTS."""
        fqn = self._fqn(
            priv="ALL",
            on="database/DB_DEV.<SCHEMA>",
            to="role/DBT_DEVELOPER",
            grant_type="FUTURE",
        )
        mock_future_grants.return_value = [
            self._future_grant_row("MONITOR", "DB_DEV.<SCHEMA>", "DATABASE"),
            self._future_grant_row("USAGE", "DB_DEV.<SCHEMA>", "DATABASE"),
        ]

        result = fetch_grant(MagicMock(), fqn)

        assert result is not None
        assert result["priv"] == "ALL"
        assert result["_privs"] == ["MONITOR", "USAGE"]
        assert result["grant_type"] == "FUTURE"
        mock_future_grants.assert_called_once()
        mock_show_grants.assert_not_called()

    @patch("snowcap.data_provider._show_grants_to_role")
    @patch("snowcap.data_provider._show_future_grants_to_role")
    @patch("snowcap.data_provider._show_future_grants_to_database_role")
    def test_fetch_grant_all_future_to_database_role(self, mock_db_role_grants, mock_future_grants, mock_show_grants):
        """ALL on FUTURE grants to a DATABASE ROLE must query SHOW FUTURE GRANTS TO DATABASE ROLE."""
        fqn = self._fqn(
            priv="ALL",
            on="database/DB_DEV.<SCHEMA>",
            to="database_role/DB_DEV.DBT_ROLE",
            grant_type="FUTURE",
        )
        mock_db_role_grants.return_value = [
            self._future_grant_row("USAGE", "DB_DEV.<SCHEMA>", "DATABASE", grant_to="DATABASE_ROLE"),
        ]

        result = fetch_grant(MagicMock(), fqn)

        assert result is not None
        assert result["priv"] == "ALL"
        assert result["_privs"] == ["USAGE"]
        assert result["grant_type"] == "FUTURE"
        mock_db_role_grants.assert_called_once()
        mock_future_grants.assert_not_called()
        mock_show_grants.assert_not_called()

    @patch("snowcap.data_provider._show_grants_to_role")
    def test_fetch_grant_all_on_integration(self, mock_show_grants):
        """ALL on an integration: SHOW GRANTS collapses *-integration types to
        granted_on='INTEGRATION'; the direct _filter_result branch must still match."""
        fqn = self._fqn(priv="ALL", on="security_integration/MY_OAUTH", to="role/SOME_ROLE")
        mock_show_grants.return_value = [
            _grant_to_role_row(privilege="USAGE", granted_on="INTEGRATION", name="MY_OAUTH", grantee_name="SOME_ROLE"),
        ]

        result = fetch_grant(MagicMock(), fqn)

        assert result is not None
        assert result["priv"] == "ALL"
        assert result["_privs"] == ["USAGE"]

    @pytest.mark.parametrize(
        "priv,on,reported_on,expected_on_type",
        [
            # SHOW GRANTS collapses all *-integration types to granted_on='INTEGRATION'
            # (verified live 2026-07-24); the returned on_type stays canonical.
            ("USAGE", "catalog_integration/MY_CATALOG", "INTEGRATION", "CATALOG INTEGRATION"),
            ("USAGE", "storage_integration/MY_STORAGE", "INTEGRATION", "STORAGE INTEGRATION"),
            # GIT REPOSITORY is reported with an underscore ('GIT_REPOSITORY') — must
            # still match, and round-trips to the canonical spaced form.
            ("READ", "git_repository/DB_PROD.PUBLIC.DBT_PLATFORM_REPO", "GIT_REPOSITORY", "GIT REPOSITORY"),
            ("AUDIT", "account/ACCOUNT", "ACCOUNT", "ACCOUNT"),
            ("USAGE", "schema/DB_DEV.PUBLIC", "SCHEMA", "SCHEMA"),
        ],
    )
    @patch("snowcap.data_provider._show_grants_to_role")
    def test_fetch_grant_object_type_round_trip(self, mock_show_grants, priv, on, reported_on, expected_on_type):
        name = on.split("/", 1)[1]
        mock_show_grants.return_value = [
            _grant_to_role_row(privilege=priv, granted_on=reported_on, name=name, grantee_name="SOME_ROLE"),
        ]

        result = fetch_grant(MagicMock(), self._fqn(priv=priv, on=on, to="role/SOME_ROLE"))

        assert result is not None
        assert result["priv"] == priv
        assert result["on"] == name
        assert result["on_type"] == expected_on_type

    @patch("snowcap.data_provider.execute")
    def test_show_future_grants_container_inference_is_quote_aware(self, mock_execute):
        """Quoted identifiers may contain dots: '"DB.WITH.DOT".<SCHEMA>' is a database-level
        collection and '"DB.WITH.DOT"."SCH.WITH.DOT".<TABLE>' is schema-level. A naive
        name.split('.') misclassifies both."""
        mock_execute.return_value = [
            _grant_to_role_row(privilege="USAGE", name='"DB.WITH.DOT".<SCHEMA>'),
            _grant_to_role_row(privilege="USAGE", name='"DB.WITH.DOT"."SCH.WITH.DOT".<TABLE>'),
        ]

        grants = _show_future_grants_to_role(MagicMock(), "SOME_ROLE")

        assert grants[0]["granted_on"] == "DATABASE"
        assert grants[1]["granted_on"] == "SCHEMA"


def _reset_grant_indexes():
    """Both grant indexes are process-wide, so a test must not inherit another's."""
    from snowcap.data_provider import reset_account_usage_caches

    reset_account_usage_caches()
    reset_cache()


class TestGrantNameKey:
    """Tests for _grant_name_key, the dict key standing in for ResourceName equality."""

    def test_resource_name_is_unsafe_as_a_dict_key(self):
        # The reason the helper exists at all: __eq__ calls these the same name but
        # __hash__ disagrees, so a plain {ResourceName: grant} dict misses the lookup.
        assert ResourceName('"FOO"') == ResourceName("FOO")
        assert hash(ResourceName('"FOO"')) != hash(ResourceName("FOO"))
        assert _grant_name_key('"FOO"') == _grant_name_key("FOO")

    @pytest.mark.parametrize(
        "left,right",
        [
            ("FOO", "FOO"),
            ("FOO", "foo"),
            ('"FOO"', "FOO"),
            ('"FOO"', "foo"),
            ('"Foo"', '"Foo"'),
            # A name that has to be quoted to be legal is the same name either way.
            ("my-name", '"my-name"'),
        ],
    )
    def test_key_is_shared_by_names_resource_name_calls_equal(self, left, right):
        assert ResourceName(left) == ResourceName(right)
        assert _grant_name_key(left) == _grant_name_key(right)

    @pytest.mark.parametrize(
        "left,right",
        [
            ('"Foo"', "Foo"),
            ('"foo"', "FOO"),
            ('"Foo"', '"foo"'),
            ("FOO", "BAR"),
        ],
    )
    def test_key_differs_for_names_resource_name_calls_different(self, left, right):
        assert ResourceName(left) != ResourceName(right)
        assert _grant_name_key(left) != _grant_name_key(right)


class TestGrantLookupIndex:
    """Tests for _grant_lookup_index and _fetch_grant_to_role, which reads through it."""

    @pytest.fixture(autouse=True)
    def _clean_indexes(self):
        _reset_grant_indexes()
        yield
        _reset_grant_indexes()

    def _fetch(self, session, granted_on, on_name, privilege="SELECT", role="SOME_ROLE"):
        return _fetch_grant_to_role(
            session,
            GrantType.OBJECT,
            ResourceName(role),
            granted_on,
            on_name,
            privilege,
        )

    @patch("snowcap.data_provider._show_grants_to_role")
    def test_finds_a_grant_by_type_privilege_and_name(self, mock_show_grants):
        mock_show_grants.return_value = [
            _grant_to_role_row(privilege="SELECT", granted_on="TABLE", name="MY_DB.MY_SCHEMA.MY_TABLE"),
        ]

        result = self._fetch(MagicMock(), "TABLE", "MY_DB.MY_SCHEMA.MY_TABLE")

        assert result is not None
        assert result["privilege"] == "SELECT"

    @pytest.mark.parametrize(
        "reported_name,requested_name",
        [
            ("MY_TABLE", '"MY_TABLE"'),
            ('"MY_TABLE"', "MY_TABLE"),
            ("MY_TABLE", "my_table"),
            ('"MixedCase"', '"MixedCase"'),
        ],
    )
    @patch("snowcap.data_provider._show_grants_to_role")
    def test_quoting_does_not_change_the_match(self, mock_show_grants, reported_name, requested_name):
        # The scan this replaced compared with ResourceName, so quoted and unquoted
        # spellings of one name matched. The index has to keep that true.
        mock_show_grants.return_value = [_grant_to_role_row(granted_on="TABLE", name=reported_name)]

        assert self._fetch(MagicMock(), "TABLE", requested_name, privilege="USAGE") is not None

    @patch("snowcap.data_provider._show_grants_to_role")
    def test_a_genuinely_different_name_does_not_match(self, mock_show_grants):
        mock_show_grants.return_value = [_grant_to_role_row(granted_on="TABLE", name='"MixedCase"')]

        assert self._fetch(MagicMock(), "TABLE", "MIXEDCASE", privilege="USAGE") is None

    @patch("snowcap.data_provider._show_grants_to_role")
    def test_wrong_privilege_does_not_match(self, mock_show_grants):
        mock_show_grants.return_value = [_grant_to_role_row(privilege="USAGE", granted_on="TABLE", name="MY_TABLE")]

        assert self._fetch(MagicMock(), "TABLE", "MY_TABLE", privilege="SELECT") is None

    @patch("snowcap.data_provider._show_grants_to_role")
    def test_account_grants_match_on_the_account_keyword(self, mock_show_grants):
        mock_show_grants.return_value = [
            _grant_to_role_row(privilege="AUDIT", granted_on="ACCOUNT", name="SOME_ACCOUNT_LOCATOR"),
        ]

        assert self._fetch(MagicMock(), "ACCOUNT", "ACCOUNT", privilege="AUDIT") is not None

    @patch("snowcap.data_provider._show_grants_to_role")
    def test_object_type_synonyms_still_match(self, mock_show_grants):
        # Snowflake reports the type with an underscore where the DDL spells it with a
        # space. Both sides go through _granted_on_label, so the index has to as well.
        mock_show_grants.return_value = [
            _grant_to_role_row(privilege="READ", granted_on="GIT_REPOSITORY", name="MY_DB.PUBLIC.MY_REPO"),
        ]

        result = self._fetch(MagicMock(), "GIT REPOSITORY", "MY_DB.PUBLIC.MY_REPO", privilege="READ")

        assert result is not None

    @patch("snowcap.data_provider._show_grants_to_role")
    def test_duplicate_grants_resolve_to_the_first_one(self, mock_show_grants):
        # Two roles can grant the same privilege on the same object. The linear scan
        # returned the first row; the index has to agree.
        mock_show_grants.return_value = [
            _grant_to_role_row(granted_on="TABLE", name="MY_TABLE", granted_by="ROLE_A"),
            _grant_to_role_row(granted_on="TABLE", name="MY_TABLE", granted_by="ROLE_B"),
        ]

        result = self._fetch(MagicMock(), "TABLE", "MY_TABLE", privilege="USAGE")

        assert result is not None
        assert result["granted_by"] == "ROLE_A"

    @patch("snowcap.data_provider._show_grants_to_role")
    def test_a_role_is_read_once_however_many_grants_are_looked_up(self, mock_show_grants):
        # The point of the index: 90k grant lookups must not re-read a role 90k times.
        mock_show_grants.return_value = [_grant_to_role_row(granted_on="TABLE", name=f"MY_TABLE_{i}") for i in range(5)]
        session = MagicMock()

        for i in range(5):
            assert self._fetch(session, "TABLE", f"MY_TABLE_{i}", privilege="USAGE") is not None

        assert mock_show_grants.call_count == 1

    @patch("snowcap.data_provider._show_grants_to_role")
    def test_each_role_gets_its_own_index(self, mock_show_grants):
        mock_show_grants.side_effect = [
            [_grant_to_role_row(granted_on="TABLE", name="TABLE_A")],
            [_grant_to_role_row(granted_on="TABLE", name="TABLE_B")],
        ]
        session = MagicMock()

        assert self._fetch(session, "TABLE", "TABLE_A", privilege="USAGE", role="ROLE_A") is not None
        assert self._fetch(session, "TABLE", "TABLE_A", privilege="USAGE", role="ROLE_B") is None
        assert self._fetch(session, "TABLE", "TABLE_B", privilege="USAGE", role="ROLE_B") is not None

    @patch("snowcap.data_provider._show_future_grants_to_role")
    @patch("snowcap.data_provider._show_grants_to_role")
    def test_future_grants_are_indexed_from_the_future_grant_source(self, mock_show_grants, mock_show_future):
        mock_show_future.return_value = [_grant_to_role_row(privilege="SELECT", granted_on="SCHEMA", name="MY_DB.SCH")]

        result = _fetch_grant_to_role(
            MagicMock(), GrantType.FUTURE, ResourceName("SOME_ROLE"), "SCHEMA", "MY_DB.SCH", "SELECT"
        )

        assert result is not None
        mock_show_grants.assert_not_called()

    @patch("snowcap.data_provider._show_grants_to_role")
    def test_resetting_the_caches_rebuilds_the_index(self, mock_show_grants):
        # The index is derived state. Leaving it behind would hide grants that an apply
        # created after it was built.
        mock_show_grants.side_effect = [
            [],
            [_grant_to_role_row(granted_on="TABLE", name="MY_TABLE")],
        ]
        session = MagicMock()

        assert self._fetch(session, "TABLE", "MY_TABLE", privilege="USAGE") is None
        _reset_grant_indexes()

        assert self._fetch(session, "TABLE", "MY_TABLE", privilege="USAGE") is not None

    @patch("snowcap.data_provider._show_grants_to_role")
    def test_resetting_the_sql_cache_rebuilds_the_index(self, mock_show_grants):
        # Blueprint.plan() calls reset_cache() and nothing else, so a second plan on the
        # same session was answered from the first plan's grants.
        mock_show_grants.side_effect = [
            [_grant_to_role_row(granted_on="TABLE", name="MY_TABLE")],
            [],
        ]
        session = MagicMock()

        assert self._fetch(session, "TABLE", "MY_TABLE", privilege="USAGE") is not None
        reset_cache()

        assert self._fetch(session, "TABLE", "MY_TABLE", privilege="USAGE") is None
        assert mock_show_grants.call_count == 2

    @patch("snowcap.data_provider._show_grants_to_role")
    def test_the_index_survives_within_one_plan(self, mock_show_grants):
        # The counterpart: only a reset invalidates the index, or the lookup is pointless.
        mock_show_grants.return_value = [_grant_to_role_row(granted_on="TABLE", name="MY_TABLE")]
        session = MagicMock()

        self._fetch(session, "TABLE", "MY_TABLE", privilege="USAGE")
        self._fetch(session, "TABLE", "MY_TABLE", privilege="USAGE")

        assert mock_show_grants.call_count == 1


class TestGrantsByRoleIndex:
    """Tests for _grants_by_role_index, the role index over the ACCOUNT_USAGE grant cache."""

    @pytest.fixture(autouse=True)
    def _clean_indexes(self):
        _reset_grant_indexes()
        yield
        _reset_grant_indexes()

    def _populate(self, session, grants):
        _ACCOUNT_USAGE_GRANTS_CACHE[id(session)] = grants

    def test_groups_grants_by_grantee(self):
        session = MagicMock()
        self._populate(
            session,
            [
                _grant_to_role_row(name="DB_A", grantee_name="ROLE_A"),
                _grant_to_role_row(name="DB_B", grantee_name="ROLE_B"),
                _grant_to_role_row(name="DB_C", grantee_name="ROLE_A"),
            ],
        )

        index = _grants_by_role_index(id(session))

        assert sorted(index) == ["ROLE_A", "ROLE_B"]
        assert [grant["name"] for grant in index["ROLE_A"]] == ["DB_A", "DB_C"]

    def test_grantee_names_are_matched_case_insensitively(self):
        # ACCOUNT_USAGE reports the grantee as stored; the caller looks it up by the
        # upper-cased role name, which is what the scan this replaced compared.
        session = MagicMock()
        self._populate(session, [_grant_to_role_row(grantee_name="role_a")])

        assert _grants_by_role_index(id(session))["ROLE_A"]

    def test_grants_to_anything_other_than_a_role_are_left_out(self):
        session = MagicMock()
        self._populate(
            session,
            [
                _grant_to_role_row(grantee_name="ROLE_A", granted_to="ROLE"),
                _grant_to_role_row(grantee_name="ROLE_A", granted_to="DATABASE_ROLE"),
            ],
        )

        assert len(_grants_by_role_index(id(session))["ROLE_A"]) == 1

    @patch("snowcap.data_provider.execute")
    def test_show_grants_reads_the_index_instead_of_the_database(self, mock_execute):
        session = MagicMock()
        self._populate(
            session,
            [
                _grant_to_role_row(name="DB_A", grantee_name="ROLE_A"),
                _grant_to_role_row(name="DB_B", grantee_name="ROLE_B"),
            ],
        )

        grants = _show_all_grants_to_role(session, ResourceName("ROLE_A"))

        assert [grant["name"] for grant in grants] == ["DB_A"]
        mock_execute.assert_not_called()

    @patch("snowcap.data_provider.execute")
    def test_a_role_with_no_grants_reads_as_empty(self, mock_execute):
        session = MagicMock()
        self._populate(session, [_grant_to_role_row(grantee_name="ROLE_A")])

        assert _show_all_grants_to_role(session, ResourceName("ROLE_B")) == []
        mock_execute.assert_not_called()

    def test_the_index_is_built_once_per_session(self):
        session = MagicMock()
        self._populate(session, [_grant_to_role_row(grantee_name="ROLE_A")])

        first = _grants_by_role_index(id(session))
        second = _grants_by_role_index(id(session))

        assert first is second

    def test_resetting_the_caches_drops_the_index(self):
        session = MagicMock()
        self._populate(session, [_grant_to_role_row(grantee_name="ROLE_A")])
        _grants_by_role_index(id(session))

        _reset_grant_indexes()

        assert _grants_by_role_index(id(session)) == {}


def _account_usage_row(database_name="MY_DB", schema_name="PUBLIC", name="MY_TABLE"):
    """A row shaped the way the ACCOUNT_USAGE listing queries alias their columns."""
    return {"database_name": database_name, "schema_name": schema_name, "name": name}


class TestListSchemaScopedFromAccountUsage:
    """Tests for _list_schema_scoped_from_account_usage, the SHOW-cap workaround."""

    @pytest.fixture(autouse=True)
    def _clean_caches(self):
        reset_account_usage_caches()
        yield
        reset_account_usage_caches()

    @patch("snowcap.data_provider._has_account_usage_access", return_value=True)
    @patch("snowcap.data_provider._list_databases")
    @patch("snowcap.data_provider.execute")
    def test_a_quoted_database_is_kept(self, mock_execute, mock_list_databases, _mock_access):
        # ACCOUNT_USAGE returns the bare name (MyDb) while str(ResourceName) renders it with
        # quotes ('"MyDb"'), so comparing rendered strings drops every database that is not
        # plain upper case. The comparison has to happen in ResourceName space.
        mock_list_databases.return_value = [ResourceName('"MyDb"')]
        mock_execute.return_value = [_account_usage_row(database_name="MyDb")]

        result = _list_schema_scoped_from_account_usage(MagicMock(), "SELECT 1", use_account_usage=True)

        assert [str(fqn.database) for fqn in result] == ['"MyDb"']

    @patch("snowcap.data_provider._has_account_usage_access", return_value=True)
    @patch("snowcap.data_provider._list_databases")
    @patch("snowcap.data_provider.execute")
    def test_an_uppercase_database_is_kept(self, mock_execute, mock_list_databases, _mock_access):
        mock_list_databases.return_value = [ResourceName("MY_DB")]
        mock_execute.return_value = [_account_usage_row()]

        result = _list_schema_scoped_from_account_usage(MagicMock(), "SELECT 1", use_account_usage=True)

        assert [str(fqn) for fqn in result] == ["MY_DB.PUBLIC.MY_TABLE"]

    @patch("snowcap.data_provider._has_account_usage_access", return_value=True)
    @patch("snowcap.data_provider._list_databases")
    @patch("snowcap.data_provider.execute")
    def test_a_database_snowcap_does_not_manage_is_dropped(self, mock_execute, mock_list_databases, _mock_access):
        # Shares and imported databases are not in _list_databases, and exporting objects
        # out of them would produce config that cannot be applied.
        mock_list_databases.return_value = [ResourceName("MY_DB")]
        mock_execute.return_value = [_account_usage_row(database_name="SOME_SHARE")]

        assert _list_schema_scoped_from_account_usage(MagicMock(), "SELECT 1", use_account_usage=True) == []

    @patch("snowcap.data_provider._has_account_usage_access", return_value=True)
    @patch("snowcap.data_provider._list_databases")
    @patch("snowcap.data_provider.execute")
    def test_system_databases_and_information_schema_are_dropped(self, mock_execute, mock_list_databases, _mock_access):
        mock_list_databases.return_value = [ResourceName("MY_DB")]
        mock_execute.return_value = [
            _account_usage_row(database_name="SNOWFLAKE"),
            _account_usage_row(schema_name="INFORMATION_SCHEMA"),
            _account_usage_row(),
        ]

        result = _list_schema_scoped_from_account_usage(MagicMock(), "SELECT 1", use_account_usage=True)

        assert [str(fqn) for fqn in result] == ["MY_DB.PUBLIC.MY_TABLE"]

    @patch("snowcap.data_provider._has_account_usage_access", return_value=True)
    @patch("snowcap.data_provider.execute")
    def test_opting_out_returns_none_without_querying(self, mock_execute, _mock_access):
        # --no-use-account-usage has to reach all the way down, not just skip the warning.
        assert _list_schema_scoped_from_account_usage(MagicMock(), "SELECT 1", use_account_usage=False) is None
        mock_execute.assert_not_called()

    @patch("snowcap.data_provider._has_account_usage_access", return_value=False)
    @patch("snowcap.data_provider.execute")
    def test_no_account_usage_access_returns_none_so_the_caller_can_show(self, mock_execute, _mock_access):
        assert _list_schema_scoped_from_account_usage(MagicMock(), "SELECT 1", use_account_usage=True) is None
        mock_execute.assert_not_called()

    @patch("snowcap.data_provider._has_account_usage_access", return_value=True)
    @patch("snowcap.data_provider.execute", side_effect=Exception("boom"))
    def test_a_failed_query_returns_none_and_stops_retrying(self, mock_execute, _mock_access):
        session = MagicMock()

        assert _list_schema_scoped_from_account_usage(session, "SELECT 1", use_account_usage=True) is None
        # The session is marked as fallen back, so the next listing does not pay for the
        # same failure again.
        assert _list_schema_scoped_from_account_usage(session, "SELECT 2", use_account_usage=True) is None
        assert mock_execute.call_count == 1

    @patch("snowcap.data_provider._has_account_usage_access", return_value=True)
    @patch("snowcap.data_provider._list_databases")
    @patch("snowcap.data_provider.execute")
    def test_staleness_is_warned_about_once_per_session(self, mock_execute, mock_list_databases, _mock_access, caplog):
        # ACCOUNT_USAGE lags live state by up to ~2 hours. That is worth saying once a run,
        # not once per resource type.
        mock_list_databases.return_value = [ResourceName("MY_DB")]
        mock_execute.return_value = [_account_usage_row()]
        session = MagicMock()

        with caplog.at_level(logging.WARNING, logger="snowcap"):
            _list_schema_scoped_from_account_usage(session, "SELECT 1", use_account_usage=True)
            _list_schema_scoped_from_account_usage(session, "SELECT 2", use_account_usage=True)

        warnings = [record for record in caplog.records if "--no-use-account-usage" in record.message]
        assert len(warnings) == 1


class TestSchemaScopedListersUseAccountUsage:
    """list_tables / list_views / list_stages read ACCOUNT_USAGE, then fall back to SHOW."""

    @pytest.fixture(autouse=True)
    def _clean_caches(self):
        reset_account_usage_caches()
        yield
        reset_account_usage_caches()

    @pytest.mark.parametrize("lister", [list_tables, list_views, list_stages])
    @patch("snowcap.data_provider._list_schema_scoped_from_account_usage")
    @patch("snowcap.data_provider.execute")
    def test_account_usage_answers_without_a_show(self, mock_execute, mock_from_account_usage, lister):
        # SHOW ... IN ACCOUNT is capped at 10,000 rows, so on a large account it is not an
        # option at all -- it fails outright and takes the export with it.
        listed = [FQN(database=ResourceName("MY_DB"), schema=ResourceName("PUBLIC"), name=ResourceName("MY_OBJECT"))]
        mock_from_account_usage.return_value = listed

        assert lister(MagicMock(), use_account_usage=True) == listed
        mock_execute.assert_not_called()

    @pytest.mark.parametrize("lister", [list_tables, list_views, list_stages])
    @patch("snowcap.data_provider._has_account_usage_access", return_value=True)
    @patch("snowcap.data_provider._list_databases", return_value=[])
    @patch("snowcap.data_provider.execute", return_value=[])
    def test_the_default_is_show(self, mock_execute, _mock_databases, _mock_access, lister):
        # A caller that says nothing keeps real-time SHOW; the lagging view is opt-in.
        lister(MagicMock())

        assert "SHOW" in mock_execute.call_args_list[0].args[1]

    @pytest.mark.parametrize("lister", [list_tables, list_views, list_stages])
    @patch("snowcap.data_provider._list_schema_scoped_from_account_usage", return_value=None)
    @patch("snowcap.data_provider.execute", return_value=[])
    def test_show_still_runs_when_account_usage_is_unavailable(self, mock_execute, _mock_from_account_usage, lister):
        assert lister(MagicMock()) == []
        assert "SHOW" in mock_execute.call_args[0][1]

    @pytest.mark.parametrize("lister", [list_tables, list_views, list_stages])
    @patch("snowcap.data_provider._list_schema_scoped_from_account_usage", return_value=None)
    @patch("snowcap.data_provider.execute", return_value=[])
    def test_the_opt_out_reaches_the_listing_helper(self, _mock_execute, mock_from_account_usage, lister):
        lister(MagicMock(), use_account_usage=False)

        assert mock_from_account_usage.call_args.kwargs["use_account_usage"] is False
