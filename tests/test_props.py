"""
Tests for snowcap/props.py - Property classes for SQL generation and parsing.
"""

import unittest
from enum import Enum

import pytest
from pyparsing import ParseException

from snowcap.enums import DataType
from snowcap.resources import Database
from snowcap.props import (
    quote_value,
    Props,
    AlertConditionProp,
    BoolProp,
    ArgsProp,
    EnumProp,
    EnumListProp,
    EnumFlagProp,
    FlagProp,
    IdentifierProp,
    IdentifierListProp,
    IntProp,
    StringProp,
    StringListProp,
    PropSet,
    PropList,
    StructProp,
    TagsProp,
    DictProp,
    ReturnsProp,
    QueryProp,
    ExpressionProp,
    TimeTravelProp,
    ColumnNamesProp,
    SchemaProp,
    FromProp,
)


class TestProp(unittest.TestCase):
    def validate_identity(self, prop, sql):
        self.assertEqual(prop.render(prop.parse(sql)), sql)

    def test_prop_alert_condition(self):
        assert AlertConditionProp().parse("IF(EXISTS(SELECT 1))") == "SELECT 1"
        assert AlertConditionProp().parse("IF(EXISTS(SELECT func() from tbl))") == "SELECT func() from tbl"
        self.validate_identity(AlertConditionProp(), "IF(EXISTS( SELECT 1 ))")

    def test_prop_bool(self):
        self.assertTrue(BoolProp("foo").parse("FOO = TRUE"))
        self.assertFalse(BoolProp("bar").parse("bar = FALSE"))
        self.validate_identity(BoolProp("boolprop"), "BOOLPROP = TRUE")

    def test_prop_args(self):
        self.assertEqual(ArgsProp().parse("(id INT)"), [{"name": "id", "data_type": DataType.INT}])
        self.assertEqual(ArgsProp().parse("(somestr VARCHAR)"), [{"name": "somestr", "data_type": DataType.VARCHAR}])
        self.assertEqual(ArgsProp().parse("(floaty FLOAT8)"), [{"name": "floaty", "data_type": DataType.FLOAT8}])
        self.assertEqual(
            ArgsProp().parse("(multiple INT, columns VARCHAR)"),
            [
                {"name": "multiple", "data_type": DataType.INT},
                {"name": "columns", "data_type": DataType.VARCHAR},
            ],
        )
        self.assertEqual(
            ArgsProp().parse("(id INT, name STRING, created_at TIMESTAMP)"),
            [
                {"name": "id", "data_type": DataType.INT},
                {"name": "name", "data_type": DataType.STRING},
                {"name": "created_at", "data_type": DataType.TIMESTAMP},
            ],
        )

    def test_prop_enum(self):
        self.assertEqual(EnumProp("data_type", DataType).parse("DATA_TYPE = VARCHAR"), DataType.VARCHAR)

    def test_prop_flag(self):
        self.assertEqual(FlagProp("this is a flag").parse("this is a flag"), True)
        self.assertRaises(ParseException, lambda: FlagProp("this is another flag").parse(""))

    def test_prop_enum_flag(self):
        self.assertEqual(EnumFlagProp(DataType).parse("VARCHAR"), DataType.VARCHAR)

    def test_prop_identifier(self):
        self.assertEqual(IdentifierProp("label").parse("label = value"), "value")
        self.assertEqual(IdentifierProp("label").parse('label = "value"'), '"value"')
        self.assertEqual(IdentifierProp("label").parse('label = "schema"."table"'), '"schema"."table"')
        self.assertEqual(
            IdentifierProp("label").parse('label = database."schema"."table"'), 'database."schema"."table"'
        )
        self.assertEqual(
            IdentifierProp("request_translator").parse('request_translator = "DB"."SCHEMA".function'),
            '"DB"."SCHEMA".function',
        )

    def test_prop_int(self):
        self.assertEqual(IntProp("int_prop").parse("int_prop = 42"), 42)

    def test_prop_string(self):
        self.assertEqual(StringProp("string_prop").parse("STRING_PROP = 'quoted value'"), "quoted value")
        self.assertEqual(StringProp("multi label").parse("MULTI LABEL = VALUE"), "VALUE")

    def test_prop_tags(self):
        self.assertDictEqual(TagsProp().parse("TAG (moon_phase = 'waxing')"), {"moon_phase": "waxing"})
        self.assertDictEqual(TagsProp().parse("WITH TAG (a = 'b')"), {"a": "b"})

    def test_prop_time_travel(self):
        self.assertDictEqual(TimeTravelProp("at").parse("AT(TIMESTAMP => 123)"), {"TIMESTAMP": "123"})


class TestProps(unittest.TestCase):
    def test_props_render(self):
        db = Database(name="foo", comment="bar")
        rendered = db.props.render(db.to_dict())
        # data_retention and max_data_extension default to None, so only comment is rendered
        self.assertEqual(rendered, "COMMENT = $$bar$$")


# ============================================================================
# Additional comprehensive tests using pytest style
# ============================================================================


class TestQuoteValue:
    """Tests for the quote_value helper function."""

    def test_quote_value_normal_string(self):
        result = quote_value("hello world")
        assert result == "$$hello world$$"

    def test_quote_value_empty_string(self):
        result = quote_value("")
        assert result == "''"

    def test_quote_value_none(self):
        result = quote_value(None)
        assert result == "''"

    def test_quote_value_with_quotes(self):
        result = quote_value('it\'s a "test"')
        assert result == '$$it\'s a "test"$$'

    def test_quote_value_multiline(self):
        result = quote_value("line1\nline2")
        assert result == "$$line1\nline2$$"

    def test_quote_value_containing_dollar_quote(self):
        result = quote_value("costs $$ and it's dear")
        assert result == "'costs $$ and it''s dear'"

    def test_quote_value_containing_dollar_quote_and_backslash(self):
        result = quote_value("$$ path C:\\tmp")
        assert result == "'$$ path C:\\\\tmp'"

    def test_quote_value_containing_dollar_quote_and_newline(self):
        result = quote_value("costs $$\nper line")
        assert result == "'costs $$\\nper line'"

    def test_quote_value_containing_dollar_quote_and_carriage_return_tab(self):
        result = quote_value("$$\r\tx")
        assert result == "'$$\\r\\tx'"

    def test_quote_value_containing_dollar_quote_and_backspace_form_feed(self):
        result = quote_value("$$\b\fx")
        assert result == "'$$\\b\\fx'"

    def test_quote_value_containing_dollar_quote_and_nul(self):
        result = quote_value("$$\0x")
        assert result == "'$$\\u0000x'"


class TestBoolPropExtended:
    """Extended tests for BoolProp class."""

    def test_parse_true(self):
        prop = BoolProp("AUTO_RESUME")
        result = prop.parse("AUTO_RESUME = TRUE")
        assert result is True

    def test_parse_false(self):
        prop = BoolProp("AUTO_RESUME")
        result = prop.parse("AUTO_RESUME = FALSE")
        assert result is False

    def test_parse_case_insensitive(self):
        prop = BoolProp("ENABLED")
        result = prop.parse("ENABLED = true")
        assert result is True

    def test_typecheck_invalid_value(self):
        prop = BoolProp("ENABLED")
        with pytest.raises(ValueError, match="Invalid boolean value"):
            prop.typecheck("invalid")

    def test_render_true(self):
        prop = BoolProp("AUTO_RESUME")
        result = prop.render(True)
        assert result == "AUTO_RESUME = TRUE"

    def test_render_false(self):
        prop = BoolProp("AUTO_RESUME")
        result = prop.render(False)
        assert result == "AUTO_RESUME = FALSE"

    def test_render_none(self):
        prop = BoolProp("AUTO_RESUME")
        result = prop.render(None)
        assert result == ""

    def test_render_without_eq(self):
        prop = BoolProp("ENABLED", eq=False)
        result = prop.render(True)
        assert result == "ENABLED TRUE"


class TestIntPropExtended:
    """Extended tests for IntProp class."""

    def test_parse_integer(self):
        prop = IntProp("AUTO_SUSPEND")
        result = prop.parse("AUTO_SUSPEND = 300")
        assert result == 300

    def test_parse_zero(self):
        prop = IntProp("TIMEOUT")
        result = prop.parse("TIMEOUT = 0")
        assert result == 0

    def test_typecheck_invalid_integer(self):
        prop = IntProp("SIZE")
        with pytest.raises(ValueError, match="Invalid integer value"):
            prop.typecheck("not_a_number")

    def test_render_integer(self):
        prop = IntProp("AUTO_SUSPEND")
        result = prop.render(300)
        assert result == "AUTO_SUSPEND = 300"

    def test_render_zero(self):
        prop = IntProp("AUTO_SUSPEND")
        result = prop.render(0)
        assert result == "AUTO_SUSPEND = 0"

    def test_render_none(self):
        prop = IntProp("AUTO_SUSPEND")
        result = prop.render(None)
        assert result == ""

    def test_render_without_eq(self):
        prop = IntProp("SIZE", eq=False)
        result = prop.render(100)
        assert result == "SIZE 100"


class TestStringPropExtended:
    """Extended tests for StringProp class."""

    def test_parse_quoted_string(self):
        prop = StringProp("COMMENT")
        result = prop.parse("COMMENT = 'my comment'")
        assert result == "my comment"

    def test_typecheck_passthrough(self):
        prop = StringProp("COMMENT")
        result = prop.typecheck("any string value")
        assert result == "any string value"

    def test_render_string(self):
        prop = StringProp("COMMENT")
        result = prop.render("my comment")
        assert result == "COMMENT = $$my comment$$"

    def test_render_none(self):
        prop = StringProp("COMMENT")
        result = prop.render(None)
        assert result == ""

    def test_render_without_eq(self):
        prop = StringProp("DESC", eq=False)
        result = prop.render("test")
        assert result == "DESC $$test$$"


class TestFlagPropExtended:
    """Extended tests for FlagProp class."""

    def test_parse_flag_present(self):
        prop = FlagProp("COPY GRANTS")
        result = prop.parse("COPY GRANTS")
        assert result is True

    def test_typecheck_always_true(self):
        prop = FlagProp("VOLATILE")
        result = prop.typecheck(None)
        assert result is True

    def test_render_true(self):
        prop = FlagProp("COPY GRANTS")
        result = prop.render(True)
        assert result == "COPY GRANTS"

    def test_render_false(self):
        prop = FlagProp("COPY GRANTS")
        result = prop.render(False)
        assert result == ""


class TestIdentifierPropExtended:
    """Extended tests for IdentifierProp class."""

    def test_parse_simple_identifier(self):
        prop = IdentifierProp("WAREHOUSE")
        result = prop.parse("WAREHOUSE = MY_WAREHOUSE")
        assert result == "MY_WAREHOUSE"

    def test_parse_qualified_identifier(self):
        prop = IdentifierProp("STAGE")
        result = prop.parse("STAGE = DB.SCHEMA.MY_STAGE")
        assert result == "DB.SCHEMA.MY_STAGE"

    def test_typecheck_joins_parts(self):
        prop = IdentifierProp("TABLE")
        result = prop.typecheck(["DB", "SCHEMA", "TABLE"])
        assert result == "DB.SCHEMA.TABLE"

    def test_render_string(self):
        prop = IdentifierProp("WAREHOUSE")
        result = prop.render("MY_WAREHOUSE")
        assert result == "WAREHOUSE = MY_WAREHOUSE"

    def test_render_object_with_name(self):
        class MockResource:
            name = "MY_WAREHOUSE"

        prop = IdentifierProp("WAREHOUSE")
        result = prop.render(MockResource())
        assert result == "WAREHOUSE = MY_WAREHOUSE"

    def test_render_none(self):
        prop = IdentifierProp("WAREHOUSE")
        result = prop.render(None)
        assert result == ""


class TestIdentifierListPropExtended:
    """Tests for IdentifierListProp class."""

    def test_parse_single_identifier(self):
        prop = IdentifierListProp("INTEGRATIONS", parens=True)
        result = prop.parse("INTEGRATIONS = (MY_INTEGRATION)")
        assert result == ["MY_INTEGRATION"]

    def test_parse_multiple_identifiers(self):
        prop = IdentifierListProp("INTEGRATIONS", parens=True)
        result = prop.parse("INTEGRATIONS = (INT1, INT2, INT3)")
        assert result == ["INT1", "INT2", "INT3"]

    def test_typecheck_joins_parts(self):
        prop = IdentifierListProp("INTEGRATIONS")
        result = prop.typecheck([["DB", "SCHEMA", "INT1"], ["INT2"]])
        assert result == ["DB.SCHEMA.INT1", "INT2"]

    def test_render_list_with_parens(self):
        prop = IdentifierListProp("INTEGRATIONS", parens=True)
        result = prop.render(["INT1", "INT2"])
        assert result == "INTEGRATIONS = (INT1, INT2)"

    def test_render_list_without_parens(self):
        prop = IdentifierListProp("ROLES", parens=False)
        result = prop.render(["ROLE1", "ROLE2"])
        assert result == "ROLES = ROLE1, ROLE2"

    def test_render_none(self):
        prop = IdentifierListProp("INTEGRATIONS")
        result = prop.render(None)
        assert result == ""


class TestStringListPropExtended:
    """Tests for StringListProp class."""

    def test_parse_single_string(self):
        prop = StringListProp("PACKAGES", parens=True)
        result = prop.parse("PACKAGES = ('package1')")
        # Parser strips quotes from string values
        assert result == ["package1"]

    def test_parse_multiple_strings(self):
        prop = StringListProp("PACKAGES", parens=True)
        result = prop.parse("PACKAGES = ('pkg1', 'pkg2', 'pkg3')")
        # Parser strips quotes from string values
        assert result == ["pkg1", "pkg2", "pkg3"]

    def test_typecheck_strips_spaces(self):
        prop = StringListProp("PACKAGES")
        result = prop.typecheck([" value1 ", " value2 "])
        assert result == ["value1", "value2"]

    def test_render_list_with_parens(self):
        prop = StringListProp("PACKAGES", parens=True)
        result = prop.render(["pkg1", "pkg2"])
        assert result == "PACKAGES = ($$pkg1$$, $$pkg2$$)"

    def test_render_list_without_parens(self):
        prop = StringListProp("IMPORTS", parens=False)
        result = prop.render(["imp1", "imp2"])
        assert result == "IMPORTS = $$imp1$$, $$imp2$$"

    def test_render_none(self):
        prop = StringListProp("PACKAGES")
        result = prop.render(None)
        assert result == ""


class TestTagsPropExtended:
    """Extended tests for TagsProp class."""

    def test_parse_single_tag(self):
        prop = TagsProp()
        result = prop.parse("TAG (my_tag = 'value1')")
        assert result == {"my_tag": "value1"}

    def test_parse_multiple_tags(self):
        prop = TagsProp()
        result = prop.parse("TAG (tag1 = 'v1', tag2 = 'v2')")
        assert result == {"tag1": "v1", "tag2": "v2"}

    def test_render_single_tag(self):
        prop = TagsProp()
        result = prop.render({"my_tag": "value1"})
        assert result == "TAG (my_tag = 'value1')"

    def test_render_none(self):
        prop = TagsProp()
        result = prop.render(None)
        assert result == ""


class TestDictPropExtended:
    """Tests for DictProp class."""

    def test_parse_single_kv(self):
        prop = DictProp("HEADERS", parens=True)
        result = prop.parse("HEADERS = ('Content-Type' = 'application/json')")
        # Parser strips quotes from keys and values
        assert result == {"Content-Type": "application/json"}

    def test_render_dict(self):
        prop = DictProp("HEADERS", parens=True)
        result = prop.render({"Content-Type": "application/json"})
        assert result == "HEADERS = ('Content-Type' = 'application/json')"

    def test_render_none(self):
        prop = DictProp("HEADERS")
        result = prop.render(None)
        assert result == ""


class TestEnumPropExtended:
    """Extended tests for EnumProp class."""

    class SampleEnum(str, Enum):
        VALUE1 = "VALUE1"
        VALUE2 = "VALUE2"

    def test_parse_enum_value(self):
        prop = EnumProp("TYPE", self.SampleEnum)
        result = prop.parse("TYPE = VALUE1")
        assert result == self.SampleEnum.VALUE1

    def test_typecheck_valid_value(self):
        prop = EnumProp("TYPE", self.SampleEnum)
        result = prop.typecheck("VALUE1")
        assert result == self.SampleEnum.VALUE1

    def test_typecheck_invalid_value(self):
        prop = EnumProp("TYPE", self.SampleEnum)
        with pytest.raises(ValueError):
            prop.typecheck("INVALID")

    def test_render_enum(self):
        prop = EnumProp("TYPE", self.SampleEnum)
        result = prop.render(self.SampleEnum.VALUE1)
        assert result == "TYPE = VALUE1"

    def test_render_quoted(self):
        prop = EnumProp("TYPE", self.SampleEnum, quoted=True)
        result = prop.render(self.SampleEnum.VALUE1)
        assert result == "TYPE = 'VALUE1'"

    def test_render_none(self):
        prop = EnumProp("TYPE", self.SampleEnum)
        result = prop.render(None)
        assert result == ""


class TestEnumListPropExtended:
    """Tests for EnumListProp class."""

    class SampleEnum(str, Enum):
        A = "A"
        B = "B"
        C = "C"

    def test_parse_enum_list(self):
        prop = EnumListProp("VALUES", self.SampleEnum, parens=True)
        result = prop.parse("VALUES = (A, B, C)")
        assert result == [self.SampleEnum.A, self.SampleEnum.B, self.SampleEnum.C]

    def test_typecheck_valid_values(self):
        prop = EnumListProp("VALUES", self.SampleEnum)
        result = prop.typecheck(["A", "B"])
        assert result == [self.SampleEnum.A, self.SampleEnum.B]

    def test_typecheck_invalid_value(self):
        prop = EnumListProp("VALUES", self.SampleEnum)
        with pytest.raises(ValueError):
            prop.typecheck(["A", "INVALID"])

    def test_render_enum_list(self):
        prop = EnumListProp("VALUES", self.SampleEnum)
        result = prop.render([self.SampleEnum.A, self.SampleEnum.B])
        # Enum render includes the class name
        assert "VALUES = " in result
        assert "A" in result
        assert "B" in result

    def test_render_empty_list(self):
        prop = EnumListProp("VALUES", self.SampleEnum)
        result = prop.render([])
        assert result == ""

    def test_render_none(self):
        prop = EnumListProp("VALUES", self.SampleEnum)
        result = prop.render(None)
        assert result == ""


class TestEnumFlagPropExtended:
    """Extended tests for EnumFlagProp class."""

    class SampleEnum(str, Enum):
        VOLATILE = "VOLATILE"
        IMMUTABLE = "IMMUTABLE"

    def test_parse_flag(self):
        prop = EnumFlagProp(self.SampleEnum)
        result = prop.parse("VOLATILE")
        assert result == self.SampleEnum.VOLATILE

    def test_typecheck_valid(self):
        prop = EnumFlagProp(self.SampleEnum)
        result = prop.typecheck("VOLATILE")
        assert result == self.SampleEnum.VOLATILE

    def test_typecheck_invalid(self):
        prop = EnumFlagProp(self.SampleEnum)
        with pytest.raises(ValueError):
            prop.typecheck("INVALID")

    def test_render_flag(self):
        prop = EnumFlagProp(self.SampleEnum)
        result = prop.render(self.SampleEnum.VOLATILE)
        assert result == self.SampleEnum.VOLATILE

    def test_render_none(self):
        prop = EnumFlagProp(self.SampleEnum)
        result = prop.render(None)
        assert result == ""


class TestQueryPropExtended:
    """Tests for QueryProp class."""

    def test_parse_query(self):
        prop = QueryProp("AS")
        result = prop.parse("AS SELECT * FROM table")
        assert result == "SELECT * FROM table"

    def test_render_query(self):
        prop = QueryProp("AS")
        result = prop.render("SELECT * FROM table")
        assert result == "AS SELECT * FROM table"

    def test_render_none(self):
        prop = QueryProp("AS")
        result = prop.render(None)
        assert result == ""


class TestExpressionPropExtended:
    """Tests for ExpressionProp class."""

    def test_typecheck_strips_whitespace(self):
        prop = ExpressionProp("SCHEDULE")
        result = prop.typecheck("  every 1 hour  ")
        assert result == "every 1 hour"

    def test_render_expression(self):
        prop = ExpressionProp("SCHEDULE")
        result = prop.render("every 1 hour")
        assert result == "SCHEDULE every 1 hour"

    def test_render_none(self):
        prop = ExpressionProp("SCHEDULE")
        result = prop.render(None)
        assert result == ""


class TestTimeTravelPropExtended:
    """Extended tests for TimeTravelProp class."""

    def test_parse_timestamp(self):
        prop = TimeTravelProp("AT")
        result = prop.parse("AT (TIMESTAMP => '2021-01-01')")
        # Parser strips quotes from values
        assert result == {"TIMESTAMP": "2021-01-01"}

    def test_parse_offset(self):
        prop = TimeTravelProp("BEFORE")
        # Negative numbers need different handling in the parser
        result = prop.parse("BEFORE (OFFSET => 100)")
        assert result == {"OFFSET": "100"}

    def test_typecheck_creates_dict(self):
        prop = TimeTravelProp("AT")
        result = prop.typecheck(["TIMESTAMP", "2021-01-01"])
        assert result == {"TIMESTAMP": "2021-01-01"}

    def test_render_timestamp(self):
        prop = TimeTravelProp("AT")
        result = prop.render({"TIMESTAMP": "2021-01-01"})
        assert result == "AT (TIMESTAMP => 2021-01-01)"

    def test_render_stream(self):
        prop = TimeTravelProp("AT")
        result = prop.render({"STREAM": "my_stream"})
        assert result == "AT (STREAM => 'my_stream')"

    def test_render_none(self):
        prop = TimeTravelProp("AT")
        result = prop.render(None)
        assert result == ""


class TestAlertConditionPropExtended:
    """Extended tests for AlertConditionProp class."""

    def test_parse_alert_condition(self):
        prop = AlertConditionProp()
        result = prop.parse("IF (EXISTS (SELECT 1 FROM table))")
        assert result == "SELECT 1 FROM table"

    def test_typecheck_strips(self):
        prop = AlertConditionProp()
        result = prop.typecheck("  (SELECT 1)  ")
        # typecheck strips outer parens and whitespace
        assert result == "(SELECT 1)"

    def test_render_condition(self):
        prop = AlertConditionProp()
        result = prop.render("SELECT 1 FROM table")
        assert result == "IF(EXISTS( SELECT 1 FROM table ))"

    def test_render_none(self):
        prop = AlertConditionProp()
        result = prop.render(None)
        assert result == ""


class TestArgsPropExtended:
    """Extended tests for ArgsProp class."""

    def test_parse_empty_args(self):
        prop = ArgsProp()
        result = prop.parse("()")
        assert result == []

    def test_parse_single_arg(self):
        prop = ArgsProp()
        result = prop.parse("(x VARCHAR)")
        assert len(result) == 1
        assert result[0]["name"] == "x"
        assert result[0]["data_type"] == DataType.VARCHAR

    def test_parse_multiple_args(self):
        prop = ArgsProp()
        result = prop.parse("(x VARCHAR, y NUMBER)")
        assert len(result) == 2
        assert result[0]["name"] == "x"
        assert result[1]["name"] == "y"

    def test_render_empty_args(self):
        prop = ArgsProp()
        result = prop.render([])
        assert result == "()"

    def test_render_single_arg(self):
        prop = ArgsProp()
        result = prop.render([{"name": "x", "data_type": DataType.VARCHAR}])
        assert result == "(x VARCHAR)"

    def test_render_arg_with_default(self):
        prop = ArgsProp()
        result = prop.render([{"name": "x", "data_type": DataType.VARCHAR, "default": "'default'"}])
        assert result == "(x VARCHAR DEFAULT 'default')"

    def test_render_none(self):
        prop = ArgsProp()
        result = prop.render(None)
        assert result == "()"


class TestColumnNamesPropExtended:
    """Tests for ColumnNamesProp class."""

    def test_parse_single_column(self):
        prop = ColumnNamesProp()
        result = prop.parse("(col1)")
        assert len(result) == 1
        assert result[0]["name"] == "col1"

    def test_parse_column_with_comment(self):
        prop = ColumnNamesProp()
        result = prop.parse("(col1 COMMENT 'my comment')")
        assert len(result) == 1
        assert result[0]["name"] == "col1"
        assert result[0]["comment"] == "my comment"

    def test_parse_multiple_columns(self):
        prop = ColumnNamesProp()
        result = prop.parse("(col1, col2, col3)")
        assert len(result) == 3
        assert result[0]["name"] == "col1"
        assert result[1]["name"] == "col2"
        assert result[2]["name"] == "col3"

    def test_render_single_column(self):
        prop = ColumnNamesProp()
        result = prop.render([{"name": "col1"}])
        assert result == "(col1)"

    def test_render_column_with_comment(self):
        prop = ColumnNamesProp()
        result = prop.render([{"name": "col1", "comment": "my comment"}])
        assert result == "(col1 COMMENT 'my comment')"

    def test_render_empty(self):
        prop = ColumnNamesProp()
        result = prop.render([])
        assert result == "()"


class TestSchemaPropExtended:
    """Tests for SchemaProp class."""

    def test_render_single_column(self):
        prop = SchemaProp()
        result = prop.render([{"name": "col1", "data_type": DataType.VARCHAR, "not_null": False, "default": None}])
        assert result == "(col1 VARCHAR)"

    def test_render_column_with_not_null(self):
        prop = SchemaProp()
        result = prop.render([{"name": "col1", "data_type": DataType.NUMBER, "not_null": True, "default": None}])
        assert result == "(col1 NUMBER NOT NULL)"

    def test_render_column_with_string_default(self):
        prop = SchemaProp()
        result = prop.render([{"name": "col1", "data_type": DataType.VARCHAR, "not_null": False, "default": "hello"}])
        assert result == "(col1 VARCHAR DEFAULT 'hello')"

    def test_render_column_with_numeric_default(self):
        prop = SchemaProp()
        result = prop.render([{"name": "col1", "data_type": DataType.NUMBER, "not_null": False, "default": 42}])
        assert result == "(col1 NUMBER DEFAULT 42)"

    def test_render_column_with_comment(self):
        prop = SchemaProp()
        result = prop.render(
            [{"name": "col1", "data_type": DataType.VARCHAR, "not_null": False, "default": None, "comment": "test"}]
        )
        assert result == "(col1 VARCHAR COMMENT 'test')"

    def test_render_empty(self):
        prop = SchemaProp()
        result = prop.render([])
        assert result == "()"


class TestFromPropExtended:
    """Tests for FromProp class."""

    def test_parse_url(self):
        prop = FromProp()
        result = prop.parse("FROM = 'https://github.com/user/repo.git'")
        # Parser keeps quotes on single-quoted strings
        assert result == "'https://github.com/user/repo.git'"

    def test_typecheck_list_joins(self):
        prop = FromProp()
        result = prop.typecheck(["@", "my_stage"])
        assert result == "@my_stage"

    def test_typecheck_string_passthrough(self):
        prop = FromProp()
        result = prop.typecheck("https://example.com")
        assert result == "https://example.com"

    def test_render_stage(self):
        prop = FromProp()
        result = prop.render("@my_stage")
        assert result == "FROM @my_stage"

    def test_render_url(self):
        prop = FromProp()
        result = prop.render("https://github.com/user/repo.git")
        assert result == "FROM 'https://github.com/user/repo.git'"


class TestPropsContainerExtended:
    """Extended tests for Props container class."""

    def test_props_creation(self):
        props = Props(
            comment=StringProp("COMMENT"),
            auto_suspend=IntProp("AUTO_SUSPEND"),
        )
        assert len(props.props) == 2
        assert "comment" in props.props
        assert "auto_suspend" in props.props

    def test_props_getitem(self):
        props = Props(comment=StringProp("COMMENT"))
        prop = props["comment"]
        assert isinstance(prop, StringProp)

    def test_props_render(self):
        props = Props(
            comment=StringProp("COMMENT"),
            auto_suspend=IntProp("AUTO_SUSPEND"),
        )
        result = props.render({"comment": "test", "auto_suspend": 300})
        assert "COMMENT = $$test$$" in result
        assert "AUTO_SUSPEND = 300" in result

    def test_props_render_partial(self):
        props = Props(
            comment=StringProp("COMMENT"),
            auto_suspend=IntProp("AUTO_SUSPEND"),
        )
        result = props.render({"comment": "test"})
        assert "COMMENT = $$test$$" in result
        assert "AUTO_SUSPEND" not in result

    def test_props_render_empty(self):
        props = Props(comment=StringProp("COMMENT"))
        result = props.render({})
        assert result == ""

    def test_props_with_name(self):
        props = Props(_name="my_props", comment=StringProp("COMMENT"))
        assert props.name == "my_props"

    def test_props_repr(self):
        props = Props(
            comment=StringProp("COMMENT"),
            auto_suspend=IntProp("AUTO_SUSPEND"),
        )
        repr_str = repr(props)
        assert "Props" in repr_str
        assert "2" in repr_str


class TestPropSetExtended:
    """Tests for PropSet class."""

    def test_render_prop_set(self):
        inner_props = Props(
            type=StringProp("TYPE"),
            format=StringProp("FORMAT"),
        )
        prop = PropSet("FILE_FORMAT", inner_props)
        result = prop.render({"type": "CSV", "format": "RFC4180"})
        assert "FILE_FORMAT = (" in result
        assert "TYPE = $$CSV$$" in result

    def test_render_empty_prop_set(self):
        inner_props = Props(type=StringProp("TYPE"))
        prop = PropSet("FILE_FORMAT", inner_props)
        result = prop.render({})
        assert result == ""

    def test_render_none_prop_set(self):
        inner_props = Props(type=StringProp("TYPE"))
        prop = PropSet("FILE_FORMAT", inner_props)
        result = prop.render(None)
        assert result == ""


class TestPropListExtended:
    """Tests for PropList class."""

    def test_render_prop_list(self):
        inner_props = Props(name=StringProp("NAME"))
        struct_prop = StructProp(inner_props)
        prop = PropList("LOCATIONS", struct_prop)
        result = prop.render([{"name": "loc1"}, {"name": "loc2"}])
        assert "LOCATIONS = (" in result
        assert "NAME = $$loc1$$" in result
        assert "NAME = $$loc2$$" in result

    def test_render_empty_list(self):
        inner_props = Props(name=StringProp("NAME"))
        struct_prop = StructProp(inner_props)
        prop = PropList("LOCATIONS", struct_prop)
        result = prop.render([])
        assert result == ""

    def test_render_none(self):
        inner_props = Props(name=StringProp("NAME"))
        struct_prop = StructProp(inner_props)
        prop = PropList("LOCATIONS", struct_prop)
        result = prop.render(None)
        assert result == ""


class TestStructPropExtended:
    """Tests for StructProp class."""

    def test_render_struct(self):
        inner_props = Props(
            name=StringProp("NAME"),
            url=StringProp("URL"),
        )
        prop = StructProp(inner_props)
        result = prop.render({"name": "test", "url": "https://example.com"})
        assert result.startswith("(")
        assert result.endswith(")")
        assert "NAME = $$test$$" in result
        assert "URL = $$https://example.com$$" in result

    def test_render_none(self):
        inner_props = Props(name=StringProp("NAME"))
        prop = StructProp(inner_props)
        result = prop.render(None)
        assert result == ""


class TestReturnsPropExtended:
    """Tests for ReturnsProp class."""

    def test_parse_simple_type(self):
        prop = ReturnsProp("RETURNS", eq=False)
        result = prop.parse("RETURNS VARCHAR")
        assert result == "VARCHAR"

    def test_parse_type_with_size(self):
        prop = ReturnsProp("RETURNS", eq=False)
        result = prop.parse("RETURNS NUMBER(38,0)")
        assert "NUMBER" in result
        assert "(38,0)" in result

    def test_typecheck_joins_parts(self):
        prop = ReturnsProp("RETURNS")
        result = prop.typecheck(["NUMBER", "(38,0)"])
        assert result == "NUMBER(38,0)"

    def test_render_returns(self):
        prop = ReturnsProp("RETURNS", eq=False)
        result = prop.render("VARCHAR")
        assert result == "RETURNS VARCHAR"

    def test_render_none(self):
        prop = ReturnsProp("RETURNS")
        result = prop.render(None)
        assert result == ""
