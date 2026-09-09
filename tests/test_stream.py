import pytest

from snowcap import resources as res
from snowcap.blueprint import Blueprint, CreateResource, compile_plan_to_sql, diff
from snowcap.enums import AccountEdition, ResourceType
from snowcap.exceptions import MarkedForReplacementException
from snowcap.identifiers import parse_URN
from tests.helpers import flatten_sql_commands

ACCOUNT_URN = parse_URN("urn::ABCD123:account/ACCOUNT")

# Every Stream subtype is addressed as `ALTER STREAM ... SET ON <THING> <target>` by the
# generic update path if its source field isn't marked triggers_replacement -- Snowflake's
# ALTER STREAM has no syntax for changing a stream's source at all, regardless of subtype.
STREAM_TYPES = [
    pytest.param(res.TableStream, "on_table", True, "ON TABLE", id="table"),
    pytest.param(res.ViewStream, "on_view", True, "ON VIEW", id="view"),
    pytest.param(res.StageStream, "on_stage", False, "ON STAGE", id="stage"),
    pytest.param(res.DynamicTableStream, "on_dynamic_table", True, "ON DYNAMIC TABLE", id="dynamic_table"),
]


@pytest.fixture
def session_ctx() -> dict:
    return {
        "account": "SOMEACCT",
        "account_edition": AccountEdition.ENTERPRISE,
        "account_locator": "ABCD123",
        "role": "SYSADMIN",
        "available_roles": ["SYSADMIN"],
    }


def _stream_manifest(session_ctx, stream_cls, source_kwarg, target, **extra):
    db = res.Database(name="db")
    schema = res.Schema(name="schema", database=db)
    stream = stream_cls(name="my_stream", schema=schema, **{source_kwarg: target}, **extra)
    return Blueprint(resources=[db, schema, stream]).generate_manifest(session_ctx)


def _remote_state_from(manifest) -> dict:
    """The state snowcap would fetch back for everything an already-applied manifest declared."""
    remote = {urn: item.data for urn, item in manifest.items() if hasattr(item, "data")}
    remote[ACCOUNT_URN] = {}
    return remote


@pytest.mark.parametrize("stream_cls,source_kwarg,has_append_only,source_sql", STREAM_TYPES)
class TestStreamSourceReplacement:
    def test_create(self, session_ctx, stream_cls, source_kwarg, has_append_only, source_sql):
        manifest = _stream_manifest(session_ctx, stream_cls, source_kwarg, "db.schema.some_source")
        changes = diff({ACCOUNT_URN: {}}, manifest)

        stream_changes = [
            c for c in changes if isinstance(c, CreateResource) and c.urn.resource_type == ResourceType.STREAM
        ]
        assert len(stream_changes) == 1

        # on_stage is a plain string field, unlike the Table/View/DynamicTable references,
        # so it isn't normalized to uppercase the way the others are.
        commands = flatten_sql_commands(compile_plan_to_sql(session_ctx, stream_changes))
        assert any(f"{source_sql} db.schema.some_source".upper() in cmd.upper() for cmd in commands)

    def test_no_op_when_target_is_unchanged(self, session_ctx, stream_cls, source_kwarg, has_append_only, source_sql):
        before = _stream_manifest(session_ctx, stream_cls, source_kwarg, "db.schema.some_source")
        remote_state = _remote_state_from(before)

        after = _stream_manifest(session_ctx, stream_cls, source_kwarg, "db.schema.some_source")
        assert diff(remote_state, after) == []

    def test_changing_the_source_is_refused_as_a_replacement(
        self, session_ctx, stream_cls, source_kwarg, has_append_only, source_sql
    ):
        # Snowflake's ALTER STREAM has no syntax for changing a stream's source, so this
        # must be refused at plan time rather than emitting an ALTER that Snowflake rejects.
        before = _stream_manifest(session_ctx, stream_cls, source_kwarg, "db.schema.old_source")
        remote_state = _remote_state_from(before)

        after = _stream_manifest(session_ctx, stream_cls, source_kwarg, "db.schema.new_source")
        with pytest.raises(MarkedForReplacementException, match=source_kwarg) as exc_info:
            diff(remote_state, after)

        # The message has to tell the operator what changing the source actually costs.
        assert "resets its offset" in str(exc_info.value)

    def test_generated_sql_never_alters_the_stream_source(
        self, session_ctx, stream_cls, source_kwarg, has_append_only, source_sql
    ):
        # Regression tripwire: if the triggers_replacement metadata is ever removed, this
        # stops raising and diff() returns an UpdateResource instead -- at which point this
        # assertion is the thing that catches the invalid ALTER before it reaches a user.
        before = _stream_manifest(session_ctx, stream_cls, source_kwarg, "db.schema.old_source")
        remote_state = _remote_state_from(before)
        after = _stream_manifest(session_ctx, stream_cls, source_kwarg, "db.schema.new_source")

        try:
            changes = diff(remote_state, after)
        except MarkedForReplacementException:
            changes = []

        commands = flatten_sql_commands(compile_plan_to_sql(session_ctx, changes)) if changes else []
        assert not any(f"SET {source_sql}" in cmd for cmd in commands)

    def test_changing_append_only_is_also_refused_as_a_replacement(
        self, session_ctx, stream_cls, source_kwarg, has_append_only, source_sql
    ):
        # append_only is likewise fixed at creation -- ALTER STREAM can't flip it either.
        if not has_append_only:
            pytest.skip(f"{stream_cls.__name__} has no append_only field")

        before = _stream_manifest(session_ctx, stream_cls, source_kwarg, "db.schema.some_source")
        remote_state = _remote_state_from(before)

        after = _stream_manifest(session_ctx, stream_cls, source_kwarg, "db.schema.some_source", append_only=True)
        with pytest.raises(MarkedForReplacementException, match="append_only"):
            diff(remote_state, after)

    def test_comment_still_updates_in_place(
        self, session_ctx, stream_cls, source_kwarg, has_append_only, source_sql
    ):
        # comment is the one property Snowflake's ALTER STREAM actually supports changing.
        before = _stream_manifest(session_ctx, stream_cls, source_kwarg, "db.schema.some_source")
        remote_state = _remote_state_from(before)

        after = _stream_manifest(session_ctx, stream_cls, source_kwarg, "db.schema.some_source", comment="updated")
        changes = diff(remote_state, after)

        commands = flatten_sql_commands(compile_plan_to_sql(session_ctx, changes))
        assert any("ALTER STREAM" in cmd and "COMMENT" in cmd for cmd in commands)
        assert not any(f"SET {source_sql}" in cmd for cmd in commands)
