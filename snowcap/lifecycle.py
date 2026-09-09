import sys
from typing import Optional, Union

from inflection import pluralize

from .builder import tidy_sql
from .enums import GrantType, ResourceType
from .identifiers import FQN, URN
from .props import BoolProp, IntProp, Props, StringProp
from .resource_name import ResourceName

__this__ = sys.modules[__name__]


def fqn_to_sql(fqn: FQN):
    database = f"{ResourceName(fqn.database)}." if fqn.database else ""
    schema = f"{ResourceName(fqn.schema)}." if fqn.schema else ""
    name = ResourceName(fqn.name)
    return f"{database}{schema}{name}"


def _key_pair_user(urn: URN) -> ResourceName:
    """
    The user a key pair belongs to. Key pairs are addressed as `<name>?user=<username>`
    because Snowflake scopes them to a user rather than making them standalone objects.
    """
    user = urn.fqn.params.get("user")
    if not user:
        raise RuntimeError(f"Key pair urn is missing its user: {urn}")
    return ResourceName(user)


################ Create functions


def create_resource(urn: URN, data: dict, props: Props, if_not_exists: bool = False) -> str:
    return getattr(__this__, f"create_{urn.resource_label}", create__default)(urn, data, props, if_not_exists)


def create__default(urn: URN, data: dict, props: Props, if_not_exists: bool = False) -> str:
    return tidy_sql(
        "CREATE",
        urn.resource_type,
        "IF NOT EXISTS" if if_not_exists else "",
        fqn_to_sql(urn.fqn),
        props.render(data),
    )


def create_account_parameter(urn: URN, data: dict, props: Props, if_not_exists: bool = False) -> str:
    value = data["value"]
    if isinstance(value, str):
        value = f"'{value}'"
    return tidy_sql(
        "ALTER",
        "ACCOUNT",
        "SET",
        urn.fqn.name,
        "=",
        value,
    )


def create_aggregation_policy(urn: URN, data: dict, props: Props, if_not_exists: bool = False) -> str:
    return tidy_sql(
        "CREATE",
        "AGGREGATION POLICY",
        "IF NOT EXISTS" if if_not_exists else "",
        fqn_to_sql(urn.fqn),
        "AS () RETURNS AGGREGATION_CONSTRAINT",
        props.render(data),
    )


def create_database(urn: URN, data: dict, props: Props, if_not_exists: bool = False) -> str:
    data = data.copy()
    transient = data.pop("transient", None)
    return tidy_sql(
        "CREATE",
        "TRANSIENT" if transient else "",
        urn.resource_type,
        "IF NOT EXISTS" if if_not_exists else "",
        urn.fqn,
        props.render(data),
    )


def create_database_role_grant(urn: URN, data: dict, props: Props, if_not_exists: bool = False) -> str:
    if data["to_role"] is not None:
        to = data["to_role"]
        to_type = "ROLE"
    else:
        to = data["to_database_role"]
        to_type = "DATABASE ROLE"

    return tidy_sql(
        "GRANT",
        "DATABASE ROLE",
        data["database_role"],
        "TO",
        to_type,
        to,
    )


def create_function(urn: URN, data: dict, props: Props, if_not_exists: bool = False) -> str:
    db = f"{urn.fqn.database}." if urn.fqn.database else ""
    schema = f"{urn.fqn.schema}." if urn.fqn.schema else ""
    name = f"{db}{schema}{data['name']}"
    return tidy_sql(
        "CREATE",
        urn.resource_type,
        "IF NOT EXISTS" if if_not_exists else "",
        name,
        props.render(data),
    )


def create_hybrid_table(urn: URN, data: dict, props: Props, if_not_exists: bool = False) -> str:
    data = data.copy()
    columns = data.pop("columns", [])
    indexes = data.pop("indexes", None)

    # Render columns
    col_strs = []
    for column in columns:
        name = column["name"]
        data_type = str(column["data_type"])
        not_null = " NOT NULL" if column.get("not_null") else ""

        if isinstance(column.get("default"), str):
            default = f" DEFAULT '{column['default']}'"
        elif column.get("default") is not None:
            default = f" DEFAULT {column['default']}"
        else:
            default = ""

        comment = f" COMMENT '{column['comment']}'" if column.get("comment") else ""
        constraint = f" {column['constraint']}" if column.get("constraint") else ""
        col_strs.append(f"{name} {data_type}{not_null}{default}{comment}{constraint}")

    # Render indexes
    if indexes:
        for idx in indexes:
            idx_name = idx["name"]
            idx_columns = ", ".join(idx["columns"])
            idx_str = f"INDEX {idx_name} ({idx_columns})"
            if idx.get("include"):
                idx_include = ", ".join(idx["include"])
                idx_str += f" INCLUDE ({idx_include})"
            col_strs.append(idx_str)

    schema_sql = f"({', '.join(col_strs)})"

    return tidy_sql(
        "CREATE",
        urn.resource_type,
        "IF NOT EXISTS" if if_not_exists else "",
        fqn_to_sql(urn.fqn),
        schema_sql,
        props.render(data),
    )


def _grant_container_sql(data: dict) -> str:
    """Render the `IN <container>` clause of a collection grant.

    The account container has no name of its own, so it renders as a bare `IN ACCOUNT`.
    """
    if data["on_type"] == ResourceType.ACCOUNT:
        return "IN ACCOUNT"
    return f"IN {data['on_type']} {data['on']}"


def create_grant(urn: URN, data: dict, props: Props, if_not_exists: bool):
    on_type = data["on_type"]
    if "INTEGRATION" in str(on_type):
        on_type = "INTEGRATION"
    elif on_type == "ACCOUNT":
        on_type = ""
    if data["grant_type"] == GrantType.INHERITED:
        # A single container-level grant covering current and future objects. Snowflake
        # rejects WITH GRANT OPTION here, which the Grant resource validates up front.
        return tidy_sql(
            "GRANT INHERITED",
            data["priv"],
            "ON ALL",
            pluralize(data["items_type"]).upper(),
            _grant_container_sql(data),
            "TO",
            data["to_type"],
            data["to"],
        )
    if data["grant_type"] == GrantType.FUTURE:
        items_type = data["items_type"]
        if "INTEGRATION" in items_type:
            items_type = "INTEGRATION"
        return tidy_sql(
            "GRANT",
            data["priv"],
            "ON FUTURE",
            pluralize(items_type).upper(),
            "IN",
            data["on_type"],
            data["on"],
            "TO",
            data["to_type"],
            data["to"],
            "WITH GRANT OPTION" if data["grant_option"] else "",
        )
    elif data["grant_type"] == GrantType.ALL:
        items_type = data["items_type"]
        if "INTEGRATION" in items_type:
            items_type = "INTEGRATION"
        return tidy_sql(
            "GRANT",
            data["priv"],
            "ON ALL",
            pluralize(items_type).upper(),
            "IN",
            data["on_type"],
            data["on"],
            "TO",
            data["to_type"],
            data["to"],
            "WITH GRANT OPTION" if data["grant_option"] else "",
        )
    return tidy_sql(
        "GRANT",
        data["priv"],
        "ON",
        on_type,
        data["on"],
        "TO",
        data["to_type"],
        data["to"],
        "WITH GRANT OPTION" if data["grant_option"] else "",
    )


def create_masking_policy(urn: URN, data: dict, props: Props, if_not_exists: bool = False) -> str:
    return tidy_sql(
        "CREATE",
        urn.resource_type,
        "IF NOT EXISTS" if if_not_exists else "",
        urn.fqn,
        "AS",
        props.render(data),
    )


def create_procedure(urn: URN, data: dict, props: Props, if_not_exists: bool = False) -> str:
    if if_not_exists:
        raise Exception("IF NOT EXISTS not supported for CREATE PROCEDURE")
    db = f"{urn.fqn.database}." if urn.fqn.database else ""
    schema = f"{urn.fqn.schema}." if urn.fqn.schema else ""
    name = f"{db}{schema}{urn.fqn.name}"
    return tidy_sql(
        "CREATE",
        urn.resource_type,
        name,
        props.render(data),
    )


def create_row_access_policy(urn: URN, data: dict, props: Props, if_not_exists: bool = False) -> str:
    return tidy_sql(
        "CREATE",
        urn.resource_type,
        "IF NOT EXISTS" if if_not_exists else "",
        urn.fqn,
        "AS",
        props.render(data),
    )


def create_role_grant(urn: URN, data: dict, props: Props, if_not_exists: bool = False):
    if data["to_role"] is not None:
        to = data["to_role"]
        to_type = "ROLE"
    else:
        to = data["to_user"]
        to_type = "USER"
    return tidy_sql(
        "GRANT",
        "ROLE",
        data["role"],
        "TO",
        to_type,
        to,
    )


def create_scanner_package(urn: URN, data: dict, props: Props, if_not_exists: bool = False) -> str:
    package_name = f"'{urn.fqn.name}'"
    return tidy_sql(
        "CALL SNOWFLAKE.TRUST_CENTER.SET_CONFIGURATION(",
        "'ENABLED',",
        "'TRUE',",
        package_name,
        ")",
    )


def create_schema(urn: URN, data: dict, props: Props, if_not_exists: bool = False) -> str:
    data = data.copy()
    transient = data.pop("transient", None)
    return tidy_sql(
        "CREATE",
        "TRANSIENT" if transient else "",
        urn.resource_type,
        "IF NOT EXISTS" if if_not_exists else "",
        urn.fqn,
        props.render(data),
    )


def create_table(urn: URN, data: dict, props: Props, if_not_exists: bool = False) -> str:
    data = data.copy()
    transient = data.pop("transient", None)
    return tidy_sql(
        "CREATE",
        "TRANSIENT" if transient else "",
        urn.resource_type,
        "IF NOT EXISTS" if if_not_exists else "",
        urn.fqn,
        props.render(data),
    )


def create_tag_reference(urn: URN, data: dict, props: Props, if_not_exists: bool = False) -> str:
    tags_sql = ", ".join([f"{k}='{v}'" for k, v in data["tags"].items()])
    return tidy_sql(
        "ALTER",
        data["object_domain"],
        data["object_name"],
        "SET TAG",
        tags_sql,
    )


def create_tag_masking_policy_reference(urn: URN, data: dict, props: Props, if_not_exists: bool = False) -> str:
    return tidy_sql(
        "ALTER TAG",
        data["tag_name"],
        "SET MASKING POLICY",
        data["masking_policy_name"],
    )


def create_user_key_pair(urn: URN, data: dict, props: Props, if_not_exists: bool = False) -> str:
    # A named key pair isn't a standalone object: it is registered on a user with
    # ALTER USER ... ADD KEY PAIR. There is no IF NOT EXISTS form.
    return tidy_sql(
        "ALTER USER",
        _key_pair_user(urn),
        "ADD KEY PAIR",
        ResourceName(urn.fqn.name),
        props.render(data),
    )


def create_view(urn: URN, data: dict, props: Props, if_not_exists: bool = False) -> str:
    data = data.copy()
    secure = data.pop("secure", None)
    volatile = data.pop("volatile", None)
    recursive = data.pop("recursive", None)
    return tidy_sql(
        "CREATE",
        "SECURE" if secure else "",
        "VOLATILE" if volatile else "",
        "RECURSIVE" if recursive else "",
        urn.resource_type,
        "IF NOT EXISTS" if if_not_exists else "",
        urn.fqn,
        props.render(data),
    )


################ Update functions


def update_resource(urn: URN, data: dict, props: Props, after: Optional[dict] = None) -> Union[str, list[str]]:
    """
    The SQL for an update. Most handlers return a single ALTER statement; a handler is
    free to return a list when the change genuinely needs more than one statement.

    `after` is the full desired state of the resource. Handlers listed in
    UPDATE_HANDLERS_NEEDING_FULL_STATE receive it because their delta alone doesn't
    carry everything the SQL needs.
    """
    handler = getattr(__this__, f"update_{urn.resource_label}", update__default)
    if handler in UPDATE_HANDLERS_NEEDING_FULL_STATE:
        return handler(urn, data, props, after or {})
    return handler(urn, data, props)


def update__default(urn: URN, data: dict, props: Props) -> str:
    # Render every field in the delta into a single ALTER statement.
    # The previous implementation called `data.popitem()` and silently
    # discarded all other fields, so multi-field deltas (e.g. rotating
    # rsa_public_key + bumping comment on a USER in one apply) only
    # updated whichever field popitem happened to return.
    #
    # Snowflake's ALTER ... SET p1 = v1, p2 = v2 syntax accepts multiple
    # property assignments in one statement, and Props.render(data) already
    # iterates all keys — so the SET case is the common one and combines
    # cleanly. UNSET (value is None) must be a separate statement because
    # Snowflake disallows mixing SET and UNSET in one ALTER. RENAME TO and
    # owner remain as their own clauses (no Snowflake syntax exists to
    # combine them with SET/UNSET in one statement).

    if "name" in data and len(data) > 1:
        raise NotImplementedError(
            f"update__default cannot combine 'name' (RENAME TO) with other fields "
            f"in one ALTER for {urn}; got delta keys {sorted(data.keys())!r}"
        )
    if "owner" in data and len(data) > 1:
        raise NotImplementedError(
            f"update__default cannot combine 'owner' with other fields "
            f"in one ALTER for {urn}; got delta keys {sorted(data.keys())!r}"
        )
    if "name" in data:
        return tidy_sql("ALTER", urn.resource_type, urn.fqn, "RENAME TO", data["name"])
    if "owner" in data:
        raise NotImplementedError

    unset_attrs = [attr.lower() for attr, v in data.items() if v is None]
    set_data = {attr: v for attr, v in data.items() if v is not None}
    if unset_attrs and set_data:
        # Snowflake rejects mixing SET and UNSET in one ALTER. The caller's
        # diff layer is expected to keep these in separate change records,
        # so reaching here means something upstream batched them together.
        raise NotImplementedError(
            f"update__default cannot mix SET and UNSET attrs in one ALTER for {urn}; "
            f"got SET={sorted(set_data.keys())!r} UNSET={sorted(unset_attrs)!r}"
        )

    if unset_attrs:
        return tidy_sql("ALTER", urn.resource_type, urn.fqn, "UNSET", ", ".join(unset_attrs))
    return tidy_sql("ALTER", urn.resource_type, urn.fqn, "SET", props.render(set_data))


def update_masking_policy(urn: URN, data: dict, props: Props) -> str:
    attr, new_value = data.popitem()
    attr = attr.lower()
    if attr == "body":
        return tidy_sql("ALTER", urn.resource_type, fqn_to_sql(urn.fqn), "SET BODY", props.render({"body": new_value}))
    else:
        return update__default(urn, {attr: new_value}, props)


def update_mcp_server(urn: URN, data: dict, props: Props) -> str:
    # Snowflake has no ALTER MCP SERVER command. A rename is impossible regardless
    # of what else changed, so it takes precedence over a specification change.
    if "name" in data:
        raise NotImplementedError(
            "Snowflake does not support renaming MCP servers (no ALTER MCP SERVER command); "
            "rename requires dropping and recreating the server"
        )
    return tidy_sql(
        "CREATE OR REPLACE",
        urn.resource_type,
        fqn_to_sql(urn.fqn),
        props.render({"specification": data["specification"]}),
    )


def update_account_parameter(urn: URN, data: dict, props: Props) -> str:
    return create_account_parameter(urn, data, props)


def update_tag_masking_policy_reference(urn: URN, data: dict, props: Props) -> str:
    """
    Return the UNSET statement for a tag masking policy binding change.

    A masking policy binding update requires two steps:
        1. ALTER TAG <tag> UNSET MASKING POLICY <old_policy>  ← this function
        2. ALTER TAG <tag> SET MASKING POLICY <new_policy>    ← emitted as after_change_cmd
           in blueprint.sql_commands_for_change

    Using urn.fqn directly would produce malformed SQL because
    TagMaskingPolicyReference encodes the masking policy name as a URN query-string
    param (TAG?masking_policy=POLICY), not as a plain SQL identifier.
    """
    tag_sql = fqn_to_sql(urn.fqn)
    old_masking_policy = urn.fqn.params.get("masking_policy", "")
    return tidy_sql("ALTER TAG", tag_sql, "UNSET MASKING POLICY", old_masking_policy)


def update_event_table(urn: URN, data: dict, props: Props) -> str:
    new_urn = URN(ResourceType.TABLE, urn.fqn, urn.account_locator)
    return update__default(new_urn, data, props)


def update_procedure(urn: URN, data: dict, props: Props) -> str:
    if "execute_as" in data:
        return tidy_sql(
            "ALTER",
            urn.resource_type,
            urn.fqn,
            "EXECUTE AS",
            data["execute_as"],
        )
    else:
        return update__default(urn, data, props)


def update_role_grant(urn: URN, data: dict, props: Props) -> str:
    raise NotImplementedError


def update_scanner_package(urn: URN, data: dict, props: Props) -> str:
    package_name = f"'{urn.fqn.name}'"
    attr, new_value = data.popitem()
    if attr == "schedule":
        new_value = f"'USING CRON {new_value}'"
    else:
        new_value = f"'{new_value}'"
    return tidy_sql(
        "CALL SNOWFLAKE.TRUST_CENTER.SET_CONFIGURATION(",
        f"'{attr}',",
        new_value,
        ",",
        package_name,
        ")",
    )


def update_schema(urn: URN, data: dict, props: Props) -> str:
    attr, new_value = data.popitem()
    attr = attr.lower()
    if new_value is None:
        return tidy_sql("ALTER SCHEMA", urn.fqn, "UNSET", attr)
    elif attr == "name":
        return tidy_sql("ALTER SCHEMA", urn.fqn, "RENAME TO", new_value)
    elif attr == "owner":
        raise NotImplementedError
    elif attr == "transient":
        raise Exception("Cannot change transient property of schema")
    elif attr == "managed_access":
        return tidy_sql("ALTER SCHEMA", urn.fqn, "ENABLE" if new_value else "DISABLE", "MANAGED ACCESS")
    else:
        new_value = f"'{new_value}'" if isinstance(new_value, str) else new_value
        return tidy_sql("ALTER SCHEMA", urn.fqn, "SET", attr, "=", new_value)


def update_table(urn: URN, data: dict, props: Props) -> str:
    attr, new_value = data.popitem()
    attr = attr.lower()
    if attr == "columns":
        raise NotImplementedError(data)
    else:
        return update__default(urn, {attr: new_value}, props)


# FIXME
# The AFTER attribute on tasks is one of the only attributes that is stateful,
# which means that you need to know the current value in order to modify it.
# This is a problem because we don't have a concept of "current value" for lifecycle updates
# and so we can't know what value to set.
def update_task(urn: URN, data: dict, props: Props) -> str:
    # as_ (MODIFY AS), when (MODIFY/REMOVE WHEN), and state (RESUME/SUSPEND) each need
    # bespoke ALTER syntax that can't be combined with a SET, so they must arrive on their
    # own. Everything else flows through update__default, which renders multi-field deltas
    # in one ALTER without dropping any (an arbitrary popitem() here would silently lose the
    # rest of the delta).
    special = [attr for attr in ("as_", "when", "state") if attr in data]
    if not special:
        return update__default(urn, data, props)
    if len(data) > 1:
        raise NotImplementedError(
            f"update_task cannot combine {special!r} with other fields in one ALTER for {urn}; "
            f"got delta keys {sorted(data.keys())!r}"
        )
    attr = special[0]
    new_value = data[attr]
    if attr == "as_":
        return tidy_sql("ALTER TASK", urn.fqn, "MODIFY", "AS", new_value)
    if attr == "when":
        if new_value is None:
            return tidy_sql("ALTER TASK", urn.fqn, "REMOVE", "WHEN")
        return tidy_sql("ALTER TASK", urn.fqn, "MODIFY", "WHEN", new_value)
    # attr == "state"
    change_verb = "RESUME" if new_value == "STARTED" else "SUSPEND"
    return tidy_sql("ALTER TASK", urn.fqn, change_verb)


def update_alert(urn: URN, data: dict, props: Props) -> str:
    # Alerts, like tasks, reach STARTED via ALTER ALERT ... RESUME rather than a CREATE
    # clause, and RESUME/SUSPEND can't be combined with a SET in one statement. Handle state
    # on its own; delegate every other field to update__default, which renders multi-field
    # deltas without dropping any (an arbitrary popitem() here would silently lose the rest).
    # Read data without mutating it: it is the live change.delta, passed by reference.
    if "state" not in data:
        return update__default(urn, data, props)
    if len(data) > 1:
        raise NotImplementedError(
            f"update_alert cannot combine 'state' (RESUME/SUSPEND) with other fields in one "
            f"ALTER for {urn}; got delta keys {sorted(data.keys())!r}"
        )
    change_verb = "RESUME" if data["state"] == "STARTED" else "SUSPEND"
    return tidy_sql("ALTER ALERT", urn.fqn, change_verb)


def update_iceberg_table(urn: URN, data: dict, props: Props) -> str:
    attr, new_value = data.popitem()
    attr = attr.lower()
    if attr == "columns":
        raise NotImplementedError(data)
    else:
        return update__default(urn, {attr: new_value}, props)


def update_user_key_pair(urn: URN, data: dict, props: Props, after: dict) -> list[str]:
    """
    Key pair changes don't fit the single ALTER ... SET shape: rotating the key, renaming
    the key pair, and setting its properties are three different Snowflake commands. This
    returns the statements the change needs, in the order they have to run.

    A new public key reaches this function as a fingerprint change -- Snowflake only ever
    reports a key pair's fingerprint, so that is what drift is detected on -- and the key
    the fingerprint was computed from is read from the desired state.
    """
    user = _key_pair_user(urn)
    key_pair = ResourceName(urn.fqn.name)
    data = data.copy()
    statements = []

    if data.pop("fingerprint", None) is not None:
        public_key = after.get("public_key")
        if not public_key:
            raise NotImplementedError(f"Cannot rotate key pair {urn}: the new public key is missing from the plan")
        # The prior key stays valid for a grace period so clients that haven't picked up
        # the new key yet keep authenticating. Snowflake's default is 24 hours;
        # expire_rotated_key_pair_after_hours overrides it, and 0 revokes it immediately.
        expire_after_hours = after.get("expire_rotated_key_pair_after_hours")
        statements.append(
            tidy_sql(
                "ALTER USER",
                user,
                "ROTATE KEY PAIR",
                key_pair,
                StringProp("public_key").render(public_key),
                IntProp("expire_rotated_key_pair_after_hours").render(expire_after_hours),
            )
        )

    set_data = {attr: data.pop(attr) for attr in ("disabled", "comment") if attr in data}
    if set_data:
        modify_props = Props(disabled=BoolProp("disabled"), comment=StringProp("comment"))
        statements.append(
            tidy_sql("ALTER USER", user, "MODIFY KEY PAIR", key_pair, "SET", modify_props.render(set_data))
        )

    if data:
        # Everything else about a key pair is fixed at registration. Fail loudly rather
        # than emit SQL that silently drops the change.
        raise NotImplementedError(f"Cannot update {sorted(data.keys())} on {urn}")

    return statements


# Handlers whose delta doesn't carry everything their SQL needs, so update_resource hands
# them the full desired state as well.
UPDATE_HANDLERS_NEEDING_FULL_STATE = (update_user_key_pair,)


################ Drop functions


def drop_resource(urn: URN, data: dict, if_exists: bool = False) -> str:
    return getattr(__this__, f"drop_{urn.resource_label}", drop__default)(urn, data, if_exists=if_exists)


def drop__default(urn: URN, data: dict, if_exists: bool) -> str:
    return tidy_sql(
        "DROP",
        urn.resource_type,
        "IF EXISTS" if if_exists else "",
        fqn_to_sql(urn.fqn),
    )


def drop_account_parameter(urn: URN, data: dict, if_exists: bool) -> str:
    return tidy_sql(
        "ALTER",
        "ACCOUNT",
        "UNSET",
        urn.fqn.name,
    )


def drop_database(urn: URN, data: dict, if_exists: bool) -> str:
    return tidy_sql(
        "DROP",
        urn.resource_type,
        "IF EXISTS" if if_exists else "",
        urn.fqn,
        "RESTRICT",
    )


def drop_database_role_grant(urn: URN, data: dict, **kwargs):

    from_type = "ROLE" if data["to_role"] else "DATABASE ROLE"
    from_name = data["to_role"] if data["to_role"] else data["to_database_role"]

    return tidy_sql(
        "REVOKE DATABASE ROLE",
        ResourceName(data["database_role"]),
        "FROM",
        from_type,
        ResourceName(from_name),
    )


def drop_shared_database_grant(data: dict, database: str) -> str:
    """
    Revoke a grant that a share handed out, given any one row of its fan-out.

    Privileges on a shared database are not independently revocable. Snowflake grants them
    with one statement, GRANT IMPORTED PRIVILEGES ON DATABASE <db>, then reports them in
    SHOW GRANTS as a row per object the share exposes -- USAGE on the database, USAGE on
    each schema, SELECT on each view, and so on. Revoking any of those rows on its own is
    rejected:

        Revoking individual privileges on imported database is not allowed.
        Use 'REVOKE IMPORTED PRIVILEGES'

    The share is the only source of privileges on those objects, so revoking IMPORTED
    PRIVILEGES removes the whole fan-out for that grantee in one statement. Every row of the
    fan-out therefore maps to the same revoke, which is idempotent: the first one takes the
    access away and any repeat finds nothing left to revoke.
    """
    return tidy_sql(
        "REVOKE IMPORTED PRIVILEGES ON DATABASE",
        ResourceName(database),
        "FROM",
        data["to_type"],
        data["to"],
    )


def drop_function(urn: URN, data: dict, if_exists: bool) -> str:
    return tidy_sql(
        "DROP",
        urn.resource_type,
        "IF EXISTS" if if_exists else "",
        urn.fqn,
    )


def drop_grant(urn: URN, data: dict, **kwargs):
    if data["priv"] == "OWNERSHIP":
        raise NotImplementedError
    if data["grant_type"] == GrantType.INHERITED:
        return tidy_sql(
            "REVOKE INHERITED",
            data["priv"],
            "ON ALL",
            pluralize(data["items_type"]).upper(),
            _grant_container_sql(data),
            "FROM",
            data["to_type"],
            data["to"],
        )
    if data["grant_type"] == GrantType.FUTURE:
        return tidy_sql(
            "REVOKE",
            data["priv"],
            "ON FUTURE",
            pluralize(data["items_type"]).upper(),
            "IN",
            data["on_type"],
            data["on"],
            "FROM",
            data["to_type"],
            data["to"],
        )
    elif data["grant_type"] == GrantType.ALL:
        return tidy_sql(
            "REVOKE",
            data["priv"],
            "ON ALL",
            pluralize(data["items_type"]).upper(),
            "IN",
            data["on_type"],
            data["on"],
            "FROM",
            data["to_type"],
            data["to"],
        )
    else:
        return tidy_sql(
            "REVOKE",
            data["priv"],
            "ON",
            data["on_type"],
            data["on"] if data["on_type"] != "ACCOUNT" else "",
            "FROM",
            data["to_type"],
            data["to"],
            # "CASCADE" if cascade else "RESTRICT",
        )


def drop_procedure(urn: URN, data: dict, if_exists: bool) -> str:
    return tidy_sql(
        "DROP",
        urn.resource_type,
        "IF EXISTS" if if_exists else "",
        urn.fqn,
        # data["returns"],
    )


def drop_role_grant(urn: URN, data: dict, **kwargs):
    return tidy_sql(
        "REVOKE ROLE",
        ResourceName(data["role"]),
        "FROM",
        "ROLE" if data.get("to_role") else "USER",
        ResourceName(data["to_role"] if data.get("to_role") else data["to_user"]),
    )


def drop_scanner_package(urn: URN, data: dict, **kwargs) -> str:
    package_name = f"'{urn.fqn.name}'"
    return tidy_sql(
        "CALL SNOWFLAKE.TRUST_CENTER.SET_CONFIGURATION(",
        "'ENABLED',",
        "'FALSE',",
        package_name,
        ")",
    )


def drop_tag_masking_policy_reference(urn: URN, data: dict, **kwargs) -> str:
    return tidy_sql(
        "ALTER TAG",
        data["tag_name"],
        "UNSET MASKING POLICY",
        data["masking_policy_name"],
    )


def drop_user_key_pair(urn: URN, data: dict, if_exists: bool = False, **kwargs) -> str:
    # IF EXISTS guards the user, which is the object being altered. A removed key pair
    # cannot be recovered; to keep the metadata, disable it instead.
    return tidy_sql(
        "ALTER USER",
        "IF EXISTS" if if_exists else "",
        _key_pair_user(urn),
        "REMOVE KEY PAIR",
        ResourceName(urn.fqn.name),
    )


################ Transfer functions


def transfer_resource(
    urn: URN,
    owner: str,
    owner_resource_type: ResourceType,
    copy_current_grants: bool = False,
    revoke_current_grants: bool = False,
) -> str:
    return getattr(__this__, f"transfer_{urn.resource_label}", transfer__default)(
        urn,
        owner,
        owner_resource_type,
        copy_current_grants,
        revoke_current_grants,
    )


def transfer__default(
    urn: URN,
    owner: str,
    owner_resource_type: ResourceType,
    copy_current_grants: bool = False,
    revoke_current_grants: bool = False,
) -> str:
    return tidy_sql(
        "GRANT OWNERSHIP ON",
        urn.resource_type,
        urn.fqn,
        "TO",
        owner_resource_type,
        owner,
        "REVOKE CURRENT GRANTS" if revoke_current_grants else "",
        "COPY CURRENT GRANTS" if copy_current_grants else "",
    )
