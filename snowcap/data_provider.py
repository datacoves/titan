import datetime
import inspect
import json
import logging
import sys
import threading
from typing import Any, Optional, TypedDict, Union

import pytz
from inflection import pluralize
from snowflake.connector import SnowflakeConnection
from snowflake.connector.errors import ProgrammingError

from .builtins import (
    ALWAYS_BLOCKED_OAUTH_ROLES,
    SYSTEM_DATABASES,
    SYSTEM_ROLES,
    SYSTEM_SECURITY_INTEGRATIONS,
    SYSTEM_USERS,
)
from .client import (
    ACCESS_CONTROL_ERR,
    DOES_NOT_EXIST_ERR,
    INVALID_COLUMN_ERR,
    INVALID_IDENTIFIER,
    OBJECT_DOES_NOT_EXIST_ERR,
    UNSUPPORTED_FEATURE,
    execute,
    execute_in_parallel,
    register_cache_reset_hook,
)
from .enums import (
    INHERITED_GRANTS_FEATURE_FLAG,
    AccountEdition,
    GrantType,
    ResourceType,
    WarehouseSize,
)
from .identifiers import FQN, URN, parse_FQN, resource_label_for_type, resource_type_for_label, smart_split
from .parse import (
    _parse_column,
    _parse_dynamic_table_text,
    format_collection_string,
    parse_collection_string,
    parse_region,
    parse_view_ddl,
)
from .privs import GrantedPrivilege
from .resource_name import (
    ResourceName,
    attribute_is_resource_name,
    resource_name_from_snowflake_metadata,
)
from .resources.authentication_policy import _PAT_POLICY_DEFAULT
from .resources.security_integration import _canonicalize_role_name
from .public_key import normalize_fingerprint
from .resources.user_key_pair import RESERVED_KEY_PAIR_NAMES
from .resources.warehouse import ADAPTIVE_UNSUPPORTED_FIELDS

__this__ = sys.modules[__name__]

logger = logging.getLogger("snowcap")

# Cache for inspect.signature() results to avoid repeated introspection
_SIGNATURE_CACHE: dict[str, inspect.Signature] = {}


def _get_cached_signature(func_name: str) -> inspect.Signature:
    """Get the signature for a function, caching the result."""
    if func_name not in _SIGNATURE_CACHE:
        func = getattr(__this__, func_name)
        _SIGNATURE_CACHE[func_name] = inspect.signature(func)
    return _SIGNATURE_CACHE[func_name]


class SessionContext(TypedDict):
    account_edition: AccountEdition
    account_grant_map: dict[str, list[ResourceName]]
    account_locator: str
    account: str
    available_roles: list[ResourceName]
    cloud_region: str
    cloud: str
    database: str
    role: ResourceName
    schemas: list[str]
    secondary_roles: list[str]
    user: str
    version: str
    warehouse: str


def _quote_snowflake_identifier(identifier: Union[str, ResourceName]) -> str:
    return str(resource_name_from_snowflake_metadata(identifier))


def _get_owner_identifier(data: dict) -> str:
    if "owner_role_type" not in data:
        # Some metadata sources (eg SYSTEM$SHOW_IMPORTED_DATABASES on some editions)
        # may omit the owner field; degrade to drift instead of crashing the plan.
        owner = data.get("owner")
        if not owner:
            return ""
        return _quote_snowflake_identifier(owner)
    if data["owner"] == "":
        return ""
    if data["owner_role_type"] == "DATABASE_ROLE":
        return _quote_snowflake_identifier(data["database_name"]) + "." + _quote_snowflake_identifier(data["owner"])
    elif data["owner_role_type"] == "ROLE":
        return _quote_snowflake_identifier(data["owner"])
    else:
        raise Exception(f"Unsupported owner role type: {data['owner_role_type']}, {data}")


def _desc_result_to_dict(desc_result, lower_properties=False):
    result = {}
    for row in desc_result:
        property = row["property"]
        if lower_properties:
            property = property.lower()
        result[property] = row["value"]
    return result


def _desc_type2_result_to_dict(desc_result, lower_properties=False):
    result = {}
    for row in desc_result:
        property = row["property"]
        if lower_properties:
            property = property.lower()
        value = row["property_value"]
        if row["property_type"] == "Boolean":
            value = value == "true"
        elif row["property_type"] == "Long":
            value = value or None
        elif row["property_type"] == "Integer":
            value = int(value)
        elif row["property_type"] == "String":
            value = value or None
        elif row["property_type"] == "List":
            value = _parse_list_property(value)
        # Not sure this is correct. External Access Integration uses this
        elif row["property_type"] == "Object":
            value = _parse_list_property(value)
        result[property] = value
    return result


def _desc_type3_result_to_dict(desc_result, lower_properties=False):
    result = {}
    for row in desc_result:
        parent_property = row["parent_property"]
        property = row["property"]
        if lower_properties:
            parent_property = parent_property.lower()
            property = property.lower()
        value = row["property_value"]
        if row["property_type"] == "Boolean":
            value = value == "true"
        elif row["property_type"] == "Long":
            value = value or None
        elif row["property_type"] == "Integer":
            value = int(value)
        elif row["property_type"] == "String":
            value = value or None
        elif row["property_type"] == "List":
            value = _parse_list_property(value)

        if parent_property:
            if parent_property not in result:
                result[parent_property] = {}
            result[parent_property][property] = value
        else:
            result[property] = value
    return result


def _desc_type4_result_to_dict(desc_result, lower_properties=False):
    result = {}
    for row in desc_result:
        property = row["name"]
        if lower_properties:
            property = property.lower()
        result[property] = row["value"]

    return result


def _fail_if_not_granted(result, *args):
    if len(result) == 0:
        raise Exception("Failed to create grant")
    if len(result) == 1 and result[0]["status"] == "Grant not executed: Insufficient privileges.":
        raise Exception(result[0]["status"], *args)


def _is_inherited_grant(row: dict[str, Any]) -> bool:
    """
    True when a grant row was produced by an inherited grant (GRANT INHERITED ...).

    An inherited grant is a container-level grant that applies to every current and future
    object of a type in an ACCOUNT, DATABASE, or SCHEMA. Snowflake reports these rows in
    SHOW GRANTS and in ACCOUNT_USAGE.GRANTS_TO_ROLES with IS_INHERITED set, and with an
    empty NAME, because the grant is defined on the container rather than on individual
    securables.

    Accounts that have not enabled FEATURE_RBAC_INHERITED_GRANTS never produce these rows,
    and older Snowflake versions do not return the column at all, so a missing column reads
    as "not inherited".
    """
    for key in ("is_inherited", "IS_INHERITED"):
        if key in row:
            value = row[key]
            if isinstance(value, str):
                return value.strip().lower() in ("true", "t", "yes", "y")
            return bool(value)
    return False


def _is_role_hierarchy_grant(row: dict[str, Any]) -> bool:
    """
    True when a grant row describes one role being granted to another.

    Snowflake reports granting a role as a grant held by the grantee, so SHOW GRANTS and
    ACCOUNT_USAGE return these alongside object grants. Snowcap models them separately, as
    RoleGrant and DatabaseRoleGrant, listed by list_role_grants() and
    list_database_role_grants(). Listing them as Grants as well would describe the same
    Snowflake fact under two resource types, so the declared grant never matches the one
    read back and sync proposes dropping it on every run.

    That drop is also unrunnable for a database role: a Grant revokes with
    REVOKE <priv> ON <on_type> ..., which for a database role reads REVOKE USAGE ON
    DATABASE ROLE, and Snowflake rejects it as an unsupported feature. The revoke database
    roles actually take is REVOKE DATABASE ROLE <name> FROM ROLE <grantee>, which
    DatabaseRoleGrant already builds.

    ACCOUNT_USAGE spells the type DATABASE_ROLE and SHOW GRANTS spells it DATABASE ROLE,
    so both are matched.
    """
    return row["granted_on"].replace("_", " ").upper() in ("ROLE", "DATABASE ROLE")


def _is_intrinsic_database_role_usage(row: dict[str, Any], grantee: str) -> bool:
    """
    True when a row is the USAGE on its own database that a database role is born with.

    Creating a database role gives it USAGE on the database it belongs to. Snowflake
    reports that in SHOW GRANTS like any other grant, but with an empty granted_by and a
    timestamp matching the CREATE, because no role granted it -- it is part of the role
    existing, the way OWNERSHIP is.

    Nothing can revoke it. REVOKE reports success and leaves it in place, even run as the
    database owner, so listing it as a grant puts a row in remote state that no config can
    declare away and no apply can remove: sync proposes the same drop on every run, forever.

    An explicitly granted USAGE on the same database is a second, separate row with
    granted_by populated. The two are indistinguishable once reduced to a grant URN, so
    this skips both and a declared USAGE on a database role's own database simply re-grants
    each apply -- harmless, since the role already has it.
    """
    if row["privilege"] != "USAGE":
        return False
    if row["granted_on"].replace("_", " ").upper() != "DATABASE":
        return False
    if "." not in grantee:
        return False
    return str(row["name"]).upper() == grantee.split(".")[0].upper()


def _imported_privileges_priv(row: dict[str, Any], shared_databases: set[str]) -> Optional[str]:
    """
    The privilege a grant on a share-backed database should be identified by.

    GRANT IMPORTED PRIVILEGES ON DATABASE <db> is how access to a shared database is given,
    and Snowflake reports the resulting grant on the database as plain USAGE. Identifying
    it as USAGE means the declared grant never matches the one read back, so every plan
    proposes creating it again -- forever, and invisibly, since re-granting changes nothing.

    fetch_grant already resolves this, but syncing a resource type builds remote state from
    list_* alone and discards the manifest URNs, so that path never runs for a synced grant.

    Returns None for anything else, including USAGE on an ordinary database, where USAGE
    means USAGE.
    """
    if row["privilege"] != "USAGE":
        return None
    if row["granted_on"].replace("_", " ").upper() != "DATABASE":
        return None
    if str(row["name"]).upper() not in shared_databases:
        return None
    return "IMPORTED PRIVILEGES"


def _granted_on_label(granted_on: str) -> str:
    """
    The object-type half of a grant URN's `on`, normalized the way the manifest builds it.

    Snowflake sometimes reports a grant against a different name than the one its DDL uses:
    SHOW GRANTS says CORTEX_AGENT_SERVER for the object GRANT and CREATE call an MCP SERVER.
    ResourceType maps those synonyms, and grant_fqn runs the manifest side through
    resource_label_for_type, so going through the same function here is what makes the two
    sides comparable.

    Taking the raw string instead leaves remote state identifying the grant as
    cortex_agent_server/... while the manifest calls it mcp_server/..., so the declared grant
    never matches the one read back. Every plan then both creates and drops it, and since
    drops run after creates, applying takes the access away.

    ResourceType spells its members with spaces and Snowflake uses underscores, hence the
    substitution. For every type that is not a synonym this returns exactly what
    granted_on.lower() did, and anything ResourceType does not know falls back to it.
    """
    try:
        return resource_label_for_type(ResourceType(granted_on.replace("_", " ")))
    except ValueError:
        return granted_on.lower()


def _normalize_future_grant_name(name: str) -> str:
    """Normalize the <OBJECT_TYPE> a SHOW FUTURE GRANTS name embeds (e.g. `DB.SCH.<TABLE>`)
    through ResourceType, so a synonym type -- SHOW reports CORTEX_AGENT_SERVER for what the
    manifest calls MCP_SERVER -- matches the declared grant instead of forcing a non-converging
    DROP+CREATE that revokes the future grant. No-op for non-synonym and unknown types."""
    prefix, sep, bracketed = name.rpartition(".")
    if not sep or not (bracketed.startswith("<") and bracketed.endswith(">")):
        return name
    try:
        canonical = str(ResourceType(bracketed[1:-1].replace("_", " "))).replace(" ", "_")
    except ValueError:
        return name
    return f"{prefix}.<{canonical}>"


def inherited_grant_fqn(grant: dict[str, Any], to_label: str, grantee: str) -> Optional[FQN]:
    """
    Build the URN-level identity of an inherited grant from a SHOW GRANTS row.

    Returns None when the row does not name a container Snowcap understands, so an
    unrecognized INHERITED_FROM value is skipped rather than turned into a grant that
    cannot be revoked.
    """
    container_type = str(grant.get("inherited_from") or "").upper()
    database = str(grant.get("inherited_from_database") or "")
    schema = str(grant.get("inherited_from_schema") or "")

    if container_type == "ACCOUNT":
        container = "ACCOUNT"
    elif container_type == "DATABASE":
        container = database
    elif container_type == "SCHEMA":
        container = f"{database}.{schema}"
    else:
        logger.debug(f"Skipping inherited grant with unrecognized container {container_type!r}")
        return None

    # Normalize the object type the way the manifest does — grant_fqn passes a ResourceType
    # to format_collection_string — so synonym types (SHOW GRANTS reports CORTEX_AGENT_SERVER
    # for what GRANT/CREATE call an MCP SERVER) match the declared type instead of producing a
    # non-converging DROP+CREATE that revokes the inherited grant in sync mode.
    try:
        items_type: Any = ResourceType(grant["granted_on"].replace("_", " "))
    except ValueError:
        items_type = grant["granted_on"].replace("_", " ")
    collection = format_collection_string(container, items_type)
    return FQN(
        name=ResourceName("GRANT"),
        params={
            "grant_type": GrantType.INHERITED.value,
            "priv": grant["privilege"],
            "on": f"{container_type.lower()}/{collection}",
            "to": f"{to_label}/{grantee}",
        },
    )


def _drop_inherited_grants(rows: list[dict[str, Any]], context: str) -> list[dict[str, Any]]:
    """
    Remove inherited grant rows from a grant listing.

    Snowcap has no representation for an inherited grant, and the rows cannot be treated as
    object grants: they carry no object name, and revoking one requires
    REVOKE INHERITED <priv> ON ALL <type> IN <container> FROM <grantee> rather than a
    per-object REVOKE. Left in remote state they would make grant sync mode emit invalid
    REVOKEs and `snowcap export` write grants that cannot be applied.

    Filtering them out means Snowcap neither manages nor disturbs inherited grants. It also
    means privileges a role holds only through inheritance are invisible to Snowcap's
    preflight privilege checks, which can make those checks over-strict; failing loudly is
    the safer direction until inherited grants are modeled.
    """
    if not rows:
        return rows
    kept = [row for row in rows if not _is_inherited_grant(row)]
    dropped = len(rows) - len(kept)
    if dropped:
        logger.debug(
            f"Ignoring {dropped} inherited grant(s) in {context}. Snowcap does not manage grants created with "
            "GRANT INHERITED."
        )
    return kept


# (session id, role, role type, grant type) -> {(granted_on label, privilege, name): grant}.
_GRANT_LOOKUP_INDEX_CACHE: dict[tuple, dict[tuple, dict[str, Any]]] = {}
_GRANT_LOOKUP_INDEX_LOCK = threading.Lock()


def _reset_grant_lookup_index() -> None:
    with _GRANT_LOOKUP_INDEX_LOCK:
        _GRANT_LOOKUP_INDEX_CACHE.clear()


# Built from cacheable SHOW GRANTS rows, so it expires with the SQL execution cache.
register_cache_reset_hook(_reset_grant_lookup_index)


def _grant_name_key(name: str) -> str:
    """
    Canonical key for a grant target name, matching ResourceName equality semantics.

    ResourceName is unsafe as a dict key: __hash__ is hash(str(self)), which keeps the
    quotes, while __eq__ treats quoted "FOO" and unquoted FOO as equal. "Exact if quoted,
    upper-cased if not" reproduces __eq__ across all four combinations.
    """
    rendered = str(ResourceName(name))
    return rendered[1:-1] if rendered.startswith('"') else rendered


def _grant_lookup_index(
    session: SnowflakeConnection,
    grant_type: GrantType,
    role: ResourceName,
    role_type: ResourceType,
) -> dict[tuple, dict[str, Any]]:
    """Return (building it first if needed) the (granted_on, privilege, name) index for one role."""
    cache_key = (id(session), str(role), role_type, grant_type)
    index = _GRANT_LOOKUP_INDEX_CACHE.get(cache_key)
    if index is not None:
        return index

    if grant_type == GrantType.FUTURE:
        if role_type == ResourceType.DATABASE_ROLE:
            grants = _show_future_grants_to_database_role(session, str(role), cacheable=True)
        else:
            grants = _show_future_grants_to_role(session, role, cacheable=True)
    else:
        grants = _show_grants_to_role(session, role, role_type=role_type, cacheable=True)

    with _GRANT_LOOKUP_INDEX_LOCK:
        # Re-check: another thread may have built it while we waited for the lock.
        index = _GRANT_LOOKUP_INDEX_CACHE.get(cache_key)
        if index is None:
            index = {}
            for grant in grants:
                is_account = grant["granted_on"] == "ACCOUNT"
                name = "ACCOUNT" if is_account else grant["name"]
                key = (
                    # Snowflake reports type synonyms (CORTEX_AGENT_SERVER for MCP SERVER).
                    _granted_on_label(grant["granted_on"]),
                    grant["privilege"],
                    name if is_account else _grant_name_key(name),
                )
                # First match wins, as the linear scan did, when a grant is duplicated.
                index.setdefault(key, grant)
            _GRANT_LOOKUP_INDEX_CACHE[cache_key] = index
    return index


def _fetch_grant_to_role(
    session: SnowflakeConnection,
    grant_type: GrantType,
    role: ResourceName,
    granted_on: str,
    on_name: str,
    privilege: str,
    role_type: ResourceType = ResourceType.ROLE,
):
    index = _grant_lookup_index(session, grant_type, role, role_type)
    name_key = on_name if granted_on == "ACCOUNT" else _grant_name_key(on_name)
    return index.get((_granted_on_label(granted_on), privilege, name_key))


def _filter_result(result, **kwargs):

    filtered = []
    predicates = {key: value for key, value in kwargs.items() if value is not None}
    for row in result:
        for key, value in predicates.items():
            # Roughly match any names. `name`, `database_name`, `schema_name`, etc.
            if attribute_is_resource_name(key):
                if resource_name_from_snowflake_metadata(row[key]) != ResourceName(value):
                    # if ResourceName(value) != f'"{row[key]}"':
                    break
            else:
                if row[key] != value:
                    break
        else:
            filtered.append(row)
    return filtered


# def _urn_from_grant(row, session_ctx):
#     account_scoped_resources = {"user", "role", "warehouse", "database", "task"}
#     granted_on = row["granted_on"].lower()
#     if granted_on == "account":
#         return URN.from_session_ctx(session_ctx)
#     else:
#         if granted_on == "procedure" or granted_on == "function":
#             # This needs a special function because Snowflake gives an incorrect FQN for functions/sprocs
#             # eg. SNOWCAP_DEV.PUBLIC."FETCH_DATABASE(NAME VARCHAR):OBJECT"
#             # The correct FQN is SNOWCAP_DEV.PUBLIC."FETCH_DATABASE"(VARCHAR)
#             id_parts = list(FullyQualifiedIdentifier.parse_string(row["name"], parse_all=True))
#             name = parse_function_name(id_parts[-1])
#             fqn = FQN(database=id_parts[0], schema=id_parts[1], name=name)
#         elif granted_on in account_scoped_resources:
#             # This is probably all account-scoped resources
#             fqn = FQN(name=ResourceName(row["name"]))
#         else:
#             # Scoped resources
#             fqn = parse_FQN(row["name"], is_db_scoped=(granted_on == "schema"))
#         return URN(
#             resource_type=ResourceType(granted_on),
#             account_locator=session_ctx["account_locator"],
#             fqn=fqn,
#         )


def _convert_to_gmt(dt: datetime.datetime, fmt_str: str = "%Y-%m-%d %H:%M:%S") -> Optional[str]:
    """
    datetime.datetime(2049, 1, 6, 12, 0, tzinfo=<DstTzInfo 'America/Los_Angeles' PST-1 day, 16:00:00 STD>)

    =>

    2049-01-06 20:00
    """
    if not dt:
        return None
    gmt = pytz.timezone("GMT")
    dt_gmt = dt.astimezone(gmt)
    return dt_gmt.strftime(fmt_str)


def _parse_cluster_keys(cluster_keys_str: str) -> Optional[list[str]]:
    """
    Assume cluster key statement is in the form of:
        LINEAR(C1, C3)
        LINEAR(SUBSTRING(C2, 5, 15), CAST(C1 AS DATE))
    """
    if cluster_keys_str is None or cluster_keys_str == "":
        return None
    cluster_keys_str = cluster_keys_str[len("LINEAR") :]
    cluster_keys_str = cluster_keys_str.strip("()")
    return [key.strip(" ") for key in cluster_keys_str.split(",")]


def _parse_function_arguments_2023_compat(arguments_str: str) -> tuple:
    """
    Input
    -----
        FETCH_DATABASE(OBJECT [, BOOLEAN]) RETURN OBJECT

    Output
    ------
        identifier => FETCH_DATABASE(OBJECT, BOOLEAN)
        returns => OBJECT

    """

    header, returns = arguments_str.split(" RETURN ")
    header = header.replace("[", "").replace("]", "")
    identifier = parse_FQN(header)
    return (identifier, returns)


def _parse_function_arguments(arguments_str: str) -> tuple[FQN, str]:
    """
    Input
    -----
        FETCH_DATABASE(VARCHAR) RETURN OBJECT

    Output
    ------
        identifier => FETCH_DATABASE(VARCHAR)
        returns => OBJECT

    """

    header, returns = arguments_str.split(" RETURN ")
    identifier = parse_FQN(header)
    return (identifier, returns)


def _parse_list_property(property_str: str) -> Optional[list]:
    if property_str is None or property_str == "":
        return None
    property_str = property_str.strip("[]")
    if property_str:
        return [item.strip(" ") for item in property_str.split(",")]
    return []


def _parse_signature(signature: str) -> list:
    signature = signature.strip("()")

    if signature:
        return [_parse_column(col.strip(" ")) for col in signature.split(",")]
    return []


def _parse_comma_separated_values(values: str) -> Optional[list]:
    if values is None or values == "":
        return None
    return [value.strip(" ") for value in values.split(",")]


def _parse_packages(packages_str: str) -> Optional[list]:
    if packages_str is None or packages_str == "":
        return None
    return json.loads(packages_str.replace("'", '"'))


def _parse_storage_location(storage_location_str: str) -> Optional[dict]:
    if storage_location_str is None or storage_location_str == "":
        return None
    raw_dict = json.loads(storage_location_str)
    storage_location = {}
    for key, value in raw_dict.items():
        key = key.lower()
        if key == "encryption_type":
            storage_location["encryption"] = {"type": value}
        elif key in (
            "name",
            "storage_provider",
            "storage_base_url",
            "storage_aws_role_arn",
            "storage_aws_external_id",
        ):
            storage_location[key] = value
    return storage_location


def _cast_param_value(raw_value: str, param_type: str) -> Any:
    if param_type == "BOOLEAN":
        return raw_value == "true"
    elif param_type == "NUMBER":
        try:
            return int(raw_value)
        except ValueError:
            try:
                return float(raw_value)
            except ValueError:
                raise Exception(f"Unsupported number type: {raw_value}")
    elif param_type == "FLOAT":
        try:
            return float(raw_value)
        except ValueError:
            raise Exception(f"Unsupported float type: {raw_value}")
    elif param_type == "STRING":
        return str(raw_value) if raw_value else None
    else:
        return raw_value


def params_result_to_dict(params_result):
    params = {}
    for param in params_result:
        typed_value = _cast_param_value(param["value"], param["type"])
        params[param["key"].lower()] = typed_value
    return params


def options_result_to_list(options_result):
    return [option.strip(" ") for option in options_result.split(",")]


def _normalize_snowflake_optional(value, upper: bool = False):
    if value is None:
        return None
    if isinstance(value, str):
        value = value.strip()
        if value == "" or value.lower() == "null":
            return None
        return value.upper() if upper else value
    return value


def remove_none_values(d):
    new_dict = {}
    for k, v in d.items():
        if isinstance(v, dict):
            new_dict[k] = remove_none_values(v)
        elif isinstance(v, list) and len(v) > 0 and isinstance(v[0], dict):
            new_dict[k] = [remove_none_values(item) for item in v if item is not None]
        elif v is not None:
            new_dict[k] = v
    return new_dict


def _fetch_columns_for_table(session: SnowflakeConnection, fqn: FQN):
    info_schema_result = execute(session, f"SELECT * FROM {fqn.database}.INFORMATION_SCHEMA.COLUMNS", cacheable=True)
    columns = []
    for col in info_schema_result:
        if (
            resource_name_from_snowflake_metadata(col["TABLE_SCHEMA"]) != fqn.schema
            or resource_name_from_snowflake_metadata(col["TABLE_NAME"]) != fqn.name
        ):
            continue

        data_type = None
        default = col["COLUMN_DEFAULT"]

        if col["DATA_TYPE"] == "NUMBER":
            data_type = f"NUMBER({col['NUMERIC_PRECISION']}, {col['NUMERIC_SCALE']})"
        elif col["DATA_TYPE"] == "TEXT":
            data_type = f"VARCHAR({col['CHARACTER_MAXIMUM_LENGTH']})"
            if col["COLUMN_DEFAULT"]:
                default = col["COLUMN_DEFAULT"].strip("'")
        else:
            data_type = col["DATA_TYPE"]

        columns.append(
            {
                "name": col["COLUMN_NAME"],
                "data_type": data_type,
                "not_null": col["IS_NULLABLE"] == "NO",
                "default": default,
                "comment": col["COMMENT"] or None,
                "constraint": None,
                "collate": None,
            }
        )
    return columns


def _fetch_owner(session: SnowflakeConnection, type_str: str, fqn: FQN) -> Optional[str]:
    show_grants = execute(session, f"SHOW GRANTS ON {type_str} {fqn}")
    ownership_grant = _filter_result(show_grants, privilege="OWNERSHIP")
    if len(ownership_grant) == 0:
        return None
    return ownership_grant[0]["grantee_name"]


def _show_resources(session: SnowflakeConnection, type_str, fqn: FQN, cacheable: bool = True) -> list[dict]:
    try:
        in_account = " IN ACCOUNT"
        if "INTEGRATIONS" in type_str:
            in_account = ""
        initial_fetch = execute(session, f"SHOW {type_str}{in_account}", cacheable=cacheable)
        if len(initial_fetch) == 0:
            return []
        elif len(initial_fetch) < 1000:
            container_kwargs = {}
            show_columns = initial_fetch[0].keys()
            if "database" in show_columns:
                container_kwargs["database"] = fqn.database
            elif "database_name" in show_columns:
                container_kwargs["database_name"] = fqn.database

            if "schema" in show_columns:
                container_kwargs["schema"] = fqn.schema
            elif "schema_name" in show_columns:
                container_kwargs["schema_name"] = fqn.schema
            filtered_fetch = _filter_result(
                initial_fetch,
                name=fqn.name,
                **container_kwargs,
            )
            return filtered_fetch
        else:
            name = str(fqn.name).replace('"', "")
            if fqn.database is None and fqn.schema is None:
                return execute(session, f"SHOW {type_str} LIKE '{name}'", cacheable=cacheable)
            elif fqn.database is None:
                return execute(session, f"SHOW {type_str} LIKE '{name}' IN SCHEMA {fqn.schema}", cacheable=cacheable)
            elif fqn.schema is None:
                return execute(
                    session, f"SHOW {type_str} LIKE '{name}' IN DATABASE {fqn.database}", cacheable=cacheable
                )
            else:
                return execute(
                    session,
                    f"SHOW {type_str} LIKE '{name}' IN SCHEMA {fqn.database}.{fqn.schema}",
                    cacheable=cacheable,
                )
    except ProgrammingError as err:
        if err.errno == OBJECT_DOES_NOT_EXIST_ERR or err.errno == DOES_NOT_EXIST_ERR:
            return []
        else:
            raise


def _show_resource_parameters(session: SnowflakeConnection, type_str: str, fqn: FQN, cacheable: bool = True) -> dict:
    result = execute(session, f"SHOW PARAMETERS IN {type_str} {fqn}", cacheable=cacheable)
    return params_result_to_dict(result)


def _show_users(session) -> list[dict]:
    # SHOW USERS requires the MANAGE GRANTS privilege
    # Other roles can see the list of users but don't get access to other metadata such as login_name.
    # This causes incorrect drift

    session_ctx = fetch_session(session)
    execution_role = None
    current_role = session_ctx["role"]

    eligible_roles = [ResourceName("SECURITYADMIN"), ResourceName("ACCOUNTADMIN")]
    if (
        "MANAGE GRANTS" in session_ctx["account_grant_map"]
        and len(session_ctx["account_grant_map"]["MANAGE GRANTS"]) > 0
    ):
        eligible_roles.extend(session_ctx["account_grant_map"]["MANAGE GRANTS"])

    if current_role in eligible_roles:
        return execute(session, "SHOW USERS", cacheable=True)
    else:
        execution_role = None
        for role in eligible_roles:
            if role in session_ctx["available_roles"]:
                execution_role = role
                break
        else:
            raise RuntimeError("Managing users requires the MANAGE GRANTS privilege")

        use_role(session, execution_role)
        users = execute(session, "SHOW USERS", cacheable=True)
        use_role(session, current_role)

    return users


def _get_account_privilege_roles(session: SnowflakeConnection) -> dict[str, list[ResourceName]]:
    grant_map: dict[str, list[ResourceName]] = {}
    grants = _drop_inherited_grants(execute(session, "SHOW GRANTS ON ACCOUNT"), "SHOW GRANTS ON ACCOUNT")
    for grant in grants:
        # Skip system grants
        if grant["granted_by"] == "":
            continue

        if grant["privilege"] in ["MANAGE GRANTS", "APPLY TAG"]:
            priv = grant["privilege"]
            role = resource_name_from_snowflake_metadata(grant["grantee_name"])
            if priv not in grant_map:
                grant_map[priv] = []
            grant_map[priv].append(role)
    return grant_map


def _show_grants_to_role(
    session: SnowflakeConnection,
    role: ResourceName,
    role_type: ResourceType = ResourceType.ROLE,
    cacheable: bool = False,
    use_account_usage: bool = False,
) -> list[dict[str, Any]]:
    """
    Get grants to a role, using ACCOUNT_USAGE cache when available.

    Automatically uses the ACCOUNT_USAGE cache if it's been populated (regardless of
    the use_account_usage flag). Falls back to SHOW GRANTS when the cache is not
    available or for database roles.

    Returns:
    {
        'created_on': datetime.datetime(2024, 2, 28, 20, 5, 32, 166000, tzinfo=<DstTzInfo 'America/Los_Angeles' PST-1 day, 16:00:00 STD>),
        'privilege': 'USAGE',
        'granted_on': 'DATABASE',
        'name': 'STATIC_DATABASE',
        'granted_to': 'ROLE',
        'grantee_name': 'THATROLE',
        'grant_option': 'false',
        'granted_by': 'ACCOUNTADMIN'
    }
    """
    grants = _show_all_grants_to_role(session, role, role_type=role_type, cacheable=cacheable)
    return _drop_inherited_grants(grants, f"grants to {role_type} {role}")


def _show_all_grants_to_role(
    session: SnowflakeConnection,
    role: ResourceName,
    role_type: ResourceType = ResourceType.ROLE,
    cacheable: bool = False,
) -> list[dict[str, Any]]:
    """
    Every grant to a role, object grants and inherited grants alike.

    Callers almost always want _show_grants_to_role() (object grants only) or
    _show_inherited_grants_to_role(); this is the shared source both read from, so a role's
    grants are fetched once regardless of which kinds the caller cares about.
    """
    # Automatically use ACCOUNT_USAGE cache for regular roles if it's been populated
    if role_type == ResourceType.ROLE:
        session_id = id(session)
        if session_id in _ACCOUNT_USAGE_GRANTS_CACHE:
            filtered_grants = _grants_by_role_index(session_id).get(str(role).upper(), [])
            logger.debug(f"Using ACCOUNT_USAGE cache for grants to role {role} ({len(filtered_grants)} grants)")
            return filtered_grants

    # Fall back to SHOW GRANTS
    return execute(
        session,
        f"SHOW GRANTS TO {role_type} {role}",
        cacheable=cacheable,
        empty_response_codes=[DOES_NOT_EXIST_ERR],
    )


def _show_inherited_grants_to_role(
    session: SnowflakeConnection,
    role: ResourceName,
    role_type: ResourceType = ResourceType.ROLE,
    cacheable: bool = True,
) -> list[dict[str, Any]]:
    """
    The inherited grants held by a role.

    Snowflake does not enumerate the individual securables an inherited grant covers, so
    each row describes the container-level grant itself: NAME is empty, GRANTED_ON is the
    object type the grant applies to, and INHERITED_FROM* identify the container.
    """
    grants = _show_all_grants_to_role(session, role, role_type=role_type, cacheable=cacheable)
    return [grant for grant in grants if _is_inherited_grant(grant)]


def _show_future_grants_to_role(
    session: SnowflakeConnection, role: ResourceName, cacheable: bool = False
) -> list[dict[str, Any]]:
    """
    {
        'created_on': datetime.datetime(2024, 2, 28, 20, 5, 32, 166000, tzinfo=<DstTzInfo 'America/Los_Angeles' PST-1 day, 16:00:00 STD>),
        'privilege': 'USAGE',
        'grant_on': 'SCHEMA',
        'name': 'STATIC_DATABASE.<SCHEMA>',
        'grant_to': 'ROLE',
        'grantee_name': 'THATROLE',
        'grant_option': 'false'
    }
    """
    grants = execute(
        session,
        f"SHOW FUTURE GRANTS TO ROLE {role}",
        cacheable=cacheable,
        empty_response_codes=[DOES_NOT_EXIST_ERR],
    )
    for grant in grants:
        grant["name"] = _normalize_future_grant_name(grant["name"])
        # smart_split: quoted identifiers may contain dots ('"DB.WITH.DOT".<SCHEMA>')
        grant["granted_on"] = "DATABASE" if len(smart_split(grant["name"], ".")) == 2 else "SCHEMA"
    return grants


def _show_future_grants_to_database_role(
    session: SnowflakeConnection, database_role: str, cacheable: bool = False
) -> list[dict[str, Any]]:
    """
    Fetch future grants for a database role.

    Args:
        session: Snowflake connection
        database_role: Fully qualified database role name (e.g., "DB_NAME.ROLE_NAME")
        cacheable: Whether to cache the result

    Returns:
        List of future grant dicts with same structure as _show_future_grants_to_role(),
        plus 'granted_on' field inferred from the name pattern.
    """
    grants = execute(
        session,
        f"SHOW FUTURE GRANTS TO DATABASE ROLE {database_role}",
        cacheable=cacheable,
        empty_response_codes=[DOES_NOT_EXIST_ERR],
    )
    for grant in grants:
        # Infer granted_on from the name pattern
        # Database-level: "DB_NAME.<SCHEMA>" (2 parts)
        # Schema-level: "DB_NAME.SCHEMA_NAME.<TABLE>" (3 parts)
        grant["name"] = _normalize_future_grant_name(grant["name"])
        # smart_split: quoted identifiers may contain dots ('"DB.WITH.DOT".<SCHEMA>')
        grant["granted_on"] = "DATABASE" if len(smart_split(grant["name"], ".")) == 2 else "SCHEMA"
    return grants


def use_secondary_roles(session: SnowflakeConnection, all: bool = False):
    """
    Set the secondary roles for the current session.
    """
    secondary_roles = "ALL" if all else "NONE"
    execute(session, f"USE SECONDARY ROLES {secondary_roles}")


def use_role(session: SnowflakeConnection, role_name: ResourceName):
    """
    Set the active role for the current session.
    """
    execute(session, f"USE ROLE {role_name}")


# Fields that come from SHOW PARAMETERS queries (expensive to fetch)
# If manifest doesn't specify these fields, we can skip the SHOW PARAMETERS query
# Only includes fields that are actually returned by the fetch functions
PARAMETER_FIELDS = {
    "database": {"max_data_extension_time_in_days", "external_volume", "catalog", "default_ddl_collation"},
    "schema": {"max_data_extension_time_in_days", "default_ddl_collation"},
    "user": {"network_policy"},
    "warehouse": {"max_concurrency_level", "statement_queued_timeout_in_seconds", "statement_timeout_in_seconds"},
    "table": {"default_ddl_collation"},
    "task": {"suspend_task_after_num_failures", "user_task_managed_initial_warehouse_size", "user_task_timeout_ms"},
    "iceberg_table": {
        "catalog_sync",
        "storage_serialization_policy",
        "data_retention_time_in_days",
        "max_data_extension_time_in_days",
        "default_ddl_collation",
    },
}


def fetch_resource(
    session: SnowflakeConnection, urn: URN, include_params: bool = True, existence_only: bool = False
) -> Optional[dict]:
    """
    Fetch a resource from Snowflake.

    Args:
        session: Snowflake connection
        urn: Resource URN
        include_params: If False, skip expensive SHOW PARAMETERS queries.
                       Use False when manifest doesn't specify parameter fields.
        existence_only: If True, only check if resource exists (skip detailed queries like DESC USER).
                       Use True for reference validation where we just need to verify existence.
    """
    try:
        func_name = f"fetch_{urn.resource_label}"
        fetch_fn = getattr(__this__, func_name)
        # Check which optional parameters the fetch function accepts (cached)
        sig = _get_cached_signature(func_name)
        kwargs = {}
        if "include_params" in sig.parameters:
            kwargs["include_params"] = include_params
        if "existence_only" in sig.parameters:
            kwargs["existence_only"] = existence_only
        if kwargs:
            return fetch_fn(session, urn.fqn, **kwargs)
        else:
            return fetch_fn(session, urn.fqn)
    except ProgrammingError as err:
        # This try/catch block fixes a cache-inconsistency issue where _show_resources returns the object as it existed at the start of the cache window,
        # but _show_resource_parameters returns the object as it exists right now. If the object was dropped in between the cache window and the query execution,
        # we should assume the database no longer exists.

        # This is only likely to happen for long-running commands like export
        if err.errno == DOES_NOT_EXIST_ERR:
            return None
        raise


def fetch_account_locator(session: SnowflakeConnection):
    locator = execute(session, "SELECT CURRENT_ACCOUNT() as account_locator")[0]["ACCOUNT_LOCATOR"]
    return locator


def fetch_region(session: SnowflakeConnection):
    region = execute(session, "SELECT CURRENT_REGION()")[0]
    return region


def fetch_inherited_grants_enabled(session: SnowflakeConnection) -> Optional[bool]:
    """
    Is FEATURE_RBAC_INHERITED_GRANTS enabled for this account?

    Returns None when the answer cannot be determined -- the parameter does not exist on
    Snowflake versions without the preview, and reading account parameters requires
    privileges the session may not hold. Callers treat None as "assume enabled" so that an
    unreadable parameter never blocks an apply that would otherwise succeed.
    """
    session_id = id(session)
    if session_id in _INHERITED_GRANTS_ENABLED_CACHE:
        return _INHERITED_GRANTS_ENABLED_CACHE[session_id]

    enabled: Optional[bool] = None
    try:
        rows = execute(
            session,
            f"SHOW PARAMETERS LIKE '{INHERITED_GRANTS_FEATURE_FLAG}' IN ACCOUNT",
            cacheable=True,
        )
        for row in rows:
            if str(row.get("key", "")).upper() == INHERITED_GRANTS_FEATURE_FLAG:
                enabled = str(row.get("value", "")).strip().upper() == "ENABLED"
                break
    except Exception as err:
        logger.debug(f"Could not read FEATURE_RBAC_INHERITED_GRANTS: {err}")

    _INHERITED_GRANTS_ENABLED_CACHE[session_id] = enabled
    return enabled


def fetch_preview_access_enabled(session: SnowflakeConnection) -> Optional[bool]:
    """
    Does this account have access to preview features at all?

    Preview access is on by default for most accounts, and it gates every preview feature
    at once. It is toggled with the SYSTEM$ENABLE_PREVIEW_ACCESS and
    SYSTEM$DISABLE_PREVIEW_ACCESS functions rather than with an account parameter, so it is
    not something Snowcap can manage as a resource -- but knowing the answer turns
    "GRANT INHERITED failed" into an actionable message.

    Returns None when the status cannot be read.
    https://docs.snowflake.com/en/release-notes/preview-features
    """
    try:
        rows = execute(session, "SELECT SYSTEM$GET_PREVIEW_ACCESS_STATUS() AS status", cacheable=True)
    except Exception as err:
        logger.debug(f"Could not read preview access status: {err}")
        return None

    if not rows:
        return None
    status = str(rows[0].get("STATUS") or rows[0].get("status") or "").upper()
    if "ENABLED" in status:
        return True
    if "DISABLED" in status:
        return False
    return None


def fetch_session(session: SnowflakeConnection) -> SessionContext:
    session_obj = execute(
        session,
        """
        SELECT
            CURRENT_ACCOUNT_NAME() as account,
            CURRENT_ACCOUNT() as account_locator,
            CURRENT_USER() as user,
            CURRENT_ROLE() as role,
            CURRENT_AVAILABLE_ROLES() as available_roles,
            CURRENT_SECONDARY_ROLES() as secondary_roles,
            CURRENT_DATABASE() as database,
            CURRENT_SCHEMAS() as schemas,
            CURRENT_WAREHOUSE() as warehouse,
            CURRENT_VERSION() as version,
            CURRENT_REGION() as region,
            SYSTEM$BOOTSTRAP_DATA_REQUEST('ACCOUNT') as account_data
        """,
    )[0]

    account_data = json.loads(session_obj["ACCOUNT_DATA"])
    available_roles = [ResourceName(role) for role in json.loads(session_obj["AVAILABLE_ROLES"])]
    region = parse_region(session_obj["REGION"])
    account_grant_map = _get_account_privilege_roles(session)

    return {
        "account_edition": AccountEdition(account_data["accountInfo"]["serviceLevelName"]),
        "account_grant_map": account_grant_map,
        "account_locator": session_obj["ACCOUNT_LOCATOR"],
        "account": session_obj["ACCOUNT"],
        "available_roles": available_roles,
        "cloud": region["cloud"],
        "cloud_region": region["cloud_region"],
        "database": session_obj["DATABASE"],
        "role": ResourceName(session_obj["ROLE"]),
        "schemas": json.loads(session_obj["SCHEMAS"]),
        "secondary_roles": json.loads(session_obj["SECONDARY_ROLES"]),
        "user": session_obj["USER"],
        "version": session_obj["VERSION"],
        "warehouse": session_obj["WAREHOUSE"],
    }


def fetch_role_privileges(
    session: SnowflakeConnection,
    roles: list[ResourceName],
    cacheable: bool = True,
    use_account_usage: bool = False,
) -> dict[ResourceName, list[GrantedPrivilege]]:
    role_privileges: dict[ResourceName, list[GrantedPrivilege]] = {}

    # Filter out roles we skip (ACCOUNTADMIN and SNOWFLAKE.* roles)
    processable_roles = [role for role in roles if role != "ACCOUNTADMIN" and not role.startswith("SNOWFLAKE.")]

    # Initialize empty lists for all processable roles
    for role in processable_roles:
        role_privileges[role] = []

    if not processable_roles:
        return role_privileges

    # Try ACCOUNT_USAGE if enabled and accessible
    if _should_use_account_usage(session, use_account_usage):
        logger.debug("fetch_role_privileges: Using ACCOUNT_USAGE for role privileges")
        role_name_set = {role.upper() for role in processable_roles}
        all_grants = _fetch_grants_from_account_usage(session)

        # If ACCOUNT_USAGE query failed, fall back to SHOW queries
        if all_grants is not None:
            for grant in all_grants:
                grantee_name = grant["grantee_name"]
                # Only process grants for roles we care about (case-insensitive)
                if grantee_name.upper() not in role_name_set:
                    continue

                # Find the original role name (preserve case)
                role_match = next((role for role in processable_roles if role.upper() == grantee_name.upper()), None)
                if role_match is None:
                    continue

                try:
                    granted_priv = GrantedPrivilege.from_grant(
                        privilege=grant["privilege"],
                        granted_on=grant["granted_on"].replace("_", " "),
                        name=grant["name"],
                    )
                    role_privileges[role_match].append(granted_priv)
                # If snowcap isn't aware of the privilege, ignore it
                except ValueError:
                    continue

            return role_privileges
        # Fall through to SHOW queries if ACCOUNT_USAGE failed

    # Fallback: Use SHOW GRANTS for each role
    logger.debug("fetch_role_privileges: Using SHOW GRANTS for role privileges")
    for role in processable_roles:
        grants = _show_grants_to_role(session, role, cacheable=cacheable)
        for grant in grants:
            try:
                granted_priv = GrantedPrivilege.from_grant(
                    privilege=grant["privilege"],
                    granted_on=grant["granted_on"].replace("_", " "),
                    name=grant["name"],
                )
                role_privileges[role].append(granted_priv)
            # If snowcap isn't aware of the privilege, ignore it
            except ValueError:
                continue
    return role_privileges


# ------------------------------
# ACCOUNT_USAGE Access Check
# ------------------------------

# Cache for ACCOUNT_USAGE access check results (keyed by session id)
_ACCOUNT_USAGE_ACCESS_CACHE: dict[int, bool] = {}

# Cache for tracking sessions where ACCOUNT_USAGE queries failed at runtime
# (distinct from permission errors - these are unexpected query failures)
# When True, that session should fall back to SHOW queries
_ACCOUNT_USAGE_FALLBACK_CACHE: dict[int, bool] = {}

# Cache for ACCOUNT_USAGE grants data (keyed by session id)
# Stores the normalized grant list from GRANTS_TO_ROLES
_ACCOUNT_USAGE_GRANTS_CACHE: dict[int, list[dict[str, Any]]] = {}

# Cache for ACCOUNT_USAGE role-to-user grants (keyed by session id)
# Stores the normalized grant list from GRANTS_TO_USERS
_ACCOUNT_USAGE_USER_GRANTS_CACHE: dict[int, list[dict[str, Any]]] = {}

# Role-name index over _ACCOUNT_USAGE_GRANTS_CACHE: session id, then upper-cased grantee.
_ACCOUNT_USAGE_GRANTS_BY_ROLE_CACHE: dict[int, dict[str, list[dict[str, Any]]]] = {}
_ACCOUNT_USAGE_GRANTS_INDEX_LOCK = threading.Lock()


def _grants_by_role_index(session_id: int) -> dict[str, list[dict[str, Any]]]:
    """Return (building it first if needed) the role -> grants index for a session's grant cache."""
    index = _ACCOUNT_USAGE_GRANTS_BY_ROLE_CACHE.get(session_id)
    if index is not None:
        return index
    with _ACCOUNT_USAGE_GRANTS_INDEX_LOCK:
        # Re-check: another thread may have built it while we waited for the lock.
        index = _ACCOUNT_USAGE_GRANTS_BY_ROLE_CACHE.get(session_id)
        if index is None:
            index = {}
            for grant in _ACCOUNT_USAGE_GRANTS_CACHE.get(session_id, []):
                if grant["granted_to"] != "ROLE":
                    continue
                index.setdefault(grant["grantee_name"].upper(), []).append(grant)
            _ACCOUNT_USAGE_GRANTS_BY_ROLE_CACHE[session_id] = index
            logger.debug(f"Built ACCOUNT_USAGE grant index: {len(index)} roles")
    return index


# Tracks sessions whose GRANTS_TO_ROLES view has no IS_INHERITED column (keyed by session
# id). Absent means "assume the column exists"; the first query proves it either way.
_ACCOUNT_USAGE_INHERITED_COLUMN: dict[int, bool] = {}

# Whether FEATURE_RBAC_INHERITED_GRANTS is enabled (keyed by session id). None means the
# parameter could not be read.
_INHERITED_GRANTS_ENABLED_CACHE: dict[int, Optional[bool]] = {}

# Sessions already warned that ACCOUNT_USAGE listing lags live state.
_ACCOUNT_USAGE_STALENESS_WARNED: set[int] = set()


def reset_account_usage_caches() -> None:
    """
    Clear all ACCOUNT_USAGE caches.

    This should be called when you need to force a fresh query of grant data,
    such as after applying changes that create new grants.
    """
    global _ACCOUNT_USAGE_ACCESS_CACHE, _ACCOUNT_USAGE_FALLBACK_CACHE
    global _ACCOUNT_USAGE_GRANTS_CACHE, _ACCOUNT_USAGE_USER_GRANTS_CACHE
    global _ACCOUNT_USAGE_INHERITED_COLUMN, _INHERITED_GRANTS_ENABLED_CACHE
    global _ACCOUNT_USAGE_GRANTS_BY_ROLE_CACHE, _GRANT_LOOKUP_INDEX_CACHE
    global _ACCOUNT_USAGE_STALENESS_WARNED

    _ACCOUNT_USAGE_ACCESS_CACHE.clear()
    _ACCOUNT_USAGE_FALLBACK_CACHE.clear()
    _ACCOUNT_USAGE_GRANTS_CACHE.clear()
    _ACCOUNT_USAGE_USER_GRANTS_CACHE.clear()
    _ACCOUNT_USAGE_INHERITED_COLUMN.clear()
    _INHERITED_GRANTS_ENABLED_CACHE.clear()
    _ACCOUNT_USAGE_STALENESS_WARNED.clear()
    # Derived indexes must not outlive the rows they were built from.
    _ACCOUNT_USAGE_GRANTS_BY_ROLE_CACHE.clear()
    _reset_grant_lookup_index()


def _mark_account_usage_fallback(session: SnowflakeConnection) -> None:
    """
    Mark that ACCOUNT_USAGE queries failed for this session and we should fall back to SHOW queries.
    This is used when a query unexpectedly fails (not permission error).
    """
    session_id = id(session)
    _ACCOUNT_USAGE_FALLBACK_CACHE[session_id] = True
    logger.warning("ACCOUNT_USAGE query failed - falling back to SHOW queries for this session")


def _should_use_account_usage(session: SnowflakeConnection, use_account_usage: bool) -> bool:
    """
    Determine whether to use ACCOUNT_USAGE queries for grants.

    Checks:
    1. use_account_usage config flag is True
    2. Session has ACCOUNT_USAGE access (IMPORTED PRIVILEGES)
    3. Session hasn't had previous ACCOUNT_USAGE query failures

    Returns:
        True if ACCOUNT_USAGE should be used, False otherwise.
    """
    if not use_account_usage:
        return False

    session_id = id(session)
    if _ACCOUNT_USAGE_FALLBACK_CACHE.get(session_id, False):
        logger.debug("Skipping ACCOUNT_USAGE: previous query failure for this session")
        return False

    return _has_account_usage_access(session)


def populate_account_usage_caches(session: SnowflakeConnection) -> bool:
    """
    Pre-populate ACCOUNT_USAGE caches for grants data.

    This should be called early in the process when use_account_usage is True
    to ensure the caches are populated before individual fetch functions are called.

    Returns:
        True if caches were populated successfully, False otherwise.
    """
    session_id = id(session)

    # Skip if already populated
    if session_id in _ACCOUNT_USAGE_GRANTS_CACHE and session_id in _ACCOUNT_USAGE_USER_GRANTS_CACHE:
        return True

    # Populate GRANTS_TO_ROLES cache
    grants = _fetch_grants_from_account_usage(session)
    if grants is None:
        return False

    # Populate GRANTS_TO_USERS cache
    user_grants = _fetch_role_grants_to_users_from_account_usage(session)
    if user_grants is None:
        return False

    logger.debug(f"Pre-populated ACCOUNT_USAGE caches: {len(grants)} role grants, {len(user_grants)} user grants")
    return True


def _has_account_usage_access(session: SnowflakeConnection) -> bool:
    """
    Check if the current session has IMPORTED PRIVILEGES on the SNOWFLAKE database.
    This is required to query ACCOUNT_USAGE views.

    Result is cached for the session to avoid repeated permission checks.

    Returns:
        True if query against ACCOUNT_USAGE succeeds, False if permission error.
    """
    session_id = id(session)
    if session_id in _ACCOUNT_USAGE_ACCESS_CACHE:
        return _ACCOUNT_USAGE_ACCESS_CACHE[session_id]

    try:
        execute(
            session,
            "SELECT 1 FROM SNOWFLAKE.ACCOUNT_USAGE.GRANTS_TO_ROLES LIMIT 1",
            cacheable=True,
        )
        _ACCOUNT_USAGE_ACCESS_CACHE[session_id] = True
        logger.debug("ACCOUNT_USAGE access check: access granted")
        return True
    except ProgrammingError as err:
        if err.errno == ACCESS_CONTROL_ERR:
            logger.debug("ACCOUNT_USAGE access check: access denied (missing IMPORTED PRIVILEGES)")
            _ACCOUNT_USAGE_ACCESS_CACHE[session_id] = False
            return False
        # Re-raise unexpected errors
        raise


# ------------------------------
# ACCOUNT_USAGE Grant Fetching
# ------------------------------


def _grants_to_roles_query(include_inherited: bool = True) -> str:
    """
    Build the GRANTS_TO_ROLES query.

    The inherited-grant columns are selected so container-level grants can be told apart
    from object grants, and so an inherited grant can be matched back to the container it
    was created on. They are omitted for accounts whose view does not expose them, which
    are accounts that cannot have inherited grants anyway.
    """
    columns = [
        "CREATED_ON",
        "PRIVILEGE",
        "GRANTED_ON",
        "NAME",
        "TABLE_CATALOG",
        "TABLE_SCHEMA",
        "GRANTED_TO",
        "GRANTEE_NAME",
        "GRANT_OPTION",
        "GRANTED_BY",
    ]
    if include_inherited:
        columns.extend(
            [
                "IS_INHERITED",
                "INHERITED_FROM",
                "INHERITED_FROM_DATABASE",
                "INHERITED_FROM_SCHEMA",
            ]
        )
    return f"""
        SELECT
            {', '.join(columns)}
        FROM SNOWFLAKE.ACCOUNT_USAGE.GRANTS_TO_ROLES
        WHERE DELETED_ON IS NULL
    """


def _fetch_grants_from_account_usage(session: SnowflakeConnection) -> list[dict[str, Any]] | None:
    """
    Fetch all role grants from SNOWFLAKE.ACCOUNT_USAGE.GRANTS_TO_ROLES in a single query.

    Returns a list of grant dictionaries with keys matching SHOW GRANTS output:
        - created_on: datetime when grant was created
        - privilege: name of the privilege
        - granted_on: object type (e.g., 'DATABASE', 'TABLE')
        - name: object name
        - granted_to: grantee type ('ROLE' or 'DATABASE_ROLE')
        - grantee_name: name of the role receiving the grant
        - grant_option: whether grant can be passed to others ('true' or 'false')
        - granted_by: role that granted the privilege

    Note: ACCOUNT_USAGE returns uppercase column names and slightly different values
    (e.g., 'ACCOUNT ROLE' instead of 'ROLE'). This function normalizes the output
    to match the SHOW GRANTS structure.

    Results are cached per session to avoid repeated queries.

    Returns:
        List of grant dictionaries, or None if the query fails (signaling fallback needed).
    """
    # Check cache first
    session_id = id(session)
    if session_id in _ACCOUNT_USAGE_GRANTS_CACHE:
        return _ACCOUNT_USAGE_GRANTS_CACHE[session_id]

    has_inherited_column = _ACCOUNT_USAGE_INHERITED_COLUMN.get(session_id, True)
    try:
        results = execute(session, _grants_to_roles_query(include_inherited=has_inherited_column), cacheable=True)
    except ProgrammingError as err:
        if has_inherited_column and err.errno in (INVALID_COLUMN_ERR, INVALID_IDENTIFIER):
            # Not every Snowflake version exposes the inherited-grant columns, so an account
            # whose GRANTS_TO_ROLES view lacks them is queried without them. Such an account
            # cannot have inherited grants in the first place.
            logger.debug("GRANTS_TO_ROLES has no IS_INHERITED column, querying without it")
            _ACCOUNT_USAGE_INHERITED_COLUMN[session_id] = False
            try:
                results = execute(session, _grants_to_roles_query(include_inherited=False), cacheable=True)
            except Exception as retry_err:
                logger.warning(f"ACCOUNT_USAGE query failed unexpectedly: {retry_err} - falling back to SHOW queries")
                _mark_account_usage_fallback(session)
                return None
        elif err.errno == ACCESS_CONTROL_ERR:
            logger.warning("ACCOUNT_USAGE query failed: access denied - falling back to SHOW queries")
            _mark_account_usage_fallback(session)
            return None
        else:
            logger.warning(
                f"ACCOUNT_USAGE query failed with error {err.errno}: {err.msg} - falling back to SHOW queries"
            )
            _mark_account_usage_fallback(session)
            return None
    except Exception as err:
        logger.warning(f"ACCOUNT_USAGE query failed unexpectedly: {err} - falling back to SHOW queries")
        _mark_account_usage_fallback(session)
        return None

    # Normalize results to match SHOW GRANTS structure
    normalized_grants = []
    for row in results:
        # ACCOUNT_USAGE returns 'ACCOUNT ROLE' but SHOW returns 'ROLE'
        # Similarly 'DATABASE_ROLE' -> 'DATABASE ROLE' for consistency
        granted_to = row["GRANTED_TO"]
        if granted_to == "ACCOUNT ROLE":
            granted_to = "ROLE"
        elif granted_to == "DATABASE_ROLE":
            granted_to = "DATABASE ROLE"

        # GRANT_OPTION is boolean in ACCOUNT_USAGE but string in SHOW
        grant_option = "true" if row["GRANT_OPTION"] else "false"

        # Construct fully qualified name to match SHOW GRANTS output
        # ACCOUNT_USAGE NAME column only has object name, not full path
        # Same 'DATABASE_ROLE' -> 'DATABASE ROLE' normalization as granted_to above
        granted_on = row["GRANTED_ON"]
        if granted_on == "DATABASE_ROLE":
            granted_on = "DATABASE ROLE"
        name = row["NAME"]
        table_catalog = row.get("TABLE_CATALOG")
        table_schema = row.get("TABLE_SCHEMA")

        if granted_on == "ACCOUNT":
            # Account grants don't need qualification
            pass
        elif granted_on == "DATABASE":
            # Database grants: NAME is already the database name
            pass
        elif granted_on == "SCHEMA":
            # Schema grants: need DATABASE.SCHEMA
            if table_catalog:
                name = f"{table_catalog}.{name}"
        elif granted_on == "DATABASE ROLE":
            # Database role grants: need DATABASE.ROLE
            if table_catalog:
                name = f"{table_catalog}.{name}"
        else:
            # Schema-scoped objects (TABLE, VIEW, FUNCTION, etc.): need DATABASE.SCHEMA.OBJECT
            if table_catalog and table_schema:
                name = f"{table_catalog}.{table_schema}.{name}"

        normalized_grants.append(
            {
                "created_on": row["CREATED_ON"],
                "privilege": row["PRIVILEGE"],
                "granted_on": granted_on,
                "name": name,
                "granted_to": granted_to,
                "grantee_name": row["GRANTEE_NAME"],
                "grant_option": grant_option,
                "granted_by": row["GRANTED_BY"],
                # Inherited grants describe a container, not a securable. NAME is empty for
                # them, and the container comes from these columns instead.
                "is_inherited": bool(row.get("IS_INHERITED")),
                "inherited_from": row.get("INHERITED_FROM") or "",
                "inherited_from_database": row.get("INHERITED_FROM_DATABASE") or "",
                "inherited_from_schema": row.get("INHERITED_FROM_SCHEMA") or "",
            }
        )

    logger.debug(f"Fetched {len(normalized_grants)} grants from ACCOUNT_USAGE.GRANTS_TO_ROLES")

    # Cache the results
    _ACCOUNT_USAGE_GRANTS_CACHE[session_id] = normalized_grants

    # Also mark that we have ACCOUNT_USAGE access (query succeeded)
    _ACCOUNT_USAGE_ACCESS_CACHE[session_id] = True

    return normalized_grants


def _fetch_role_grants_to_users_from_account_usage(session: SnowflakeConnection) -> list[dict[str, Any]] | None:
    """
    Fetch all role-to-user grants from SNOWFLAKE.ACCOUNT_USAGE.GRANTS_TO_USERS in a single query.

    Returns a list of grant dictionaries with keys matching SHOW GRANTS OF ROLE output:
        - created_on: datetime when grant was created
        - role: name of the role being granted
        - granted_to: always 'USER'
        - grantee_name: name of the user receiving the grant
        - granted_by: role that granted the privilege

    Results are cached per session to avoid repeated queries.

    Returns:
        List of grant dictionaries, or None if the query fails (signaling fallback needed).
    """
    # Check cache first
    session_id = id(session)
    if session_id in _ACCOUNT_USAGE_USER_GRANTS_CACHE:
        return _ACCOUNT_USAGE_USER_GRANTS_CACHE[session_id]

    query = """
        SELECT
            CREATED_ON,
            ROLE,
            GRANTED_TO,
            GRANTEE_NAME,
            GRANTED_BY
        FROM SNOWFLAKE.ACCOUNT_USAGE.GRANTS_TO_USERS
        WHERE DELETED_ON IS NULL
    """
    try:
        results = execute(session, query, cacheable=True)
    except ProgrammingError as err:
        if err.errno == ACCESS_CONTROL_ERR:
            logger.warning("ACCOUNT_USAGE GRANTS_TO_USERS query failed: access denied - falling back to SHOW queries")
        else:
            logger.warning(
                f"ACCOUNT_USAGE GRANTS_TO_USERS query failed with error {err.errno}: {err.msg} - falling back to SHOW queries"
            )
        _mark_account_usage_fallback(session)
        return None
    except Exception as err:
        logger.warning(f"ACCOUNT_USAGE GRANTS_TO_USERS query failed unexpectedly: {err} - falling back to SHOW queries")
        _mark_account_usage_fallback(session)
        return None

    # Normalize results to match SHOW GRANTS OF ROLE structure
    normalized_grants = []
    for row in results:
        normalized_grants.append(
            {
                "created_on": row["CREATED_ON"],
                "role": row["ROLE"],
                "granted_to": row["GRANTED_TO"],
                "grantee_name": row["GRANTEE_NAME"],
                "granted_by": row["GRANTED_BY"],
            }
        )

    logger.debug(f"Fetched {len(normalized_grants)} role grants to users from ACCOUNT_USAGE.GRANTS_TO_USERS")

    # Cache the results
    _ACCOUNT_USAGE_USER_GRANTS_CACHE[session_id] = normalized_grants

    return normalized_grants


def _fetch_future_grants_for_all_roles(
    session: SnowflakeConnection, role_names: list[ResourceName]
) -> dict[str, list[dict[str, Any]]]:
    """
    Fetch future grants for all specified roles using SHOW FUTURE GRANTS commands.

    Note: Future grants are NOT available in SNOWFLAKE.ACCOUNT_USAGE views.
    They represent templates for privileges that will be applied when new objects
    are created, not actual granted privileges. Therefore, SHOW FUTURE GRANTS
    commands must be used.

    Args:
        session: Snowflake connection
        role_names: List of role names to fetch future grants for

    Returns:
        Dictionary mapping role names (as strings) to their list of future grant dicts.
        Each future grant dict has keys matching _show_future_grants_to_role() output:
            - created_on: datetime when future grant was created
            - privilege: name of the privilege
            - grant_on: 'SCHEMA' (from SHOW output)
            - granted_on: 'DATABASE' or 'SCHEMA' (inferred from name pattern)
            - name: object pattern (e.g., 'DB_NAME.<SCHEMA>' or 'DB_NAME.SCHEMA_NAME.<TABLE>')
            - grant_to: 'ROLE'
            - grantee_name: name of the role receiving the future grant
            - grant_option: 'true' or 'false'
    """
    from concurrent.futures import ThreadPoolExecutor, as_completed

    future_grants_by_role: dict[str, list[dict[str, Any]]] = {}

    def fetch_for_role(role_name: ResourceName) -> tuple[str, list[dict[str, Any]]]:
        grants = _show_future_grants_to_role(session, role_name, cacheable=True)
        return str(role_name), grants

    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = {executor.submit(fetch_for_role, role_name): role_name for role_name in role_names}
        for future in as_completed(futures):
            role_name_str, grants = future.result()
            future_grants_by_role[role_name_str] = grants

    total_grants = sum(len(g) for g in future_grants_by_role.values())
    logger.debug(f"Fetched {total_grants} future grants for {len(role_names)} roles using SHOW FUTURE GRANTS")
    return future_grants_by_role


def _fetch_future_grants_for_all_database_roles(
    session: SnowflakeConnection, database_role_fqns: list[FQN]
) -> dict[str, list[dict[str, Any]]]:
    """
    Fetch future grants for all specified database roles using SHOW FUTURE GRANTS commands.

    Note: Future grants are NOT available in SNOWFLAKE.ACCOUNT_USAGE views.
    They represent templates for privileges that will be applied when new objects
    are created, not actual granted privileges. Therefore, SHOW FUTURE GRANTS
    commands must be used.

    Args:
        session: Snowflake connection
        database_role_fqns: List of FQN objects for database roles (with database and name)

    Returns:
        Dictionary mapping fully qualified database role names (e.g., "DB.ROLE") to their
        list of future grant dicts. Each future grant dict has keys matching
        _show_future_grants_to_database_role() output.
    """
    from concurrent.futures import ThreadPoolExecutor, as_completed

    future_grants_by_db_role: dict[str, list[dict[str, Any]]] = {}

    def fetch_for_db_role(db_role_fqn: FQN) -> tuple[str, list[dict[str, Any]]]:
        fq_name = f"{db_role_fqn.database}.{db_role_fqn.name}"
        grants = _show_future_grants_to_database_role(session, fq_name, cacheable=True)
        return fq_name, grants

    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = {executor.submit(fetch_for_db_role, fqn): fqn for fqn in database_role_fqns}
        for future in as_completed(futures):
            db_role_name_str, grants = future.result()
            future_grants_by_db_role[db_role_name_str] = grants

    total_grants = sum(len(g) for g in future_grants_by_db_role.values())
    logger.debug(
        f"Fetched {total_grants} future grants for {len(database_role_fqns)} database roles using SHOW FUTURE GRANTS"
    )
    return future_grants_by_db_role


# ------------------------------
# Fetch Resources
# ------------------------------


def fetch_account(session: SnowflakeConnection, fqn: FQN):
    return {
        "name": None,
        "locator": None,
    }


def fetch_account_parameter(session: SnowflakeConnection, fqn: FQN):
    show_result = execute(session, "SHOW PARAMETERS IN ACCOUNT", cacheable=True)
    account_parameters = _filter_result(show_result, key=fqn.name, level="ACCOUNT")
    if len(account_parameters) == 0:
        return None
    if len(account_parameters) > 1:
        raise Exception(f"Found multiple account parameters matching {fqn}")
    data = account_parameters[0]
    return {
        "name": ResourceName(data["key"]),
        "value": _cast_param_value(data["value"], data["type"]),
    }


def fetch_aggregation_policy(session: SnowflakeConnection, fqn: FQN):
    show_result = _show_resources(session, "AGGREGATION POLICIES", fqn)
    if len(show_result) == 0:
        return None
    if len(show_result) > 1:
        raise Exception(f"Found multiple aggregation policies matching {fqn}")
    data = show_result[0]
    desc_result = execute(session, f"DESC AGGREGATION POLICY {fqn}")
    properties = desc_result[0]
    return {
        "name": _quote_snowflake_identifier(data["name"]),
        "body": properties["body"],
        "owner": _get_owner_identifier(data),
    }


def fetch_alert(session: SnowflakeConnection, fqn: FQN):
    alerts = _show_resources(session, "ALERTS", fqn)
    if len(alerts) == 0:
        return None
    if len(alerts) > 1:
        raise Exception(f"Found multiple alerts matching {fqn}")
    data = alerts[0]
    return {
        "name": _quote_snowflake_identifier(data["name"]),
        "warehouse": data["warehouse"] or None,
        "schedule": data["schedule"] or None,
        "comment": data["comment"] or None,
        "condition": data["condition"],
        "then": data["action"],
        "state": str(data["state"]).upper(),
        "owner": _get_owner_identifier(data),
    }


def fetch_api_integration(session: SnowflakeConnection, fqn: FQN):
    integrations = _show_resources(session, "API INTEGRATIONS", fqn)
    if len(integrations) == 0:
        return None
    if len(integrations) > 1:
        raise Exception(f"Found multiple api integrations matching {fqn}")
    data = integrations[0]
    desc_result = execute(session, f"DESC API INTEGRATION {fqn}")
    properties = _desc_type2_result_to_dict(desc_result, lower_properties=True)
    owner = _fetch_owner(session, "INTEGRATION", fqn)

    # Different api_provider values return different DESC properties:
    #   AWS_API_GATEWAY family  -> api_aws_role_arn
    #   AZURE_API_MANAGEMENT    -> azure_tenant_id, azure_ad_application_id
    #   GOOGLE_API_GATEWAY      -> google_audience
    #   GIT_HTTPS_API           -> none of the above
    # Use .get() so missing fields fall back to None instead of crashing.
    return {
        "name": _quote_snowflake_identifier(data["name"]),
        "api_provider": properties["api_provider"],
        "api_aws_role_arn": properties.get("api_aws_role_arn") or None,
        "azure_tenant_id": properties.get("azure_tenant_id") or None,
        "azure_ad_application_id": properties.get("azure_ad_application_id") or None,
        "google_audience": properties.get("google_audience") or None,
        "enabled": properties["enabled"],
        "api_allowed_prefixes": properties.get("api_allowed_prefixes"),
        "api_blocked_prefixes": properties.get("api_blocked_prefixes"),
        "owner": owner,
        "comment": data["comment"] or None,
    }


def fetch_authentication_policy(session: SnowflakeConnection, fqn: FQN):
    policies = _show_resources(session, "AUTHENTICATION POLICIES", fqn)
    if len(policies) == 0:
        return None
    if len(policies) > 1:
        raise Exception(f"Found multiple authentication policies matching {fqn}")
    data = policies[0]
    desc_result = execute(session, f"DESC AUTHENTICATION POLICY {fqn}")
    properties = _desc_result_to_dict(desc_result, lower_properties=True)

    # mfa_authentication_methods is deprecated as of Snowflake 2025_06 bundle.
    # Snowflake returns a default value ['PASSWORD'] even when not set.
    # Return None when it's the default to avoid false drift detection.
    mfa_auth_methods = _parse_list_property(properties["mfa_authentication_methods"])
    if mfa_auth_methods == ["PASSWORD"]:
        mfa_auth_methods = None

    # pat_policy's brace shape is doc-derived and unverified against a live account (see
    # _suppress_default_pat_policy above), so a parse failure must degrade to None instead of
    # aborting the whole account-wide fetch pipeline (blueprint.py re-raises fetch exceptions).
    try:
        pat_policy = _suppress_default_pat_policy(_parse_pat_policy_property(properties.get("pat_policy")))
    except Exception as err:
        logger.warning(f"Failed to parse pat_policy property {properties.get('pat_policy')!r}: {err}")
        pat_policy = None

    return {
        "name": _quote_snowflake_identifier(data["name"]),
        "authentication_methods": _parse_list_property(properties["authentication_methods"]),
        "mfa_authentication_methods": mfa_auth_methods,
        "mfa_enrollment": properties["mfa_enrollment"],
        "client_types": _parse_list_property(properties["client_types"]),
        "security_integrations": _parse_list_property(properties["security_integrations"]),
        "pat_policy": pat_policy,
        "comment": data["comment"] or None,
        "owner": _get_owner_identifier(data),
    }


def fetch_catalog_integration(session: SnowflakeConnection, fqn: FQN):
    integrations = _show_resources(session, "CATALOG INTEGRATIONS", fqn)
    if len(integrations) == 0:
        return None
    if len(integrations) > 1:
        raise Exception(f"Found multiple catalog integrations matching {fqn}")

    data = integrations[0]
    desc_result = execute(session, f"DESC CATALOG INTEGRATION {fqn}")
    properties = _desc_type2_result_to_dict(desc_result, lower_properties=True)
    owner = _fetch_owner(session, "INTEGRATION", fqn)

    if properties["catalog_source"] == "GLUE":
        return {
            "name": _quote_snowflake_identifier(data["name"]),
            "catalog_source": properties["catalog_source"],
            "catalog_namespace": properties["catalog_namespace"],
            "table_format": properties["table_format"],
            "glue_aws_role_arn": properties["glue_aws_role_arn"],
            "glue_catalog_id": properties["glue_catalog_id"],
            "glue_region": properties["glue_region"],
            "enabled": properties["enabled"],
            "owner": owner,
            "comment": data["comment"] or None,
        }
    elif properties["catalog_source"] == "OBJECT_STORE":
        return {
            "name": _quote_snowflake_identifier(data["name"]),
            "catalog_source": properties["catalog_source"],
            "table_format": properties["table_format"],
            "enabled": properties["enabled"],
            "owner": owner,
            "comment": data["comment"] or None,
        }
    elif properties["catalog_source"] == "ICEBERG_REST":
        # REST_CONFIG / REST_AUTHENTICATION come back from DESC as EnumMap-typed
        # values. They're declared non-fetchable on the dataclass (YAML is the
        # source of truth), but we still parse them so consumers introspecting
        # the fetched state can see what's there.
        return {
            "name": _quote_snowflake_identifier(data["name"]),
            "catalog_source": properties["catalog_source"],
            "table_format": properties["table_format"],
            "catalog_namespace": properties.get("catalog_namespace"),
            "rest_config": _parse_enum_map(properties.get("rest_config")),
            "rest_authentication": _parse_enum_map(properties.get("rest_authentication")),
            "enabled": properties["enabled"],
            "refresh_interval_seconds": properties.get("refresh_interval_seconds"),
            "owner": owner,
            "comment": data["comment"] or None,
        }
    else:
        raise Exception(f"Unsupported catalog integration: {properties['catalog_source']}")


def _parse_enum_map(value):
    """Parse Snowflake DESC EnumMap values like '{KEY=VAL, KEY=VAL}' into a dict.

    Values may contain '=' (e.g., URLs, base64) so we split each key=value pair
    on the first '=' only. Empty/None inputs return None. 'null' values map to
    None to match Snowflake's representation.
    """
    if value is None:
        return None
    if isinstance(value, dict):
        return value
    if not isinstance(value, str):
        return value
    body = value.strip()
    if not body.startswith("{") or not body.endswith("}"):
        return value
    body = body[1:-1].strip()
    if not body:
        return {}
    out = {}
    # Snowflake separates pairs with ", " — values don't contain literal ", " so
    # this is safe enough; falls back to single-pair if no comma. Drop null
    # values so the parsed dict only contains explicitly-set fields (Snowflake
    # echoes optional fields as null when unset).
    for pair in body.split(", "):
        if "=" not in pair:
            continue
        k, v = pair.split("=", 1)
        k = k.strip().lower()
        v = v.strip()
        if v == "null" or v == "":
            continue
        out[k] = v
    return out


# _PAT_POLICY_DEFAULT (imported from resources.authentication_policy, shared with the
# resource's __post_init__ so the declared spec and the fetched state suppress defaults
# identically) is the fetch layer's pat_policy key schema (used to filter out sub-keys like
# REQUIRE_ROLE_RESTRICTION_FOR_SERVICE_USERS) and the suppression sentinel below.


def _parse_pat_policy_property(prop_value: Optional[str]) -> Optional[dict]:
    # Contract: returns a COMPLETE dict (all _PAT_POLICY_DEFAULT keys), None (absent/empty/null
    # input), or raises. A partial dict must never escape — __post_init__ on the resource dataclass
    # enforces "None or complete" and blueprint.py re-raises any exception, aborting the
    # account-wide fetch for every resource, so malformed input has to raise here and be caught by
    # the fetch layer's except -> logger.warning -> None fallback.
    if prop_value is None or prop_value == "" or prop_value == "null":
        return None
    parsed = _parse_enum_map(prop_value)
    if not isinstance(parsed, dict):
        raise ValueError(f"Unexpected pat_policy format: {prop_value!r}")
    pat_policy = {key: parsed[key] for key in _PAT_POLICY_DEFAULT if key in parsed}
    if pat_policy.keys() != _PAT_POLICY_DEFAULT.keys():
        raise ValueError(f"Incomplete pat_policy fields: {prop_value!r}")
    pat_policy["default_expiry_in_days"] = int(pat_policy["default_expiry_in_days"])
    pat_policy["max_expiry_in_days"] = int(pat_policy["max_expiry_in_days"])
    require_role = pat_policy["require_role_restriction_for_service_users"]
    if not isinstance(require_role, bool):
        if str(require_role).lower() not in ("true", "false"):
            raise ValueError(f"Unexpected pat_policy boolean: {prop_value!r}")
        pat_policy["require_role_restriction_for_service_users"] = str(require_role).lower() == "true"
    return pat_policy


def _suppress_default_pat_policy(pat_policy: Optional[dict]) -> Optional[dict]:
    # pat_policy is doc-derived (unverified against a live DESC AUTHENTICATION POLICY output),
    # mirroring the mfa_authentication_methods drift-avoidance above: Snowflake echoes this
    # default even when pat_policy was never explicitly set, so treat it as "unset" to avoid
    # false drift detection.
    return None if pat_policy == _PAT_POLICY_DEFAULT else pat_policy


def fetch_columns(session: SnowflakeConnection, resource_type: str, fqn: FQN):
    desc_result = execute(session, f"DESC {resource_type} {fqn}")
    columns = []
    for col in desc_result:
        if col["kind"] != "COLUMN":
            raise Exception(f"Unexpected kind {col['kind']} in desc result")
        columns.append(
            {
                "name": col["name"],
                "data_type": col["type"],
                "not_null": col["null?"] == "N",
                "default": col["default"],
                "comment": col["comment"] or None,
                "constraint": None,
                "collate": None,
            }
        )
    return columns


def fetch_compute_pool(session: SnowflakeConnection, fqn: FQN):
    show_result = execute(session, f"SHOW COMPUTE POOLS LIKE '{fqn.name}'", cacheable=True)

    if len(show_result) == 0:
        return None
    if len(show_result) > 1:
        raise Exception(f"Found multiple compute pools matching {fqn}")

    data = show_result[0]

    return {
        "name": _quote_snowflake_identifier(data["name"]),
        "owner": _get_owner_identifier(data),
        "min_nodes": data["min_nodes"],
        "max_nodes": data["max_nodes"],
        "instance_family": data["instance_family"],
        "auto_resume": data["auto_resume"] == "true",
        "auto_suspend_secs": data["auto_suspend_secs"],
        "comment": data["comment"] or None,
    }


def fetch_database(session: SnowflakeConnection, fqn: FQN, include_params: bool = True):
    show_result = _show_resources(session, "DATABASES", fqn)

    if len(show_result) == 0:
        return None
    if len(show_result) > 1:
        raise Exception(f"Found multiple databases matching {fqn}")

    data = show_result[0]

    if data["kind"] == "IMPORTED DATABASE":
        return fetch_shared_database(session, fqn)

    is_standard_db = data["kind"] == "STANDARD"
    is_snowflake_builtin = data["kind"] == "APPLICATION" and data["name"] in SYSTEM_DATABASES

    if not (is_standard_db or is_snowflake_builtin):
        return None

    options = options_result_to_list(data["options"])

    # Only fetch parameters if needed (expensive SHOW PARAMETERS query)
    if include_params:
        params = _show_resource_parameters(session, "DATABASE", fqn)
        max_data_extension = params.get("max_data_extension_time_in_days")
        external_volume = params.get("external_volume")
        catalog = params.get("catalog")
        default_ddl_collation = params["default_ddl_collation"]
    else:
        max_data_extension = None
        external_volume = None
        catalog = None
        default_ddl_collation = None

    return {
        "name": _quote_snowflake_identifier(data["name"]),
        "data_retention_time_in_days": int(data["retention_time"]),
        "comment": data["comment"] or None,
        "transient": "TRANSIENT" in options,
        "owner": _get_owner_identifier(data),
        "max_data_extension_time_in_days": max_data_extension,
        "external_volume": external_volume,
        "catalog": catalog,
        "default_ddl_collation": default_ddl_collation,
    }


def fetch_database_role(session: SnowflakeConnection, fqn: FQN):
    try:
        show_result = execute(session, f"SHOW DATABASE ROLES IN DATABASE {fqn.database}", cacheable=True)
    except ProgrammingError as err:
        if err.errno == DOES_NOT_EXIST_ERR:
            return None
        raise

    roles = _filter_result(show_result, name=fqn.name)
    if len(roles) == 0:
        return None
    if len(roles) > 1:
        raise Exception(f"Found multiple database roles matching {fqn}")
    data = roles[0]
    return {
        "name": _quote_snowflake_identifier(data["name"]),
        "owner": _get_owner_identifier(data),
        "database": fqn.database,
        "comment": data["comment"] or None,
    }


def _database_role_grantee_fqn(grantee_name: str, default_database: Optional[ResourceName]) -> FQN:
    """
    Build an FQN for a DATABASE_ROLE grant's grantee.

    Snowflake reports a database-role grantee unqualified when it lives in the same
    database as the role granting it, but fully qualified when it's in another database.
    Parsing it as an FQN and filling in default_database only when it's missing makes both
    cases comparable to DatabaseRoleGrant.to_database_role's FQN, which is always fully
    qualified.
    """
    grantee_fqn = parse_FQN(grantee_name, is_db_scoped=True)
    if grantee_fqn.database is None:
        grantee_fqn.database = default_database
    return grantee_fqn


def fetch_database_role_grant(session: SnowflakeConnection, fqn: FQN):
    show_result = execute(session, f"SHOW GRANTS OF DATABASE ROLE {fqn.database}.{fqn.name}", cacheable=True)

    subject, subject_name = next(iter(fqn.params.items()))

    if subject == "database_role":
        target = parse_FQN(subject_name, is_db_scoped=True)
        role_grants = [
            row
            for row in _filter_result(show_result, granted_to=subject.upper())
            if _database_role_grantee_fqn(row["grantee_name"], fqn.database) == target
        ]
    else:
        role_grants = _filter_result(show_result, granted_to=subject.upper(), grantee_name=subject_name)

    if len(role_grants) == 0:
        return None
    if len(role_grants) > 1:
        raise Exception(f"Found multiple database role grants matching {fqn}")

    data = role_grants[0]

    to_role = None
    to_database_role = None
    if data["granted_to"] == "ROLE":
        to_role = _quote_snowflake_identifier(data["grantee_name"])
    elif data["granted_to"] == "DATABASE_ROLE":
        to_database_role = str(_database_role_grantee_fqn(data["grantee_name"], fqn.database))

    return {
        "database_role": data["role"],
        "to_role": to_role,
        "to_database_role": to_database_role,
    }


def fetch_dbt_project(session: SnowflakeConnection, fqn: FQN):
    projects = _show_resources(session, "DBT PROJECTS", fqn)
    if len(projects) == 0:
        return None
    if len(projects) > 1:
        raise Exception(f"Found multiple dbt projects matching {fqn}")

    data = projects[0]
    return {
        "name": data["name"],
        "owner": _get_owner_identifier(data),
        "comment": data.get("comment") or None,
    }


def fetch_dynamic_table(session: SnowflakeConnection, fqn: FQN):
    show_result = _show_resources(session, "DYNAMIC TABLES", fqn)
    if len(show_result) == 0:
        return None
    if len(show_result) > 1:
        raise Exception(f"Found multiple dynamic tables matching {fqn}")

    columns = fetch_columns(session, "DYNAMIC TABLE", fqn)
    columns = [{"name": col["name"], "comment": col["comment"]} for col in columns]

    data = show_result[0]
    refresh_mode, initialize, as_ = _parse_dynamic_table_text(data["text"])
    return {
        "name": _quote_snowflake_identifier(data["name"]),
        "owner": _get_owner_identifier(data),
        "warehouse": data["warehouse"],
        "refresh_mode": refresh_mode,
        "initialize": initialize,
        "target_lag": data["target_lag"],
        "comment": data["comment"] or None,
        "columns": columns,
        "as_": as_,
    }


def fetch_event_table(session: SnowflakeConnection, fqn: FQN):
    show_result = execute(session, "SHOW EVENT TABLES IN ACCOUNT")

    tables = _filter_result(show_result, name=fqn.name, database_name=fqn.database, schema_name=fqn.schema)

    if len(tables) == 0:
        return None
    if len(tables) > 1:
        raise Exception(f"Found multiple tables matching {fqn}")

    data = tables[0]
    return {
        "name": _quote_snowflake_identifier(data["name"]),
        "comment": data["comment"] or None,
        "cluster_by": _parse_cluster_keys(data["cluster_by"]),
        "data_retention_time_in_days": int(data["retention_time"]),
        "change_tracking": data["change_tracking"] == "ON",
        "owner": _get_owner_identifier(data),
    }


def fetch_integration(session: SnowflakeConnection, fqn: FQN):
    """
    Fetch any integration regardless of concrete subtype.

    Backs the generic `ResourceType.INTEGRATION` registered in RESOURCE_SCOPES so
    that grants like `on: integration <fqn>` parse and resolve (Snowflake's
    `GRANT USAGE ON INTEGRATION <name>` syntax accepts any subtype; this fetcher
    returns the minimum SHOW INTEGRATIONS metadata so the grant's required-ref
    check succeeds).
    """
    show_result = execute(session, "SHOW INTEGRATIONS", cacheable=True)
    show_result = _filter_result(show_result, name=fqn.name)
    if len(show_result) == 0:
        return None
    if len(show_result) > 1:
        raise Exception(f"Found multiple integrations matching {fqn}")
    data = show_result[0]
    owner = _fetch_owner(session, "INTEGRATION", fqn)
    return {
        "name": _quote_snowflake_identifier(data["name"]),
        "type": data["type"],
        "category": data["category"],
        "enabled": data["enabled"] == "true",
        "comment": data["comment"] or None,
        "owner": owner,
    }


def fetch_external_access_integration(session: SnowflakeConnection, fqn: FQN):
    integrations = _show_resources(session, "EXTERNAL ACCESS INTEGRATIONS", fqn)
    if len(integrations) == 0:
        return None
    if len(integrations) > 1:
        raise Exception(f"Found multiple external access integrations matching {fqn}")

    data = integrations[0]
    desc_result = execute(session, f"DESC EXTERNAL ACCESS INTEGRATION {fqn}", cacheable=True)
    properties = _desc_type2_result_to_dict(desc_result, lower_properties=True)
    owner = _fetch_owner(session, "INTEGRATION", fqn)
    return {
        "name": _quote_snowflake_identifier(data["name"]),
        "allowed_network_rules": properties["allowed_network_rules"],
        "allowed_api_authentication_integrations": properties["allowed_api_authentication_integrations"] or None,
        "allowed_authentication_secrets": properties["allowed_authentication_secrets"] or None,
        "enabled": data["enabled"] == "true",
        "owner": owner,
        "comment": data["comment"] or None,
    }


def fetch_external_volume(session: SnowflakeConnection, fqn: FQN):
    show_result = _show_resources(session, "EXTERNAL VOLUMES", fqn)
    if len(show_result) == 0:
        return None
    if len(show_result) > 1:
        raise Exception(f"Found multiple external volumes matching {fqn}")

    data = show_result[0]
    desc_result = execute(session, f"DESC EXTERNAL VOLUME {fqn}", cacheable=True)
    properties = _desc_type3_result_to_dict(desc_result, lower_properties=True)
    owner = _fetch_owner(session, "VOLUME", fqn)

    storage_locations = []
    index = 1
    while True:
        storage_location = properties["storage_locations"].get(f"storage_location_{index}")
        if storage_location is None:
            break
        storage_locations.append(_parse_storage_location(storage_location))
        index += 1

    return {
        "name": _quote_snowflake_identifier(data["name"]),
        "owner": owner,
        "storage_locations": storage_locations,
        "allow_writes": data["allow_writes"] == "true",
        "comment": data["comment"] or None,
    }


def fetch_file_format(session: SnowflakeConnection, fqn: FQN):
    show_result = _show_resources(session, "FILE FORMATS", fqn)
    if len(show_result) == 0:
        return None
    if len(show_result) > 1:
        raise Exception(f"Found multiple file formats matching {fqn}")

    data = show_result[0]
    format_options = json.loads(data["format_options"])

    if data["type"] == "CSV":
        return {
            "name": _quote_snowflake_identifier(data["name"]),
            "type": data["type"],
            "owner": _get_owner_identifier(data),
            "field_delimiter": format_options["FIELD_DELIMITER"],
            "skip_header": format_options["SKIP_HEADER"],
            "null_if": format_options["NULL_IF"] or None,
            "empty_field_as_null": format_options["EMPTY_FIELD_AS_NULL"],
            "compression": format_options["COMPRESSION"],
            "record_delimiter": format_options["RECORD_DELIMITER"],
            "file_extension": format_options["FILE_EXTENSION"],
            "parse_header": format_options["PARSE_HEADER"],
            "skip_blank_lines": format_options["SKIP_BLANK_LINES"],
            "date_format": format_options["DATE_FORMAT"],
            "time_format": format_options["TIME_FORMAT"],
            "timestamp_format": format_options["TIMESTAMP_FORMAT"],
            "binary_format": format_options["BINARY_FORMAT"],
            "escape": format_options["ESCAPE"] if format_options["ESCAPE"] != "NONE" else None,
            "escape_unenclosed_field": format_options["ESCAPE_UNENCLOSED_FIELD"],
            "trim_space": format_options["TRIM_SPACE"],
            "field_optionally_enclosed_by": (
                format_options["FIELD_OPTIONALLY_ENCLOSED_BY"]
                if format_options["FIELD_OPTIONALLY_ENCLOSED_BY"] != "NONE"
                else None
            ),
            "error_on_column_count_mismatch": format_options["ERROR_ON_COLUMN_COUNT_MISMATCH"],
            "replace_invalid_characters": format_options["REPLACE_INVALID_CHARACTERS"],
            "skip_byte_order_mark": format_options["SKIP_BYTE_ORDER_MARK"],
            "encoding": format_options["ENCODING"],
            "comment": data["comment"] or None,
        }
    elif data["type"] == "PARQUET":
        return {
            "name": _quote_snowflake_identifier(data["name"]),
            "type": data["type"],
            "owner": _get_owner_identifier(data),
            "comment": data["comment"] or None,
            "compression": format_options["COMPRESSION"],
            "binary_as_text": format_options["BINARY_AS_TEXT"],
            "trim_space": format_options["TRIM_SPACE"],
            "replace_invalid_characters": format_options["REPLACE_INVALID_CHARACTERS"],
            "null_if": format_options["NULL_IF"] or None,
        }
    elif data["type"] == "JSON":
        return {
            "name": _quote_snowflake_identifier(data["name"]),
            "type": data["type"],
            "owner": _get_owner_identifier(data),
            "comment": data["comment"] or None,
            "compression": format_options["COMPRESSION"],
            "date_format": format_options["DATE_FORMAT"],
            "time_format": format_options["TIME_FORMAT"],
            "timestamp_format": format_options["TIMESTAMP_FORMAT"],
            "binary_format": format_options["BINARY_FORMAT"],
            "trim_space": format_options["TRIM_SPACE"],
            "null_if": format_options["NULL_IF"] or None,
            "file_extension": format_options["FILE_EXTENSION"],
            "enable_octal": format_options["ENABLE_OCTAL"],
            "allow_duplicate": format_options["ALLOW_DUPLICATE"],
            "strip_outer_array": format_options["STRIP_OUTER_ARRAY"],
            "strip_null_values": format_options["STRIP_NULL_VALUES"],
            "replace_invalid_characters": format_options["REPLACE_INVALID_CHARACTERS"],
            "ignore_utf8_errors": format_options["IGNORE_UTF8_ERRORS"],
            "skip_byte_order_mark": format_options["SKIP_BYTE_ORDER_MARK"],
        }
    else:
        raise Exception(f"Unsupported file format type: {data['type']}")


def fetch_function(session: SnowflakeConnection, fqn: FQN):
    udfs = _show_resources(session, "USER FUNCTIONS", fqn)
    if len(udfs) == 0:
        return None
    if len(udfs) > 1:
        raise Exception(f"Found multiple functions matching {fqn}")

    data = udfs[0]
    _, returns = data["arguments"].split(" RETURN ")
    try:
        desc_result = execute(session, f"DESC FUNCTION {fqn}", cacheable=True)
    except ProgrammingError as err:
        if err.errno == DOES_NOT_EXIST_ERR:
            return None
        raise
    properties = _desc_result_to_dict(desc_result)
    owner = _fetch_owner(session, "FUNCTION", fqn)

    if data["language"] == "PYTHON":
        return {
            "name": _quote_snowflake_identifier(data["name"]),
            "secure": data["is_secure"] == "Y",
            "args": _parse_signature(properties["signature"]),
            "returns": returns,
            "language": data["language"],
            "comment": None if data["description"] == "user-defined function" else data["description"],
            "volatility": properties["volatility"],
            "as_": properties["body"],
            "owner": owner,
        }
    elif data["language"] == "JAVASCRIPT":
        return {
            "name": _quote_snowflake_identifier(data["name"]),
            "secure": data["is_secure"] == "Y",
            "args": _parse_signature(properties["signature"]),
            "returns": returns,
            "language": data["language"],
            "comment": None if data["description"] == "user-defined function" else data["description"],
            "volatility": properties["volatility"],
            "as_": properties["body"],
            "owner": owner,
        }


def _parse_grant_collection(on_type: str, on: str) -> dict[str, str]:
    """
    Split a collection grant's encoded target into container and item type.

    The account container has no name, so it is encoded as "ACCOUNT.<TABLE>" and cannot be
    told apart from a database called ACCOUNT by looking at the string alone. The container
    type travels alongside it in the URN, so it is passed in rather than inferred.
    """
    if on_type == ResourceType.ACCOUNT.value:
        _, _, items_type = on.partition(".")
        return {"on": "ACCOUNT", "on_type": "account", "items_type": items_type.strip("<>")}
    return parse_collection_string(on)


def _inherited_grant_matches(grant: dict[str, Any], items_type: str, container_type: str, container: str) -> bool:
    """Does an inherited grant row describe a grant on this container and object type?"""
    if grant["granted_on"].replace("_", " ").upper() != items_type.replace("_", " ").upper():
        return False
    inherited_from = str(grant.get("inherited_from") or "").upper()
    if inherited_from != container_type.upper():
        return False
    if container_type == "ACCOUNT":
        return True
    database = str(grant.get("inherited_from_database") or "")
    if container_type == "DATABASE":
        return ResourceName(database) == ResourceName(container)
    schema = str(grant.get("inherited_from_schema") or "")
    return ResourceName(f"{database}.{schema}") == ResourceName(container)


def fetch_inherited_grant(session: SnowflakeConnection, fqn: FQN):
    """
    Fetch a single inherited grant.

    Unlike ON ALL grants, an inherited grant is one durable record that Snowflake reports
    back, so it can be compared against config instead of being reapplied on every run.
    """
    priv = fqn.params["priv"]
    on_type, on = fqn.params["on"].split("/", 1)
    to_type, to = fqn.params["to"].split("/", 1)
    to_type = resource_type_for_label(to_type)

    collection = _parse_grant_collection(on_type.upper(), on)
    container_type = collection["on_type"].upper()
    container = collection["on"]
    items_type = collection["items_type"]

    for grant in _show_inherited_grants_to_role(session, to, role_type=to_type):
        if grant["privilege"] != priv:
            continue
        if not _inherited_grant_matches(grant, items_type, container_type, container):
            continue
        return {
            "priv": priv,
            "on": container,
            "on_type": container_type.replace("_", " "),
            "to": to,
            "to_type": resource_type_for_label(grant["granted_to"]),
            "grant_option": False,
            "owner": grant.get("granted_by") or "",
            "_privs": [priv],
            "items_type": items_type.replace("_", " "),
            "grant_type": GrantType.INHERITED,
        }
    return None


def fetch_grant(session: SnowflakeConnection, fqn: FQN):
    priv = fqn.params["priv"]
    on_type, on = fqn.params["on"].split("/", 1)
    # Two forms of on_type are in play (verified live 2026-07-24):
    #   - canonical (spec/diff) form: spaced, e.g. 'CATALOG INTEGRATION',
    #     'GIT REPOSITORY' — what the Grant model stores and what we return.
    #   - SHOW GRANTS query form: all *-integration types collapse to the bare
    #     word 'INTEGRATION'; everything else keeps the underscored label
    #     uppercased ('GIT_REPOSITORY', 'SCHEMA', ...).
    query_on_type = "INTEGRATION" if on_type.lower().endswith("_integration") else on_type.upper()
    on_type = on_type.upper().replace("_", " ")
    to_type, to = fqn.params["to"].split("/", 1)
    to_type = resource_type_for_label(to_type)
    # Default to OBJECT grant type if not specified
    grant_type = fqn.params.get("grant_type", GrantType.OBJECT)

    if grant_type == GrantType.INHERITED:
        return fetch_inherited_grant(session, fqn)

    if priv == "ALL":
        filters = {
            "granted_on": query_on_type,
        }

        if query_on_type != "ACCOUNT":
            filters["name"] = on

        if grant_type == GrantType.FUTURE:
            if to_type == ResourceType.DATABASE_ROLE:
                grants = _show_future_grants_to_database_role(session, str(to), cacheable=True)
            else:
                grants = _show_future_grants_to_role(session, to, cacheable=True)
        else:
            grants = _show_grants_to_role(session, to, role_type=to_type, cacheable=True)
        grants = _filter_result(grants, **filters)

        if len(grants) == 0:
            return None

        data = grants[0]
        privs = sorted([g["privilege"] for g in grants])

    else:
        data = _fetch_grant_to_role(
            session,
            grant_type=grant_type,
            role=to,
            granted_on=query_on_type,
            on_name=on,
            privilege=priv,
            role_type=to_type,
        )
        if data is None and priv == "IMPORTED PRIVILEGES" and on_type == "DATABASE":
            # Snowflake reports IMPORTED PRIVILEGES on a shared database as USAGE in SHOW GRANTS.
            # Gate on the database actually being shared: without this, a mistakenly-declared
            # IMPORTED PRIVILEGES grant on a regular database would false-match its (very common)
            # plain USAGE grant and mask the config error.
            # Any kind but STANDARD is share-backed: IMPORTED DATABASE for a marketplace or
            # direct share, APPLICATION for the SNOWFLAKE database, which behaves the same
            # way and was missed by testing for IMPORTED DATABASE alone. A STANDARD database
            # is the only case where a plain USAGE grant could be mistaken for this one.
            db_rows = _show_resources(session, "DATABASES", FQN(name=ResourceName(on)))
            if db_rows and db_rows[0]["kind"] != "STANDARD":
                data = _fetch_grant_to_role(
                    session,
                    grant_type=grant_type,
                    role=to,
                    granted_on=on_type,
                    on_name=on,
                    privilege="USAGE",
                    role_type=to_type,
                )
        if data is None:
            return None
        privs = [priv]

    # elif len(grants) > 1 and priv != "ALL":
    #     # This is likely to happen when a grant has been issued by ACCOUNTADMIN
    #     # and some other role with MANAGE GRANTS or OWNERSHIP. It needs to be properly
    #     # handled in the future.
    #     raise Exception(f"Found multiple grants matching {fqn}")

    items_type = None
    if grant_type == GrantType.FUTURE:
        collection = parse_collection_string(on)
        items_type = collection["items_type"].upper()
        on_type = collection["on_type"]
        on = collection["on"]
        to_type = resource_type_for_label(data["grant_to"])
        owner = ""
    else:
        to_type = resource_type_for_label(data["granted_to"])
        owner = data["granted_by"]

    return {
        "priv": priv,
        "on": "ACCOUNT" if on_type == "ACCOUNT" else on,
        "on_type": on_type.replace("_", " "),
        "to": to,
        "to_type": to_type,
        "grant_option": data["grant_option"] == "true",
        "owner": owner,
        "_privs": privs,
        "items_type": items_type.replace("_", " ") if items_type else None,
        "grant_type": grant_type,
    }


def fetch_grant_on_all(session: SnowflakeConnection, fqn: FQN):
    # All grants are expensive to fetch, so we will assume they are always out of date
    return None


def fetch_iceberg_table(session: SnowflakeConnection, fqn: FQN, include_params: bool = True):
    tables = _show_resources(session, "ICEBERG TABLES", fqn)
    if len(tables) == 0:
        return None
    if len(tables) > 1:
        raise Exception(f"Found multiple iceberg tables matching {fqn}")

    data = tables[0]
    columns = fetch_columns(session, "ICEBERG TABLE", fqn)

    # Only fetch parameters if needed (expensive query)
    if include_params:
        show_params_result = execute(session, f"SHOW PARAMETERS FOR TABLE {fqn}")
        params = params_result_to_dict(show_params_result)
    else:
        params = {}

    return {
        "name": fqn.name,
        "owner": data["owner"],
        "columns": columns,
        "external_volume": data["external_volume_name"],
        "catalog": data["catalog_name"],
        "base_location": data["base_location"].rstrip("/"),
        "catalog_sync": params.get("catalog_sync") or None,
        "storage_serialization_policy": params.get("storage_serialization_policy"),
        "data_retention_time_in_days": params.get("data_retention_time_in_days"),
        "max_data_extension_time_in_days": params.get("max_data_extension_time_in_days"),
        # "change_tracking": data["change_tracking"],
        "default_ddl_collation": params.get("default_ddl_collation") or None,
        "comment": data["comment"] or None,
    }


def fetch_image_repository(session: SnowflakeConnection, fqn: FQN):
    repos = _show_resources(session, "IMAGE REPOSITORIES", fqn)

    if len(repos) == 0:
        return None
    if len(repos) > 1:
        raise Exception(f"Found multiple image repositories matching {fqn}")

    data = repos[0]

    return {"name": fqn.name, "owner": _get_owner_identifier(data)}


def fetch_masking_policy(session: SnowflakeConnection, fqn: FQN):
    policies = _show_resources(session, "MASKING POLICIES", fqn)
    if len(policies) == 0:
        return None
    if len(policies) > 1:
        raise Exception(f"Found multiple masking policies matching {fqn}")

    data = policies[0]
    options = json.loads(data["options"]) if data["options"] else {}
    desc_result = execute(session, f"DESC MASKING POLICY {fqn}", cacheable=True)
    properties = desc_result[0]

    return {
        "name": data["name"],
        "owner": _get_owner_identifier(data),
        "args": _parse_signature(properties["signature"]),
        "returns": properties["return_type"],
        "body": properties["body"],
        "comment": data["comment"] or None,
        "exempt_other_policies": options.get("exempt_other_policies", "false") == "true",
    }


def fetch_materialized_view(session: SnowflakeConnection, fqn: FQN):
    materialized_views = _show_resources(session, "MATERIALIZED VIEWS", fqn)
    if len(materialized_views) == 0:
        return None
    if len(materialized_views) > 1:
        raise Exception(f"Found multiple materialized views matching {fqn}")

    data = materialized_views[0]
    columns = fetch_columns(session, "VIEW", fqn)

    return {
        "name": fqn.name,
        "owner": _get_owner_identifier(data),
        "secure": data["is_secure"] == "true",
        "columns": columns,
        "cluster_by": _parse_cluster_keys(data["cluster_by"]),
        "comment": data["comment"] or None,
        "as_": parse_view_ddl(data["text"]),
    }


def fetch_mcp_server(session: SnowflakeConnection, fqn: FQN, existence_only: bool = False):
    show_result = _show_resources(session, "MCP SERVERS", fqn)
    if len(show_result) == 0:
        return None
    if len(show_result) > 1:
        raise Exception(f"Found multiple mcp servers matching {fqn}")
    data = show_result[0]

    # For existence checks (reference validation), skip expensive DESC MCP SERVER
    if existence_only:
        return {
            "name": _quote_snowflake_identifier(data["name"]),
            "owner": _get_owner_identifier(data),
        }

    desc_result = execute(session, f"DESC MCP SERVER {fqn}")
    properties = desc_result[0]
    return {
        "name": _quote_snowflake_identifier(data["name"]),
        "owner": _get_owner_identifier(data),
        "specification": properties["server_spec"],
    }


def fetch_network_policy(session: SnowflakeConnection, fqn: FQN):
    policies = _show_resources(session, "NETWORK POLICIES", fqn)
    if len(policies) == 0:
        return None
    if len(policies) > 1:
        raise Exception(f"Found multiple network policies matching {fqn}")

    data = policies[0]
    desc_result = execute(session, f"DESC NETWORK POLICY {fqn}", cacheable=True)
    properties = _desc_type4_result_to_dict(desc_result, lower_properties=True)

    allowed_network_rule_list = None
    if "allowed_network_rule_list" in properties:
        allowed_network_rule_list = [
            rule["fullyQualifiedRuleName"] for rule in json.loads(properties["allowed_network_rule_list"])
        ]
    blocked_network_rule_list = None
    if "blocked_network_rule_list" in properties:
        blocked_network_rule_list = [
            rule["fullyQualifiedRuleName"] for rule in json.loads(properties["blocked_network_rule_list"])
        ]
    allowed_ip_list = None
    if "allowed_ip_list" in properties:
        allowed_ip_list = properties["allowed_ip_list"].split(",")
    blocked_ip_list = None
    if "blocked_ip_list" in properties:
        blocked_ip_list = properties["blocked_ip_list"].split(",")

    owner = _fetch_owner(session, "NETWORK POLICY", fqn)

    return {
        "name": data["name"],
        "allowed_network_rule_list": allowed_network_rule_list,
        "blocked_network_rule_list": blocked_network_rule_list,
        "allowed_ip_list": allowed_ip_list,
        "blocked_ip_list": blocked_ip_list,
        "comment": data["comment"] or None,
        "owner": owner,
    }


def fetch_network_rule(session: SnowflakeConnection, fqn: FQN):
    show_result = _show_resources(session, "NETWORK RULES", fqn)

    if len(show_result) == 0:
        return None
    if len(show_result) > 1:
        raise Exception(f"Found multiple network rules matching {fqn}")

    desc_result = execute(session, f"DESC NETWORK RULE {fqn}", cacheable=True)
    properties = desc_result[0]

    data = show_result[0]
    return {
        "name": fqn.name,
        "owner": _get_owner_identifier(data),
        "type": data["type"],
        "value_list": _parse_comma_separated_values(properties["value_list"]),
        "mode": data["mode"],
        "comment": data["comment"] or None,
    }


def fetch_notebook(session: SnowflakeConnection, fqn: FQN):
    notebooks = _show_resources(session, "NOTEBOOKS", fqn)
    if len(notebooks) == 0:
        return None
    if len(notebooks) > 1:
        raise Exception(f"Found multiple notebooks matching {fqn}")

    data = notebooks[0]
    desc_result = execute(session, f"DESC NOTEBOOK {fqn}", cacheable=True)
    properties = desc_result[0]
    return {
        "name": data["name"],
        "main_file": None if properties["main_file"] == "notebook_app.ipynb" else properties["main_file"],
        "query_warehouse": data["query_warehouse"],
        "comment": data["comment"],
        "owner": _get_owner_identifier(data),
        # "version": data["version"],
    }


def fetch_notification_integration(session: SnowflakeConnection, fqn: FQN):
    show_result = execute(session, f"SHOW NOTIFICATION INTEGRATIONS LIKE '{fqn.name}'")
    if len(show_result) == 0:
        return None
    if len(show_result) > 1:
        raise Exception(f"Found multiple notification integrations matching {fqn}")

    data = show_result[0]
    desc_result = execute(session, f"DESC NOTIFICATION INTEGRATION {fqn.name}")
    properties = _desc_type2_result_to_dict(desc_result, lower_properties=True)

    owner = _fetch_owner(session, "INTEGRATION", fqn)

    if data["type"] == "EMAIL":
        return {
            "name": _quote_snowflake_identifier(data["name"]),
            "type": data["type"],
            "enabled": data["enabled"] == "true",
            "allowed_recipients": properties["allowed_recipients"],
            "owner": owner,
            "comment": data["comment"] or None,
        }
    elif data["type"].startswith("QUEUE"):
        # QUEUE type notifications have format like "QUEUE - GCP_PUBSUB" or "QUEUE - AZURE_STORAGE_QUEUE"
        # The direction field may or may not exist depending on the notification type
        type_parts = data["type"].split(" - ")
        notification_provider = type_parts[1] if len(type_parts) > 1 else None
        direction = data.get("direction") or properties.get("direction", "INBOUND")

        base_result = {
            "name": _quote_snowflake_identifier(data["name"]),
            "type": "QUEUE",
            "direction": direction,
            "notification_provider": notification_provider,
            "enabled": data["enabled"] == "true",
            "owner": owner,
            "comment": data["comment"] or None,
        }

        # Add provider-specific fields
        if notification_provider == "GCP_PUBSUB":
            if direction == "INBOUND":
                base_result["gcp_pubsub_subscription_name"] = properties.get("gcp_pubsub_subscription_name")
            else:  # OUTBOUND
                base_result["gcp_pubsub_topic_name"] = properties.get("gcp_pubsub_topic_name")
        elif notification_provider == "AZURE_STORAGE_QUEUE":
            base_result["azure_storage_queue_primary_uri"] = properties.get("azure_storage_queue_primary_uri")
            base_result["azure_tenant_id"] = properties.get("azure_tenant_id")
        elif notification_provider == "AZURE_EVENT_GRID":
            base_result["azure_event_grid_topic_endpoint"] = properties.get("azure_event_grid_topic_endpoint")
            base_result["azure_tenant_id"] = properties.get("azure_tenant_id")
        elif notification_provider == "AWS_SNS":
            base_result["aws_sns_topic_arn"] = properties.get("aws_sns_topic_arn")
            base_result["aws_sns_role_arn"] = properties.get("aws_sns_role_arn")

        return base_result
    else:
        raise Exception(f"Unsupported notification integration type: {data['type']}")


def fetch_packages_policy(session: SnowflakeConnection, fqn: FQN):
    show_result = _show_resources(session, "PACKAGES POLICIES", fqn)
    if len(show_result) == 0:
        return None
    if len(show_result) > 1:
        raise Exception(f"Found multiple packages policies matching {fqn}")

    data = show_result[0]
    desc_result = execute(session, f"DESC PACKAGES POLICY {fqn}")
    properties = desc_result[0]

    return {
        "name": _quote_snowflake_identifier(data["name"]),
        "language": properties["language"],
        "allowlist": _parse_packages(properties["allowlist"]),
        "blocklist": _parse_packages(properties["blocklist"]),
        "additional_creation_blocklist": _parse_packages(properties["additional_creation_blocklist"]),
        "comment": data["comment"] or None,
        "owner": _get_owner_identifier(data),
    }


def fetch_password_policy(session: SnowflakeConnection, fqn: FQN):
    policies = _show_resources(session, "PASSWORD POLICIES", fqn)
    if len(policies) == 0:
        return None
    if len(policies) > 1:
        raise Exception(f"Found multiple password policies matching {fqn}")

    data = policies[0]
    desc_result = execute(session, f"DESC PASSWORD POLICY {fqn}")
    properties = _desc_result_to_dict(desc_result)

    comment = properties["COMMENT"] if properties["COMMENT"] != "null" else None

    return {
        "name": _quote_snowflake_identifier(data["name"]),
        "password_min_length": int(properties["PASSWORD_MIN_LENGTH"]),
        "password_max_length": int(properties["PASSWORD_MAX_LENGTH"]),
        "password_min_upper_case_chars": int(properties["PASSWORD_MIN_UPPER_CASE_CHARS"]),
        "password_min_lower_case_chars": int(properties["PASSWORD_MIN_LOWER_CASE_CHARS"]),
        "password_min_numeric_chars": int(properties["PASSWORD_MIN_NUMERIC_CHARS"]),
        "password_min_special_chars": int(properties["PASSWORD_MIN_SPECIAL_CHARS"]),
        "password_min_age_days": int(properties["PASSWORD_MIN_AGE_DAYS"]),
        "password_max_age_days": int(properties["PASSWORD_MAX_AGE_DAYS"]),
        "password_max_retries": int(properties["PASSWORD_MAX_RETRIES"]),
        "password_lockout_time_mins": int(properties["PASSWORD_LOCKOUT_TIME_MINS"]),
        "password_history": int(properties["PASSWORD_HISTORY"]),
        "comment": comment,
        "owner": properties["OWNER"],
    }


def fetch_pipe(session: SnowflakeConnection, fqn: FQN):
    show_result = _show_resources(session, "PIPES", fqn)
    if len(show_result) == 0:
        return None
    if len(show_result) > 1:
        raise Exception(f"Found multiple pipes matching {fqn}")

    data = show_result[0]

    # desc_result = execute(session, f"DESC PIPE {fqn}", cacheable=True)

    return {
        "name": _quote_snowflake_identifier(data["name"]),
        "as_": data["definition"],
        "owner": _get_owner_identifier(data),
        "error_integration": data["error_integration"],
        # "aws_sns_topic": data["aws_sns_topic"],
        "integration": data["integration"],
        "comment": data["comment"],
    }


def fetch_procedure(session: SnowflakeConnection, fqn: FQN):
    # SHOW PROCEDURES IN SCHEMA {}.{}
    # FIXME: This will fail if the database doesn't exist
    show_result = execute(session, f"SHOW PROCEDURES IN SCHEMA {fqn.database}.{fqn.schema}", cacheable=True)
    sprocs = _filter_result(show_result, name=fqn.name)
    if len(sprocs) == 0:
        return None
    if len(sprocs) > 1:
        raise Exception(f"Found multiple stored procedures matching {fqn}")

    data = sprocs[0]

    identifier, returns = _parse_function_arguments(data["arguments"])
    desc_result = execute(session, f"DESC PROCEDURE {fqn.database}.{fqn.schema}.{str(identifier)}", cacheable=True)
    properties = _desc_result_to_dict(desc_result)

    owner = _fetch_owner(session, "PROCEDURE", fqn)

    return {
        "name": _quote_snowflake_identifier(data["name"]),
        "args": _parse_signature(properties["signature"]),
        "comment": data["description"],
        "execute_as": properties["execute as"],
        "external_access_integrations": data["external_access_integrations"] or None,
        "handler": properties["handler"],
        "imports": _parse_list_property(properties["imports"]) or None,
        "language": properties["language"],
        "null_handling": properties["null handling"],
        "owner": owner,
        "packages": _parse_packages(properties["packages"]),
        "returns": returns,
        "runtime_version": properties["runtime_version"],
        "secure": data["is_secure"] == "Y",
        "as_": properties["body"],
    }


def fetch_role(session: SnowflakeConnection, fqn: FQN):
    roles = _show_resources(session, "ROLES", fqn)

    if len(roles) == 0:
        return None
    if len(roles) > 1:
        raise Exception(f"Found multiple roles matching {fqn}")

    data = roles[0]

    return {
        "name": _quote_snowflake_identifier(data["name"]),
        "comment": data["comment"] or None,
        "owner": _get_owner_identifier(data),
    }


def fetch_role_grant(session: SnowflakeConnection, fqn: FQN, use_account_usage: bool = False):
    """
    Fetch a role grant (role granted to another role or user).

    Automatically uses ACCOUNT_USAGE cache when it's been populated to avoid
    SHOW GRANTS OF ROLE commands. Falls back to SHOW GRANTS OF ROLE if grant
    not found in cache (to handle latency).
    """
    subject, grantee = fqn.params.copy().popitem()
    subject = ResourceName(subject)
    grantee = ResourceName(grantee)
    role_name = str(fqn.name).upper()
    grantee_upper = str(grantee).upper()

    # Automatically use ACCOUNT_USAGE cache if it's been populated
    session_id = id(session)

    # For role-to-role grants, check GRANTS_TO_ROLES cache
    if str(subject).upper() == "ROLE" and session_id in _ACCOUNT_USAGE_GRANTS_CACHE:
        for grant in _ACCOUNT_USAGE_GRANTS_CACHE[session_id]:
            if (
                grant["privilege"] == "USAGE"
                and grant["granted_on"] == "ROLE"
                and grant["name"].upper() == role_name
                and grant["grantee_name"].upper() == grantee_upper
                and grant["granted_to"] == "ROLE"
            ):
                return {
                    "role": fqn.name,
                    "to_role": _quote_snowflake_identifier(grant["grantee_name"]),
                }
        # Not found in cache - will fall through to SHOW GRANTS fallback
        logger.debug(f"Role grant {fqn.name} to role {grantee} not found in ACCOUNT_USAGE cache, trying SHOW GRANTS")

    # For role-to-user grants, check GRANTS_TO_USERS cache
    if str(subject).upper() == "USER" and session_id in _ACCOUNT_USAGE_USER_GRANTS_CACHE:
        for grant in _ACCOUNT_USAGE_USER_GRANTS_CACHE[session_id]:
            if grant["role"].upper() == role_name and grant["grantee_name"].upper() == grantee_upper:
                return {
                    "role": fqn.name,
                    "to_user": _quote_snowflake_identifier(grant["grantee_name"]),
                }
        # Not found in cache - will fall through to SHOW GRANTS fallback
        logger.debug(f"Role grant {fqn.name} to user {grantee} not found in ACCOUNT_USAGE cache, trying SHOW GRANTS")

    # Fall back to SHOW GRANTS OF ROLE (either cache not available or grant not found in cache)
    try:
        show_result = execute(session, f"SHOW GRANTS OF ROLE {fqn.name}", cacheable=True)
    except ProgrammingError as err:
        if err.errno == DOES_NOT_EXIST_ERR:
            return None
        raise

    if len(show_result) == 0:
        return None

    for data in show_result:
        if (
            resource_name_from_snowflake_metadata(data["granted_to"]) == subject
            and resource_name_from_snowflake_metadata(data["grantee_name"]) == grantee
        ):
            if data["granted_to"] == "ROLE":
                return {
                    "role": fqn.name,
                    "to_role": _quote_snowflake_identifier(data["grantee_name"]),
                    # "owner": data["granted_by"],
                }
            elif data["granted_to"] == "USER":
                return {
                    "role": fqn.name,
                    "to_user": _quote_snowflake_identifier(data["grantee_name"]),
                    # "owner": data["granted_by"],
                }
            else:
                raise Exception(f"Unexpected role grant for role {fqn.name}")

    return None


def fetch_scanner_package(session: SnowflakeConnection, fqn: FQN):
    scanner_packages = execute(
        session,
        f"select * from snowflake.trust_center.scanner_packages where ID = '{fqn.name}' and STATE = 'TRUE'",
        cacheable=True,
    )
    if len(scanner_packages) == 0:
        return None
    if len(scanner_packages) > 1:
        raise Exception(f"Found multiple scanner packages matching {fqn}")

    data = scanner_packages[0]

    return {
        "name": _quote_snowflake_identifier(data["ID"]),
        "enabled": data["STATE"] == "TRUE",
        "schedule": data["SCHEDULE"][11:],
    }


def fetch_schema(session: SnowflakeConnection, fqn: FQN, include_params: bool = True):
    if fqn.database is None:
        raise Exception(f"Schema {fqn} is missing a database name")
    try:
        show_result = _show_resources(session, "SCHEMAS", fqn)
    except ProgrammingError:
        return None

    if len(show_result) == 0:
        return None
    if len(show_result) > 1:
        raise Exception(f"Found multiple schemas matching {fqn}")

    data = show_result[0]

    options = options_result_to_list(data["options"])

    # Only fetch parameters if needed (expensive SHOW PARAMETERS query)
    if include_params:
        params = _show_resource_parameters(session, "SCHEMA", fqn)
        max_data_extension = params.get("max_data_extension_time_in_days")
        default_ddl_collation = params["default_ddl_collation"]
    else:
        max_data_extension = None
        default_ddl_collation = None

    return {
        "name": _quote_snowflake_identifier(data["name"]),
        "transient": "TRANSIENT" in options,
        "owner": _get_owner_identifier(data),
        "managed_access": "MANAGED ACCESS" in options,
        "data_retention_time_in_days": int(data["retention_time"]),
        "max_data_extension_time_in_days": max_data_extension,
        "default_ddl_collation": default_ddl_collation,
        "comment": data["comment"] or None,
    }


def fetch_git_repository(session: SnowflakeConnection, fqn: FQN):
    show_result = _show_resources(session, "GIT REPOSITORIES", fqn)
    if len(show_result) == 0:
        return None
    if len(show_result) > 1:
        raise Exception(f"Found multiple git repositories matching {fqn}")
    data = show_result[0]
    return {
        "name": _quote_snowflake_identifier(data["name"]),
        "origin": data["origin"],
        "api_integration": data["api_integration"],
        "git_credentials": data.get("git_credentials") or None,
        "comment": data["comment"] or None,
        "owner": _get_owner_identifier(data),
    }


def fetch_secret(session: SnowflakeConnection, fqn: FQN):
    show_result = _show_resources(session, "SECRETS", fqn)
    if len(show_result) == 0:
        return None
    if len(show_result) > 1:
        raise Exception(f"Found multiple secrets matching {fqn}")
    data = show_result[0]
    desc_result = execute(session, f"DESC SECRET {fqn}")
    properties = desc_result[0]
    if data["secret_type"] == "PASSWORD":
        return {
            "name": _quote_snowflake_identifier(data["name"]),
            "secret_type": data["secret_type"],
            "username": properties["username"],
            "comment": data["comment"] or None,
            "owner": _get_owner_identifier(data),
        }
    elif data["secret_type"] == "GENERIC_STRING":
        return {
            "name": _quote_snowflake_identifier(data["name"]),
            "secret_type": data["secret_type"],
            "comment": data["comment"] or None,
            "owner": _get_owner_identifier(data),
        }
    elif data["secret_type"] == "OAUTH2":
        return {
            "name": _quote_snowflake_identifier(data["name"]),
            "api_authentication": properties["integration_name"],
            "secret_type": data["secret_type"],
            "oauth_scopes": data["oauth_scopes"],
            "oauth_refresh_token_expiry_time": _convert_to_gmt(properties["oauth_refresh_token_expiry_time"]),
            "comment": data["comment"] or None,
            "owner": _get_owner_identifier(data),
        }
    else:
        raise NotImplementedError(f"Unsupported secret type {data['secret_type']}")


def fetch_security_integration(session: SnowflakeConnection, fqn: FQN):
    show_result = execute(session, "SHOW SECURITY INTEGRATIONS", cacheable=True)

    show_result = _filter_result(show_result, name=fqn.name)

    if len(show_result) == 0:
        return None
    if len(show_result) > 1:
        raise Exception(f"Found multiple security integrations matching {fqn}")

    data = show_result[0]
    desc_result = execute(session, f"DESC SECURITY INTEGRATION {fqn.name}")
    properties = _desc_type2_result_to_dict(desc_result, lower_properties=True)

    owner = _fetch_owner(session, "INTEGRATION", fqn)

    if data["type"] == "API_AUTHENTICATION":
        return {
            "name": _quote_snowflake_identifier(data["name"]),
            "type": data["type"],
            "auth_type": properties["auth_type"],
            "enabled": data["enabled"] == "true",
            "oauth_token_endpoint": properties["oauth_token_endpoint"],
            "oauth_client_auth_method": properties["oauth_client_auth_method"],
            "oauth_client_id": properties["oauth_client_id"],
            "oauth_grant": properties["oauth_grant"],
            "oauth_access_token_validity": int(properties["oauth_access_token_validity"]),
            "oauth_allowed_scopes": _parse_list_property(properties["oauth_allowed_scopes"]),
            "comment": data["comment"] or None,
            "owner": owner,
        }

    elif data["type"].startswith("OAUTH"):
        type_, oauth_client = data["type"].split(" - ")
        if oauth_client == "SNOWSERVICES_INGRESS":
            return {
                "name": _quote_snowflake_identifier(data["name"]),
                "type": type_,
                "oauth_client": oauth_client,
                "enabled": data["enabled"] == "true",
                "owner": owner,
            }
        elif oauth_client == "CUSTOM":
            # Canonicalize role names the same way the spec does (_canonicalize_role_name)
            # so a quoted, case-sensitive role compares equal on both sides.
            pre_authorized_roles_list = properties.get("pre_authorized_roles_list") or None
            if pre_authorized_roles_list:
                pre_authorized_roles_list = sorted(_canonicalize_role_name(role) for role in pre_authorized_roles_list)
            blocked_roles_list = {
                _canonicalize_role_name(role) for role in properties.get("blocked_roles_list") or []
            } - set(ALWAYS_BLOCKED_OAUTH_ROLES)
            oauth_refresh_token_validity = properties.get("oauth_refresh_token_validity")
            if oauth_refresh_token_validity is not None:
                oauth_refresh_token_validity = int(oauth_refresh_token_validity)
            return {
                "name": _quote_snowflake_identifier(data["name"]),
                "type": type_,
                "oauth_client": oauth_client,
                "enabled": data["enabled"] == "true",
                "oauth_client_type": properties.get("oauth_client_type"),
                "oauth_redirect_uri": properties.get("oauth_redirect_uri"),
                "oauth_allow_non_tls_redirect_uri": properties.get("oauth_allow_non_tls_redirect_uri"),
                "oauth_issue_refresh_tokens": properties.get("oauth_issue_refresh_tokens"),
                "oauth_refresh_token_validity": oauth_refresh_token_validity,
                "oauth_single_use_refresh_tokens_required": properties.get("oauth_single_use_refresh_tokens_required"),
                "oauth_use_secondary_roles": properties.get("oauth_use_secondary_roles"),
                "oauth_any_role_mode": properties.get("oauth_any_role_mode"),
                "oauth_enforce_pkce": properties.get("oauth_enforce_pkce"),
                # oauth_enable_role_selection is CREATE-only (DESC never returns it); it is
                # marked unfetchable on the spec, so it is intentionally not read back here.
                "network_policy": properties.get("network_policy"),
                "pre_authorized_roles_list": pre_authorized_roles_list,
                "blocked_roles_list": sorted(blocked_roles_list) or None,
                "comment": data["comment"] or None,
                "owner": owner,
            }
        elif oauth_client in ("LOOKER", "TABLEAU_DESKTOP", "TABLEAU_SERVER"):
            # Partner OAuth is modeled (SnowflakePartnerOAuthSecurityIntegration) and
            # declarable, but has no fetch branch. Returning None would make a declared
            # partner integration look absent and plan a spurious CREATE on every apply, so
            # fail loudly: a declared resource that genuinely can't be read back is an error.
            raise Exception(
                f"snowcap cannot read back partner OAuth integration {fqn.name!r} "
                f"(oauth_client={oauth_client}): fetch is not implemented for partner OAuth"
            )
    # A security integration type snowcap does not model (e.g. SAML2, SCIM, EXTERNAL_OAUTH)
    # must not break list/export just because the account holds one. Skip it with a warning
    # rather than raising, so fetching one unmodeled type doesn't abort the whole run.
    logger.warning(f"Skipping unsupported security integration type {data['type']!r} for {fqn.name}")
    return None


def fetch_sequence(session: SnowflakeConnection, fqn: FQN):
    show_result = execute(session, f"SHOW SEQUENCES LIKE '{fqn.name}' IN SCHEMA {fqn.database}.{fqn.schema}")
    if len(show_result) == 0:
        return None
    if len(show_result) > 1:
        raise Exception(f"Found multiple sequences matching {fqn}")

    data = show_result[0]

    return {
        "name": _quote_snowflake_identifier(data["name"]),
        "owner": _get_owner_identifier(data),
        "start": data["next_value"],
        "increment": data["interval"],
        "comment": data["comment"] or None,
    }


def fetch_service(session: SnowflakeConnection, fqn: FQN):
    show_result = execute(
        session, f"SHOW SERVICES LIKE '{fqn.name}' IN SCHEMA {fqn.database}.{fqn.schema}", cacheable=True
    )

    if len(show_result) == 0:
        return None
    if len(show_result) > 1:
        raise Exception(f"Found multiple services matching {fqn}")

    data = show_result[0]

    return {
        "name": fqn.name,
        "compute_pool": data["compute_pool"],
        "external_access_integrations": None,
        "auto_resume": data["auto_resume"] == "true",
        "min_instances": data["min_instances"],
        "max_instances": data["max_instances"],
        "query_warehouse": data["query_warehouse"],
        "comment": data["comment"] or None,
        "owner": _get_owner_identifier(data),
    }


def fetch_share(session: SnowflakeConnection, fqn: FQN):
    show_result = execute(session, f"SHOW SHARES LIKE '{fqn.name}'")
    shares = _filter_result(show_result, kind="OUTBOUND")

    if len(shares) == 0:
        return None
    if len(shares) > 1:
        raise Exception(f"Found multiple shares matching {fqn}")

    data = shares[0]
    return {
        "name": _quote_snowflake_identifier(data["name"]),
        "owner": _get_owner_identifier(data),
        "comment": data["comment"] or None,
    }


def fetch_shared_database(session: SnowflakeConnection, fqn: FQN):
    show_result = execute(session, "SELECT SYSTEM$SHOW_IMPORTED_DATABASES()", cacheable=True)
    show_result = json.loads(show_result[0]["SYSTEM$SHOW_IMPORTED_DATABASES()"])

    shares = _filter_result(show_result, name=fqn.name)

    if len(shares) == 0:
        return None
    if len(shares) > 1:
        raise Exception(f"Found multiple shares matching {fqn}")

    data = shares[0]
    # owner is deliberately not read from SYSTEM$SHOW_IMPORTED_DATABASES: its owner output is
    # undocumented, and ownership of an imported database cannot change anyway (Snowflake
    # prevents GRANT OWNERSHIP on it). The spec pins owner to ACCOUNTADMIN and marks it
    # non-fetchable, so report the pinned value; it is still used to pick the execution role
    # for drops.
    return {
        "name": _quote_snowflake_identifier(data["name"]),
        "from_share": data["origin"],
        "owner": "ACCOUNTADMIN",
    }


def fetch_stage(session: SnowflakeConnection, fqn: FQN):
    show_result = _show_resources(session, "STAGES", fqn)
    stages = _filter_result(show_result, name=fqn.name)

    if len(stages) == 0:
        return None
    if len(stages) > 1:
        raise Exception(f"Found multiple stages matching {fqn}")

    data = stages[0]
    # desc_result = execute(session, f"DESC STAGE {fqn}")
    # properties = _desc_type3_result_to_dict(desc_result, lower_properties=True)

    if data["type"] == "EXTERNAL":
        return {
            "name": _quote_snowflake_identifier(data["name"]),
            "url": data["url"],
            "owner": _get_owner_identifier(data),
            "type": data["type"],
            "storage_integration": data["storage_integration"],
            "directory": {"enable": data["directory_enabled"] == "Y"},
            "comment": data["comment"] or None,
        }
    elif data["type"] in ("INTERNAL", "INTERNAL NO CSE"):
        return {
            "name": _quote_snowflake_identifier(data["name"]),
            "owner": _get_owner_identifier(data),
            "type": "INTERNAL",
            "directory": {"enable": data["directory_enabled"] == "Y"},
            "comment": data["comment"] or None,
        }
    else:
        raise Exception(f"Unsupported stage type {data['type']}")


def fetch_storage_integration(session: SnowflakeConnection, fqn: FQN):
    show_result = execute(session, "SHOW INTEGRATIONS")
    integrations = _filter_result(show_result, name=fqn.name, category="STORAGE")

    if len(integrations) == 0:
        return None
    if len(integrations) > 1:
        raise Exception(f"Found multiple storage integrations matching {fqn}")

    data = integrations[0]

    desc_result = execute(session, f"DESC INTEGRATION {fqn.name}")
    properties = _desc_type2_result_to_dict(desc_result, lower_properties=True)

    owner = _fetch_owner(session, "INTEGRATION", fqn)

    if properties["storage_provider"] == "S3":
        return {
            "name": _quote_snowflake_identifier(data["name"]),
            "type": data["type"],
            "enabled": data["enabled"] == "true",
            "comment": data["comment"] or None,
            "owner": owner,
            "storage_provider": properties["storage_provider"],
            "storage_aws_role_arn": properties.get("storage_aws_role_arn"),
            "storage_allowed_locations": properties.get("storage_allowed_locations") or None,
            "storage_blocked_locations": properties.get("storage_blocked_locations") or None,
            "storage_aws_object_acl": properties.get("storage_aws_object_acl"),
        }
    elif properties["storage_provider"] == "GCS":
        return {
            "name": _quote_snowflake_identifier(data["name"]),
            "type": data["type"],
            "enabled": data["enabled"] == "true",
            "comment": data["comment"] or None,
            "owner": owner,
            "storage_provider": properties["storage_provider"],
            "storage_allowed_locations": properties.get("storage_allowed_locations") or None,
            "storage_blocked_locations": properties.get("storage_blocked_locations") or None,
        }
    elif properties["storage_provider"] == "AZURE":
        return {
            "name": _quote_snowflake_identifier(data["name"]),
            "type": data["type"],
            "enabled": data["enabled"] == "true",
            "comment": data["comment"] or None,
            "owner": owner,
            "storage_provider": properties["storage_provider"],
            "storage_allowed_locations": properties.get("storage_allowed_locations") or None,
            "azure_tenant_id": properties["azure_tenant_id"],
        }
    else:
        raise Exception(f"Unsupported storage provider {properties['storage_provider']}")


def fetch_stream(session: SnowflakeConnection, fqn: FQN):
    show_result = execute(session, "SHOW STREAMS IN ACCOUNT", cacheable=True)

    streams = _filter_result(show_result, name=fqn.name, database_name=fqn.database, schema_name=fqn.schema)

    if len(streams) == 0:
        return None
    if len(streams) > 1:
        raise Exception(f"Found multiple streams matching {fqn}")

    data = streams[0]
    if data["source_type"] == "Table":
        return {
            "name": _quote_snowflake_identifier(data["name"]),
            "comment": data["comment"] or None,
            "append_only": data["mode"] == "APPEND_ONLY",
            "on_table": data["table_name"],
            "owner": _get_owner_identifier(data),
        }
    elif data["source_type"] == "View":
        return {
            "name": _quote_snowflake_identifier(data["name"]),
            "comment": data["comment"] or None,
            "append_only": data["mode"] == "APPEND_ONLY",
            "on_view": data["table_name"],
            "owner": _get_owner_identifier(data),
        }
    elif data["source_type"] == "Dynamic Table":
        return {
            "name": _quote_snowflake_identifier(data["name"]),
            "comment": data["comment"] or None,
            "append_only": data["mode"] == "APPEND_ONLY",
            "on_dynamic_table": data["table_name"],
            "owner": _get_owner_identifier(data),
        }
    elif data["source_type"] == "Stage":
        # Snowflake only returns the stage name without the fully qualified path.
        # We need to construct it from the stream's database/schema.
        stage_name = data["table_name"]
        if "." not in stage_name:
            stage_name = f"{data['database_name']}.{data['schema_name']}.{stage_name}"
        return {
            "name": _quote_snowflake_identifier(data["name"]),
            "on_stage": stage_name,
            "owner": _get_owner_identifier(data),
            "comment": data["comment"] or None,
        }
    else:
        raise NotImplementedError(f"Unsupported stream source type {data['source_type']}")


def fetch_streamlit(session: SnowflakeConnection, fqn: FQN):
    streamlits = _show_resources(session, "STREAMLITS", fqn)
    if len(streamlits) == 0:
        return None
    if len(streamlits) > 1:
        raise Exception(f"Found multiple streamlits matching {fqn}")

    data = streamlits[0]
    desc_result = execute(session, f"DESC STREAMLIT {fqn}", cacheable=True)
    properties = desc_result[0] if desc_result else {}
    return {
        "name": data["name"],
        # from_ is omitted (like fetch_notebook): DESC STREAMLIT returns
        # root_location as a fully-qualified, uppercased stage path, which
        # never matches the declared from_ (e.g. "@my_stage") and would show
        # perpetual drift. The spec marks from_ non-fetchable instead.
        # version is only settable for repo-based apps and isn't returned by
        # DESC STREAMLIT in a comparable form, so it's always None here —
        # repo-based apps (from_="https://...", version="main") may drift on
        # version. Known limitation.
        "version": None,
        # Snowflake's default main_file is streamlit_app.py; map it to None so
        # an omitted field doesn't drift (same as fetch_notebook).
        "main_file": None if properties.get("main_file") == "streamlit_app.py" else properties.get("main_file"),
        "title": properties.get("title") or None,
        "query_warehouse": data.get("query_warehouse") or None,
        "comment": data.get("comment") or None,
        "owner": _get_owner_identifier(data),
    }


def fetch_tag(session: SnowflakeConnection, fqn: FQN):
    try:
        show_result = execute(session, "SHOW TAGS IN ACCOUNT", cacheable=True)
    except ProgrammingError as err:
        if err.errno == UNSUPPORTED_FEATURE:
            return None
        raise
    tags = _filter_result(show_result, name=fqn.name, database_name=fqn.database, schema_name=fqn.schema)
    if len(tags) == 0:
        return None
    if len(tags) > 1:
        raise Exception(f"Found multiple tags matching {fqn}")
    data = tags[0]
    return {
        "name": _quote_snowflake_identifier(data["name"]),
        "owner": _get_owner_identifier(data),
        "comment": data["comment"] or None,
        "allowed_values": json.loads(data["allowed_values"]) if data["allowed_values"] else None,
        # Snowflake reports the literal string 'NONE' for tags without propagation settings
        "propagate": None if data.get("propagate") in (None, "", "NONE") else data["propagate"],
        "on_conflict": None if data.get("on_conflict") in (None, "", "NONE") else data["on_conflict"],
    }


def fetch_task(session: SnowflakeConnection, fqn: FQN, include_params: bool = True):
    show_result = _show_resources(session, "TASKS", fqn)

    if len(show_result) == 0:
        return None
    if len(show_result) > 1:
        raise Exception(f"Found multiple tasks matching {fqn}")

    data = show_result[0]
    task_details_result = execute(session, f"DESC TASK {fqn.database}.{fqn.schema}.{fqn.name}", cacheable=True)
    if len(task_details_result) == 0:
        raise Exception(f"Failed to fetch task details for {fqn}")
    task_details = task_details_result[0]

    # Only fetch parameters if needed (expensive query)
    if include_params:
        show_params_result = execute(session, f"SHOW PARAMETERS FOR TASK {fqn}")
        params = params_result_to_dict(show_params_result)
    else:
        params = {}

    error_integration = None
    if data["error_integration"] != "null":
        error_integration = _quote_snowflake_identifier(data["error_integration"])

    success_integration = None
    if data.get("success_integration") and data["success_integration"] != "null":
        success_integration = _quote_snowflake_identifier(data["success_integration"])

    task_relations = json.loads(task_details["task_relations"])
    after = task_relations["Predecessors"]

    suspend_task_after_num_failures = None
    if len(after) == 0:
        suspend_task_after_num_failures = params.get("suspend_task_after_num_failures", None)

    user_task_managed_initial_warehouse_size = None
    serverless_task_min_statement_size = None
    serverless_task_max_statement_size = None
    if not data["warehouse"]:
        user_task_managed_initial_warehouse_size = params.get("user_task_managed_initial_warehouse_size", None)
        serverless_task_min_statement_size = params.get("serverless_task_min_statement_size", None)
        serverless_task_max_statement_size = params.get("serverless_task_max_statement_size", None)
    return {
        "name": _quote_snowflake_identifier(data["name"]),
        "warehouse": data["warehouse"],
        "schedule": data["schedule"],
        "config": data["config"],
        "allow_overlapping_execution": data["allow_overlapping_execution"] == "true",
        "user_task_managed_initial_warehouse_size": user_task_managed_initial_warehouse_size,
        "user_task_timeout_ms": params.get("user_task_timeout_ms", None),
        "suspend_task_after_num_failures": suspend_task_after_num_failures,
        "error_integration": error_integration,
        "success_integration": success_integration,
        "serverless_task_min_statement_size": serverless_task_min_statement_size,
        "serverless_task_max_statement_size": serverless_task_max_statement_size,
        "task_auto_retry_attempts": params.get("task_auto_retry_attempts", None),
        "user_task_minimum_trigger_interval_in_seconds": params.get(
            "user_task_minimum_trigger_interval_in_seconds", None
        ),
        "target_completion_interval": _normalize_snowflake_optional(data.get("target_completion_interval")),
        "state": str(data["state"]).upper(),
        "owner": _get_owner_identifier(data),
        "comment": task_details["comment"] or None,
        "after": after or None,
        # SHOW TASKS reports the WHEN clause in the 'condition' column. Without reading it back,
        # a task with a WHEN never round-trips and snowcap re-plans "MODIFY WHEN ..." every apply.
        "when": data["condition"] or None,
        "as_": task_details["definition"],
    }


def fetch_replication_group(session: SnowflakeConnection, fqn: FQN):
    show_result = execute(session, f"SHOW REPLICATION GROUPS LIKE '{fqn.name}'", cacheable=True)

    replication_groups = _filter_result(show_result, is_primary="true")
    if len(replication_groups) == 0:
        return None
    if len(replication_groups) > 1:
        raise Exception(f"Found multiple replication groups matching {fqn}")

    data = replication_groups[0]
    show_databases_result = execute(session, f"SHOW DATABASES IN REPLICATION GROUP {fqn.name}")
    databases = [row["name"] for row in show_databases_result]
    return {
        "name": _quote_snowflake_identifier(data["name"]),
        "object_types": data["object_types"].split(","),
        "allowed_integration_types": (
            None if data["allowed_integration_types"] == "" else data["allowed_integration_types"].split(",")
        ),
        "allowed_accounts": None if data["allowed_accounts"] == "" else data["allowed_accounts"].split(","),
        "allowed_databases": databases,
        "replication_schedule": data["replication_schedule"],
        "owner": _get_owner_identifier(data),
    }


def fetch_resource_monitor(session: SnowflakeConnection, fqn: FQN):
    show_result = execute(session, f"SHOW RESOURCE MONITORS LIKE '{fqn.name}'")
    resource_monitors = _filter_result(show_result)
    if len(resource_monitors) == 0:
        return None
    if len(resource_monitors) > 1:
        raise Exception(f"Found multiple resource monitors matching {fqn}")
    data = resource_monitors[0]
    return {
        "name": _quote_snowflake_identifier(data["name"]),
        "owner": _get_owner_identifier(data),
        "credit_quota": int(float(data["credit_quota"])) if data["credit_quota"] else None,
        "frequency": data["frequency"],
        "start_timestamp": _convert_to_gmt(data["start_time"], "%Y-%m-%d %H:%M"),
        "end_timestamp": _convert_to_gmt(data["end_time"], "%Y-%m-%d %H:%M"),
        "notify_users": data["notify_users"] or None,
    }


def fetch_row_access_policy(session: SnowflakeConnection, fqn: FQN):
    policies = _show_resources(session, "ROW ACCESS POLICIES", fqn)
    if len(policies) == 0:
        return None
    if len(policies) > 1:
        raise Exception(f"Found multiple row access policies matching {fqn}")

    data = policies[0]
    desc_result = execute(session, f"DESC ROW ACCESS POLICY {fqn}", cacheable=True)
    properties = desc_result[0]

    return {
        "name": data["name"],
        "owner": _get_owner_identifier(data),
        "args": _parse_signature(properties["signature"]),
        "returns": "BOOLEAN",  # Row access policies always return BOOLEAN
        "body": properties["body"],
        "comment": data["comment"] or None,
    }


def fetch_resource_tags(session: SnowflakeConnection, resource_type: ResourceType, fqn: FQN):
    """
    +----------------------+------------+-------------+-----------+--------+----------------------+---------------+-------------+--------+-------------+
    |     TAG_DATABASE     | TAG_SCHEMA |  TAG_NAME   | TAG_VALUE | LEVEL  |   OBJECT_DATABASE    | OBJECT_SCHEMA | OBJECT_NAME | DOMAIN | COLUMN_NAME |
    +----------------------+------------+-------------+-----------+--------+----------------------+---------------+-------------+--------+-------------+
    | SNOWCAP                | SOMESCH    | TASTY_TREAT | muffin    | SCHEMA | TEST_DB_RUN_13287C56 |               | SOMESCH     | SCHEMA |             |
    | TEST_DB_RUN_13287C56 | PUBLIC     | TRASH       | true      | SCHEMA | TEST_DB_RUN_13287C56 |               | SOMESCH     | SCHEMA |             |
    +----------------------+------------+-------------+-----------+--------+----------------------+---------------+-------------+--------+-------------+

    """

    database = f"{fqn.database}." if fqn.database else ""

    try:
        tag_refs = execute(
            session,
            f"""
                SELECT *
                FROM table({database}information_schema.tag_references(
                    '{fqn}', '{str(resource_type)}'
                ))""",
        )
    except ProgrammingError as err:
        if err.errno == UNSUPPORTED_FEATURE:
            return None
        raise

    if len(tag_refs) == 0:
        return None

    tag_map = {}
    for tag_ref in tag_refs:
        in_same_database = tag_ref["TAG_DATABASE"] == tag_ref["OBJECT_DATABASE"]
        in_same_schema = tag_ref["TAG_SCHEMA"] == tag_ref["OBJECT_SCHEMA"]
        tag_in_public_schema = tag_ref["TAG_SCHEMA"] == "PUBLIC"

        if in_same_database and (in_same_schema or tag_in_public_schema):
            tag_name = tag_ref["TAG_NAME"]
        else:
            tag_name = f"{tag_ref['TAG_DATABASE']}.{tag_ref['TAG_SCHEMA']}.{tag_ref['TAG_NAME']}"
        tag_map[tag_name] = tag_ref["TAG_VALUE"]
    return tag_map


def fetch_table(session: SnowflakeConnection, fqn: FQN, include_params: bool = True):
    show_result = execute(session, "SHOW TABLES IN ACCOUNT", cacheable=True)

    tables = _filter_result(
        show_result,
        name=fqn.name,
        database_name=fqn.database,
        schema_name=fqn.schema,
    )

    if len(tables) == 0:
        return None
    if len(tables) > 1:
        raise Exception(f"Found multiple tables matching {fqn}")

    columns = fetch_columns(session, "TABLE", fqn)

    data = tables[0]

    # Only fetch parameters if needed (expensive query)
    if include_params:
        show_params_result = execute(session, f"SHOW PARAMETERS FOR TABLE {fqn}")
        params = params_result_to_dict(show_params_result)
    else:
        params = {}

    return {
        "name": _quote_snowflake_identifier(data["name"]),
        "columns": columns,
        "cluster_by": _parse_cluster_keys(data["cluster_by"]),
        "transient": data["kind"] == "TRANSIENT",
        "owner": _get_owner_identifier(data),
        "comment": data["comment"] or None,
        "enable_schema_evolution": data["enable_schema_evolution"] == "Y",
        # "data_retention_time_in_days": int(data["retention_time"]),
        # "max_data_extension_time_in_days": params.get("max_data_extension_time_in_days", None),
        "default_ddl_collation": params.get("default_ddl_collation", None),
        "change_tracking": data["change_tracking"] == "ON",
    }


def fetch_tag_reference(session: SnowflakeConnection, fqn: FQN):
    object_domain = fqn.params["domain"]
    # TODO: this is a hacky fix
    name = str(fqn).split("?")[0]
    resource_fqn = parse_FQN(name, is_db_scoped=(object_domain == "SCHEMA"))

    tag_db = resource_fqn.database if resource_fqn.database else resource_fqn

    # Another hacky fix
    if str(resource_fqn) == "DATABASE":
        resource_fqn = '"DATABASE"'  # type: ignore[assignment]

    try:
        tag_refs = execute(
            session,
            f"""
                SELECT *
                FROM table({tag_db}.information_schema.tag_references(
                    '{resource_fqn}', '{object_domain}'
                ))""",
        )
    except ProgrammingError as err:
        if err.errno in (INVALID_IDENTIFIER, UNSUPPORTED_FEATURE):
            return None
        raise

    if len(tag_refs) == 0:
        return None

    tag_map = {}
    for tag_ref in tag_refs:
        tag_name = f"{tag_ref['TAG_DATABASE']}.{tag_ref['TAG_SCHEMA']}.{tag_ref['TAG_NAME']}"
        tag_map[tag_name] = tag_ref["TAG_VALUE"]
    return {
        "object_name": name,
        "object_domain": object_domain,
        "tags": tag_map,
    }


def fetch_user(
    session: SnowflakeConnection, fqn: FQN, include_params: bool = True, existence_only: bool = False
) -> Optional[dict]:
    show_result = _show_users(session)
    users = _filter_result(show_result, name=fqn.name)

    if len(users) == 0:
        return None
    if len(users) > 1:
        raise Exception(f"Found multiple users matching {fqn}")

    data = users[0]

    # For existence checks (reference validation), skip expensive DESC USER
    if existence_only:
        return {"name": _quote_snowflake_identifier(data["name"]), "owner": ""}

    desc_result = execute(session, f"DESC USER {fqn}")
    properties = _desc_result_to_dict(desc_result, lower_properties=True)

    # Only fetch parameters if needed (expensive SHOW PARAMETERS query)
    if include_params:
        show_params_result = execute(session, f"SHOW PARAMETERS FOR USER {fqn}")
        params = params_result_to_dict(show_params_result)
        network_policy = params["network_policy"]
    else:
        network_policy = None

    user_type = properties["type"].upper()

    display_name = None
    login_name = None
    must_change_password = None
    if user_type != "SERVICE":
        display_name = data["display_name"]
        login_name = data["login_name"]
        must_change_password = data["must_change_password"] == "true"

    rsa_public_key = properties["rsa_public_key"] if properties["rsa_public_key"] != "null" else None
    # The second legacy key is what a key rotation on the legacy properties runs through.
    # Without reading it back, a config that sets it re-applies it on every plan.
    rsa_public_key_2 = properties.get("rsa_public_key_2")
    rsa_public_key_2 = rsa_public_key_2 if rsa_public_key_2 not in (None, "null") else None
    middle_name = properties["middle_name"] if properties["middle_name"] != "null" else None

    default_secondary_roles = json.loads(data["default_secondary_roles"]) if data["default_secondary_roles"] else None

    return {
        "name": _quote_snowflake_identifier(data["name"]),
        "login_name": login_name,
        "display_name": display_name,
        "first_name": data["first_name"] or None,
        "middle_name": middle_name,
        "last_name": data["last_name"] or None,
        "email": data["email"] or None,
        "comment": data["comment"] or None,
        "disabled": data["disabled"] == "true",
        "must_change_password": must_change_password,
        "default_warehouse": data["default_warehouse"] or None,
        "default_namespace": data["default_namespace"] or None,
        "default_role": data["default_role"] or None,
        "default_secondary_roles": default_secondary_roles,
        "type": user_type,
        "rsa_public_key": rsa_public_key,
        "rsa_public_key_2": rsa_public_key_2,
        "network_policy": network_policy,
        "owner": _get_owner_identifier(data),
    }


def _show_user_key_pairs_sql(user: ResourceName) -> str:
    # The sweep issues this per user and a fetch issues it again for one of them. Same
    # text means the execution cache serves the second from the first.
    return f"SHOW USER KEY PAIRS FOR USER {user}"


def _show_user_key_pairs(session: SnowflakeConnection, user: ResourceName) -> list[dict]:
    return execute(session, _show_user_key_pairs_sql(user), cacheable=True)


def _key_pair_is_declarable(row: dict) -> bool:
    """
    Whether a SHOW USER KEY PAIRS row is a key pair a config can declare.

    Two kinds of row are not: the prior key of a rotation, which lives on under a
    generated name until it expires, and the reserved PUBLIC_KEY_1 / PUBLIC_KEY_2 names
    Snowflake reports for the legacy rsa_public_key and rsa_public_key_2 user properties,
    which are managed on the user resource instead.

    A rotated-out key is identified by `rotated_to`, the column Snowflake sets, and never
    by its name. The generated name is a naming convention, not a guarantee: anyone who
    can register a key pair can name one `<anything>_ROTATED_<digits>`, and treating that
    as a tombstone would hide a live key from drift detection and from the sync sweep that
    removes what config does not declare.
    """
    if row.get("rotated_to"):
        return False
    return ResourceName(row["name"]) not in RESERVED_KEY_PAIR_NAMES


def _user_key_pair_to_dict(data: dict) -> dict:
    status = (data["status"] or "").upper()
    role_scope = data.get("role_scope")
    return {
        "name": _quote_snowflake_identifier(data["name"]),
        "user": _quote_snowflake_identifier(data["user_name"]),
        # Snowflake never returns the public key itself, so the fingerprint is what
        # snowcap compares against the fingerprint of the configured key.
        "fingerprint": normalize_fingerprint(data["fingerprint"]),
        "role_restriction": _quote_snowflake_identifier(role_scope) if role_scope else None,
        # status is ACTIVE, EXPIRED, or DISABLED. A key pair past its expiration reports
        # EXPIRED, and that isn't the disabled flag drifting -- expiration is fixed when
        # the key is registered. Snowflake reports DISABLED for a key pair that is both
        # disabled and expired, so a disabled key never reads back as enabled.
        # https://docs.snowflake.com/en/sql-reference/sql/show-user-key-pairs
        "disabled": status == "DISABLED",
        # The duration a key pair was registered with is not reported, only the absolute
        # time it expires. Whether it expires at all is comparable; the duration is not.
        "has_expiration": data.get("expires_at") is not None,
        "comment": data["comment"] or None,
    }


def fetch_user_key_pair(session: SnowflakeConnection, fqn: FQN) -> Optional[dict]:
    user = fqn.params.get("user")
    if not user:
        raise Exception(f"User key pair fqn must specify a user {fqn}")

    try:
        show_result = _show_user_key_pairs(session, ResourceName(user))
    except ProgrammingError as err:
        # No user, no key pairs. Snowflake reports the missing user rather than an empty list.
        if err.errno in (DOES_NOT_EXIST_ERR, OBJECT_DOES_NOT_EXIST_ERR):
            return None
        raise

    key_pairs = _filter_result(show_result, name=fqn.name)

    if len(key_pairs) == 0:
        return None
    if len(key_pairs) > 1:
        raise Exception(f"Found multiple user key pairs matching {fqn}")

    data = key_pairs[0]

    if not _key_pair_is_declarable(data):
        return None

    return _user_key_pair_to_dict(data)


def fetch_view(session: SnowflakeConnection, fqn: FQN):
    if fqn.schema is None:
        raise Exception(f"View fqn must have a schema {fqn}")
    try:
        views = _show_resources(session, "VIEWS", fqn)
    except ProgrammingError:
        return None

    if len(views) == 0:
        return None
    if len(views) > 1:
        raise Exception(f"Found multiple views matching {fqn}")

    data = views[0]

    if data["is_materialized"] == "true":
        return None

    columns = fetch_columns(session, "VIEW", fqn)

    return {
        "name": _quote_snowflake_identifier(data["name"]),
        "owner": _get_owner_identifier(data),
        "secure": data["is_secure"] == "true",
        "columns": columns,
        "change_tracking": data["change_tracking"] == "ON",
        "comment": data["comment"] or None,
        "as_": parse_view_ddl(data["text"]),
    }


def fetch_warehouse(session: SnowflakeConnection, fqn: FQN, include_params: bool = True):
    try:
        show_result = _show_resources(session, "WAREHOUSES", fqn)
    except ProgrammingError:
        return None

    if len(show_result) == 0:
        return None
    if len(show_result) > 1:
        raise Exception(f"Found multiple warehouses matching {fqn}")

    data = show_result[0]

    # Only fetch parameters if needed (expensive SHOW PARAMETERS query)
    if include_params:
        show_params_result = execute(session, f"SHOW PARAMETERS FOR WAREHOUSE {fqn}")
        params = params_result_to_dict(show_params_result)
        # ADAPTIVE warehouses omit max_concurrency_level from SHOW PARAMETERS entirely
        # (verified live), so read every parameter defensively.
        max_concurrency_level = params.get("max_concurrency_level")
        statement_queued_timeout = params.get("statement_queued_timeout_in_seconds")
        statement_timeout = params.get("statement_timeout_in_seconds")
    else:
        max_concurrency_level = None
        statement_queued_timeout = None
        statement_timeout = None

    resource_monitor = _normalize_snowflake_optional(data.get("resource_monitor"))
    warehouse_type = _normalize_snowflake_optional(data["type"], upper=True)
    generation = _normalize_snowflake_optional(data.get("generation"))
    if generation is not None:
        generation = str(generation)
    resource_constraint = _normalize_snowflake_optional(data.get("resource_constraint"), upper=True)
    max_query_performance_level = _normalize_snowflake_optional(data.get("max_query_performance_level"), upper=True)
    query_throughput_multiplier = _normalize_snowflake_optional(data.get("query_throughput_multiplier"))

    if warehouse_type == "STANDARD":
        if resource_constraint is None and generation in {"1", "2"}:
            resource_constraint = f"STANDARD_GEN_{generation}"
        elif generation is None and resource_constraint in {"STANDARD_GEN_1", "STANDARD_GEN_2"}:
            generation = resource_constraint[-1]

    # Enterprise edition features
    query_accel = _normalize_snowflake_optional(data.get("enable_query_acceleration"))
    if query_accel is not None:
        query_accel = str(query_accel).lower() == "true"

    # Adaptive warehouses may report ''/'null'/'ADAPTIVE' in the size column instead of a
    # WarehouseSize value; ADAPTIVE_UNSUPPORTED_FIELDS nulls warehouse_size out below regardless,
    # so this conversion just needs to not crash on those values.
    try:
        warehouse_size = str(WarehouseSize(data["size"]))
    except ValueError:
        warehouse_size = None

    warehouse_dict = {
        "name": _quote_snowflake_identifier(data["name"]),
        "owner": _get_owner_identifier(data),
        "warehouse_type": warehouse_type,
        "warehouse_size": warehouse_size,
        "generation": generation,
        "resource_constraint": resource_constraint,
        "max_query_performance_level": max_query_performance_level,
        "query_throughput_multiplier": query_throughput_multiplier,
        "auto_suspend": data["auto_suspend"],
        "auto_resume": data["auto_resume"] == "true",
        "comment": data["comment"] or None,
        "resource_monitor": resource_monitor,
        "enable_query_acceleration": query_accel,
        "query_acceleration_max_scale_factor": _normalize_snowflake_optional(
            data.get("query_acceleration_max_scale_factor", None)
        ),
        "max_cluster_count": data.get("max_cluster_count", None),
        "min_cluster_count": data.get("min_cluster_count", None),
        "scaling_policy": data.get("scaling_policy", None),
        "max_concurrency_level": max_concurrency_level,
        "statement_queued_timeout_in_seconds": statement_queued_timeout,
        "statement_timeout_in_seconds": statement_timeout,
    }

    # ADAPTIVE warehouses don't support these properties (Snowflake computes them
    # automatically); null them out here using the same field set __post_init__ validates
    # against, so fetched state matches a declared ADAPTIVE spec with no spurious drift.
    if warehouse_type == "ADAPTIVE":
        for field_name in ADAPTIVE_UNSUPPORTED_FIELDS:
            if field_name in warehouse_dict:
                warehouse_dict[field_name] = None

    return warehouse_dict


################ List functions

######## List helpers


def list_resource(session: SnowflakeConnection, resource_label: str, **kwargs) -> list[FQN]:
    func_name = f"list_{pluralize(resource_label)}"
    list_func = getattr(__this__, func_name)
    # Pass through kwargs (e.g., use_account_usage) to functions that support them (cached)
    sig = _get_cached_signature(func_name)
    supported_kwargs = {k: v for k, v in kwargs.items() if k in sig.parameters}
    return list_func(session, **supported_kwargs)


def list_account_scoped_resource(session: SnowflakeConnection, resource) -> list[FQN]:
    show_result = execute(session, f"SHOW {resource}", cacheable=True)
    resources = []
    for row in show_result:
        resources.append(FQN(name=resource_name_from_snowflake_metadata(row["name"])))
    return resources


def list_schema_scoped_resource(session: SnowflakeConnection, resource) -> list[FQN]:
    show_result = execute(session, f"SHOW {resource} IN ACCOUNT", cacheable=True)
    resources = []
    for row in show_result:
        if row["database_name"] in SYSTEM_DATABASES:
            continue
        resources.append(
            FQN(
                database=resource_name_from_snowflake_metadata(row["database_name"]),
                schema=resource_name_from_snowflake_metadata(row["schema_name"]),
                name=resource_name_from_snowflake_metadata(row["name"]),
            )
        )
    return resources


######## List functions by resource


def list_account_parameters(session: SnowflakeConnection) -> list[FQN]:
    show_result = execute(session, "SHOW PARAMETERS IN ACCOUNT", cacheable=True)
    account_parameters = []
    for row in show_result:
        # Skip system parameters and unset parameters
        if row["level"] != "ACCOUNT":
            continue
        account_parameters.append(FQN(name=ResourceName(row["key"])))
    return account_parameters


def list_alerts(session: SnowflakeConnection) -> list[FQN]:
    return list_schema_scoped_resource(session, "ALERTS")


def list_api_integrations(session: SnowflakeConnection) -> list[FQN]:
    return list_account_scoped_resource(session, "API INTEGRATIONS")


def list_authentication_policies(session: SnowflakeConnection) -> list[FQN]:
    return list_schema_scoped_resource(session, "AUTHENTICATION POLICIES")


def list_catalog_integrations(session: SnowflakeConnection) -> list[FQN]:
    return list_account_scoped_resource(session, "CATALOG INTEGRATIONS")


def list_compute_pools(session: SnowflakeConnection) -> list[FQN]:
    try:
        show_result = execute(session, "SHOW COMPUTE POOLS")
    except ProgrammingError as err:
        logger.warning(f"Error listing compute pools: {err}")
        return []
    return [FQN(name=resource_name_from_snowflake_metadata(row["name"])) for row in show_result]


def _list_databases(session: SnowflakeConnection) -> list[ResourceName]:
    show_result = execute(session, "SHOW DATABASES", cacheable=True)
    databases = []
    for row in show_result:
        # Exclude system databases like SNOWFLAKE
        if row["name"] in SYSTEM_DATABASES:
            continue
        # Exclude database shares
        if row["kind"] != "STANDARD":
            continue
        databases.append(resource_name_from_snowflake_metadata(row["name"]))
    return databases


def list_databases(session: SnowflakeConnection) -> list[FQN]:
    databases = _list_databases(session)
    return [FQN(name=database) for database in databases]


def list_database_owners(session: SnowflakeConnection) -> dict[str, str]:
    """
    Owner role of every database in the account, keyed by upper-cased name.

    Used to manage grants held by database roles, which live inside a database and cannot
    be reached with account-level authority alone. Reads the same cached SHOW DATABASES
    response _list_databases uses, so this costs no extra query.
    """
    show_result = execute(session, "SHOW DATABASES", cacheable=True)
    return {row["name"].upper(): row["owner"] for row in show_result if row.get("owner")}


def list_shared_database_names(session: SnowflakeConnection) -> set[str]:
    """
    Names of databases whose privileges come from a share rather than from grants on the
    database itself, upper-cased.

    Every kind but STANDARD qualifies. IMPORTED DATABASE is the marketplace or direct
    share; APPLICATION covers the SNOWFLAKE database, which behaves the same way and would
    be missed by testing for IMPORTED DATABASE alone.

    Two things depend on this. Privileges on them are granted with IMPORTED PRIVILEGES and
    reported back as USAGE, and they cannot be revoked one at a time; see
    lifecycle.drop_shared_database_grant. Reads the same cached SHOW DATABASES response
    _list_databases uses, so this costs no extra query.
    """
    show_result = execute(session, "SHOW DATABASES", cacheable=True)
    return {row["name"].upper() for row in show_result if row["kind"] != "STANDARD"}


def list_database_roles(session: SnowflakeConnection, database=None) -> list[FQN]:
    databases: list[ResourceName]
    if database:
        databases = [ResourceName(database)]
    else:
        databases = _list_databases(session)

    roles = []
    for database_name in databases:
        try:
            # A rare case where we need to always quote the identifier. Snowflake chokes if the database name
            # is DATABASE, but this will work if quoted
            if database_name == "DATABASE":
                database_name._quoted = True
            database_roles = execute(session, f"SHOW DATABASE ROLES IN DATABASE {database_name}", cacheable=True)
        except ProgrammingError as err:
            if err.errno == DOES_NOT_EXIST_ERR:
                continue
            raise
        for role in database_roles:
            roles.append(
                FQN(
                    name=resource_name_from_snowflake_metadata(role["name"]),
                    database=database_name,
                )
            )
    return roles


def list_database_role_grants(
    session: SnowflakeConnection, database=None, use_account_usage: bool = False
) -> list[FQN]:
    """
    List all database role grants (database role granted to roles or other database roles).

    When use_account_usage is True and ACCOUNT_USAGE access is available, uses:
    - GRANTS_TO_ROLES view for database role grants (privilege=USAGE, granted_on=DATABASE ROLE)

    Falls back to SHOW GRANTS OF DATABASE ROLE commands when ACCOUNT_USAGE is unavailable.

    Args:
        session: Snowflake connection
        database: Optional database name to filter grants for. If None, returns grants for all databases.
        use_account_usage: Whether to attempt using ACCOUNT_USAGE (default True)

    Returns:
        List of FQN objects representing database role grants, with params indicating
        whether the grantee is a 'role' or 'database_role'.
    """
    databases: list[ResourceName]
    if database:
        databases = [ResourceName(database)]
    else:
        databases = _list_databases(session)

    # Build a set of database names for filtering (uppercase for case-insensitive matching)
    database_name_set = {str(db).upper() for db in databases}

    role_grants: list[FQN] = []

    # Try ACCOUNT_USAGE if enabled and accessible
    use_au = _should_use_account_usage(session, use_account_usage)
    if use_au:
        logger.debug("Using ACCOUNT_USAGE for list_database_role_grants()")

        # Fetch all grants and filter for database role grants
        # Database role grants have privilege=USAGE and granted_on=DATABASE ROLE
        all_grants = _fetch_grants_from_account_usage(session)

        # If ACCOUNT_USAGE query succeeded, process results
        if all_grants is not None:
            for grant in all_grants:
                # Filter for database role grants (USAGE on DATABASE ROLE)
                if grant["privilege"] != "USAGE" or grant["granted_on"] != "DATABASE ROLE":
                    continue

                # The name field contains the fully qualified database role (e.g., "DB.ROLE_NAME")
                db_role_name = grant["name"]
                if "." not in db_role_name:
                    continue

                db_name, role_name = db_role_name.split(".", 1)

                # Filter by database if specified
                if db_name.upper() not in database_name_set:
                    continue

                # Determine subject based on grantee type
                subject = "role" if grant["granted_to"] == "ROLE" else "database_role"
                grantee_name = grant["grantee_name"]
                if subject == "database_role":
                    grantee_name = str(
                        _database_role_grantee_fqn(grantee_name, resource_name_from_snowflake_metadata(db_name))
                    )

                role_grants.append(
                    FQN(
                        name=resource_name_from_snowflake_metadata(role_name),
                        database=resource_name_from_snowflake_metadata(db_name),
                        params={subject: grantee_name},
                    )
                )
            # If we got results or no specific database was filtered, return
            # If specific database was filtered and we got 0 results, fall back to SHOW
            # (handles ACCOUNT_USAGE latency for newly created grants)
            if role_grants or database is None:
                return role_grants
            logger.debug("ACCOUNT_USAGE returned 0 results for specific database, falling back to SHOW")
        # Fall through to SHOW queries if ACCOUNT_USAGE failed or returned empty for filtered query

    # Fallback to SHOW GRANTS OF DATABASE ROLE commands
    logger.debug(
        "Using SHOW GRANTS OF DATABASE ROLE for list_database_role_grants() (ACCOUNT_USAGE unavailable or disabled)"
    )

    for database_name in databases:
        try:
            # A rare case where we need to always quote the identifier. Snowflake chokes if the database name
            # is DATABASE, but this will work if quoted
            if database_name == "DATABASE":
                database_name._quoted = True
            database_roles = execute(session, f"SHOW DATABASE ROLES IN DATABASE {database_name}", cacheable=True)
        except ProgrammingError as err:
            if err.errno == DOES_NOT_EXIST_ERR:
                continue
            raise
        for role in database_roles:
            show_result = execute(
                session, f"SHOW GRANTS OF DATABASE ROLE {database_name}.{role['name']}", cacheable=True
            )
            for data in show_result:
                subject = "role" if data["granted_to"] == "ROLE" else "database_role"
                db, name = data["role"].split(".")
                grantee_name = data["grantee_name"]
                if subject == "database_role":
                    grantee_name = str(
                        _database_role_grantee_fqn(grantee_name, resource_name_from_snowflake_metadata(db))
                    )
                role_grants.append(
                    FQN(
                        name=resource_name_from_snowflake_metadata(name),
                        database=resource_name_from_snowflake_metadata(db),
                        params={subject: grantee_name},
                    )
                )
    return role_grants


def list_dynamic_tables(session: SnowflakeConnection) -> list[FQN]:
    return list_schema_scoped_resource(session, "DYNAMIC TABLES")


def list_integrations(session: SnowflakeConnection) -> list[FQN]:
    """List every integration in the account (any subtype).

    Backs the generic `ResourceType.INTEGRATION` (umbrella). Concrete subtypes
    (API/CATALOG/EXTERNAL_ACCESS/NOTIFICATION/SECURITY/STORAGE) still have their
    own list_*_integrations functions for typed manifests.
    """
    show_result = execute(session, "SHOW INTEGRATIONS", cacheable=True)
    return [FQN(name=resource_name_from_snowflake_metadata(row["name"])) for row in show_result]


def list_external_access_integrations(session: SnowflakeConnection) -> list[FQN]:
    return list_account_scoped_resource(session, "EXTERNAL ACCESS INTEGRATIONS")


def list_external_volumes(session: SnowflakeConnection) -> list[FQN]:
    return list_account_scoped_resource(session, "EXTERNAL VOLUMES")


def list_file_formats(session: SnowflakeConnection) -> list[FQN]:
    return list_schema_scoped_resource(session, "FILE FORMATS")


def list_functions(session: SnowflakeConnection) -> list[FQN]:
    show_result = execute(session, "SHOW USER FUNCTIONS IN ACCOUNT", cacheable=True)
    functions = []
    for row in show_result:
        # Skip functions with empty database/schema and system databases
        if not row["catalog_name"] or not row["schema_name"]:
            continue
        if row["catalog_name"] in SYSTEM_DATABASES:
            continue
        fqn, returns = _parse_function_arguments(row["arguments"])
        fqn.database = row["catalog_name"]
        fqn.schema = row["schema_name"]
        functions.append(fqn)
    return functions


def list_grants(
    session: SnowflakeConnection,
    use_account_usage: bool = False,
    include_future_grants: bool = True,
    future_grant_roles: Optional[set] = None,
    future_grant_database_roles: Optional[set] = None,
) -> list[FQN]:
    grants: list[FQN] = []

    # Databases whose privileges come from a share. Grants on them are declared as
    # IMPORTED PRIVILEGES and reported back as USAGE; see _imported_privileges_priv.
    shared_databases = list_shared_database_names(session)

    # Get all non-system role names for processing
    # Use "SHOW ROLES IN ACCOUNT" to match _show_resources for cache consistency
    roles_result = execute(session, "SHOW ROLES IN ACCOUNT", cacheable=True)
    role_names = [
        resource_name_from_snowflake_metadata(role["name"])
        for role in roles_result
        if resource_name_from_snowflake_metadata(role["name"]) not in SYSTEM_ROLES
    ]

    # Database roles are lazily fetched only when needed:
    # - When ACCOUNT_USAGE is unavailable/disabled (for SHOW grants fallback)
    # - When fetching future grants to database roles
    database_role_fqns: Optional[list[FQN]] = None
    database_role_name_set: Optional[set[str]] = None

    def get_database_roles() -> list[FQN]:
        nonlocal database_role_fqns
        if database_role_fqns is None:
            database_role_fqns = list_database_roles(session)
        return database_role_fqns

    def get_database_role_name_set() -> set[str]:
        nonlocal database_role_name_set
        if database_role_name_set is None:
            fqns = get_database_roles()
            database_role_name_set = {f"{fqn.database}.{fqn.name}".upper() for fqn in fqns}
        return database_role_name_set

    # Determine whether to use ACCOUNT_USAGE or SHOW queries
    use_au = _should_use_account_usage(session, use_account_usage)
    au_succeeded = False

    if use_au:
        logger.debug("list_grants: using ACCOUNT_USAGE for regular grants")
        # Fetch all grants in a single ACCOUNT_USAGE query
        all_grants = _fetch_grants_from_account_usage(session)

        # If ACCOUNT_USAGE query succeeded, process results
        if all_grants is not None:
            au_succeeded = True
            # Build a set of non-system role names for filtering
            role_name_set = {str(rn) for rn in role_names}

            for data in all_grants:
                granted_to = data["granted_to"]
                grantee = data["grantee_name"]

                # Process grants to account roles
                if granted_to == "ROLE":
                    if grantee not in role_name_set:
                        continue
                    to_prefix = "role"
                # Process grants to database roles
                elif granted_to == "DATABASE ROLE":
                    if grantee.upper() not in get_database_role_name_set():
                        continue
                    to_prefix = "database_role"
                else:
                    # Skip other grantee types (e.g., USER)
                    continue

                # Skip role and database role grants (hierarchy is handled by
                # list_role_grants and list_database_role_grants)
                if _is_role_hierarchy_grant(data):
                    continue

                # Snowcap Grants don't support OWNERSHIP privilege
                if data["privilege"] == "OWNERSHIP":
                    continue

                # A database role is born holding usage on its own database
                if to_prefix == "database_role" and _is_intrinsic_database_role_usage(data, grantee):
                    continue

                # Skip undocumented privs
                if data["privilege"] in ["CANCEL QUERY"]:
                    continue

                # Inherited grants are container-level and carry no object name
                if _is_inherited_grant(data):
                    inherited_fqn = inherited_grant_fqn(data, to_prefix, grantee)
                    if inherited_fqn:
                        grants.append(inherited_fqn)
                    continue

                name = data["name"]
                if data["granted_on"] == "ACCOUNT":
                    name = "ACCOUNT"
                on = f"{_granted_on_label(data['granted_on'])}/{name}"
                priv = _imported_privileges_priv(data, shared_databases) or data["privilege"]
                to = f"{to_prefix}/{grantee}"
                grants.append(
                    FQN(
                        name=ResourceName("GRANT"),
                        params={
                            "grant_type": "OBJECT",
                            "priv": priv,
                            "on": on,
                            "to": to,
                        },
                    )
                )
        # Fall through to SHOW queries if ACCOUNT_USAGE failed

    if not au_succeeded:
        logger.debug("list_grants: using SHOW GRANTS per role (ACCOUNT_USAGE disabled or unavailable)")
        # Fall back to per-role SHOW queries for account roles
        for role_name in role_names:
            grant_data = _show_grants_to_role(
                session, role_name, role_type=ResourceType.ROLE, cacheable=True, use_account_usage=False
            )
            for data in grant_data:
                # Skip role and database role grants (hierarchy is handled by
                # list_role_grants and list_database_role_grants)
                if _is_role_hierarchy_grant(data):
                    continue

                # Snowcap Grants don't support OWNERSHIP privilege
                if data["privilege"] == "OWNERSHIP":
                    continue

                # Skip undocumented privs
                if data["privilege"] in ["CANCEL QUERY"]:
                    continue

                name = data["name"]
                if data["granted_on"] == "ACCOUNT":
                    name = "ACCOUNT"
                on = f"{_granted_on_label(data['granted_on'])}/{name}"
                priv = _imported_privileges_priv(data, shared_databases) or data["privilege"]
                to = f"role/{role_name}"
                grants.append(
                    FQN(
                        name=ResourceName("GRANT"),
                        params={
                            "grant_type": "OBJECT",
                            "priv": priv,
                            "on": on,
                            "to": to,
                        },
                    )
                )

        # Inherited grants come from the same (cached) SHOW GRANTS response, so listing them
        # costs no extra queries.
        for role_name in role_names:
            for data in _show_inherited_grants_to_role(session, role_name, role_type=ResourceType.ROLE):
                inherited_fqn = inherited_grant_fqn(data, "role", str(role_name))
                if inherited_fqn:
                    grants.append(inherited_fqn)

        # Also fetch grants for database roles using SHOW GRANTS TO DATABASE ROLE
        for db_role_fqn in get_database_roles():
            fq_db_role_name = f"{db_role_fqn.database}.{db_role_fqn.name}"
            grant_data = _show_grants_to_role(
                session,
                ResourceName(fq_db_role_name),
                role_type=ResourceType.DATABASE_ROLE,
                cacheable=True,
                use_account_usage=False,
            )
            for data in grant_data:
                # Skip role and database role grants (hierarchy is handled by
                # list_role_grants and list_database_role_grants)
                if _is_role_hierarchy_grant(data):
                    continue

                # Snowcap Grants don't support OWNERSHIP privilege
                if data["privilege"] == "OWNERSHIP":
                    continue

                # A database role is born holding usage on its own database
                if _is_intrinsic_database_role_usage(data, fq_db_role_name):
                    continue

                # Skip undocumented privs
                if data["privilege"] in ["CANCEL QUERY"]:
                    continue

                name = data["name"]
                if data["granted_on"] == "ACCOUNT":
                    name = "ACCOUNT"
                on = f"{_granted_on_label(data['granted_on'])}/{name}"
                priv = _imported_privileges_priv(data, shared_databases) or data["privilege"]
                to = f"database_role/{fq_db_role_name}"
                grants.append(
                    FQN(
                        name=ResourceName("GRANT"),
                        params={
                            "grant_type": "OBJECT",
                            "priv": priv,
                            "on": on,
                            "to": to,
                        },
                    )
                )

            for data in _show_inherited_grants_to_role(
                session, ResourceName(fq_db_role_name), role_type=ResourceType.DATABASE_ROLE
            ):
                inherited_fqn = inherited_grant_fqn(data, "database_role", fq_db_role_name)
                if inherited_fqn:
                    grants.append(inherited_fqn)

    # Future grants always use SHOW commands (not available in ACCOUNT_USAGE)
    # Only fetch if include_future_grants is True (manifest has future grants)
    if include_future_grants:
        # If future_grant_roles is provided, only fetch for those specific roles
        # This optimization avoids querying all roles when only a few have future grants
        if future_grant_roles:
            roles_to_query = [rn for rn in role_names if str(rn).upper() in future_grant_roles]
            logger.debug(f"list_grants: fetching future grants for {len(roles_to_query)} roles (filtered by manifest)")
        else:
            roles_to_query = role_names
            logger.debug("list_grants: fetching future grants using SHOW FUTURE GRANTS")

        future_grants_by_role = _fetch_future_grants_for_all_roles(session, roles_to_query)
        for role_name in roles_to_query:
            role_name_str = str(role_name)
            grant_data = future_grants_by_role.get(role_name_str, [])
            for data in grant_data:
                on_type = data["granted_on"].lower()
                collection = data["name"]
                to = f"role/{role_name}"
                grants.append(
                    FQN(
                        name=ResourceName("GRANT"),
                        params={
                            "grant_type": "FUTURE",
                            "priv": data["privilege"],
                            "on": f"{on_type}/{collection}",
                            "to": to,
                        },
                    )
                )

        # Fetch future grants for database roles
        if future_grant_database_roles:
            db_roles_to_query = [
                fqn
                for fqn in get_database_roles()
                if f"{fqn.database}.{fqn.name}".upper() in future_grant_database_roles
            ]
            logger.debug(
                f"list_grants: fetching future grants for {len(db_roles_to_query)} database roles (filtered by manifest)"
            )
        else:
            db_roles_to_query = get_database_roles()
            if db_roles_to_query:
                logger.debug(f"list_grants: fetching future grants for {len(db_roles_to_query)} database roles")

        if db_roles_to_query:
            future_grants_by_db_role = _fetch_future_grants_for_all_database_roles(session, db_roles_to_query)
            for db_role_fqn in db_roles_to_query:
                fq_db_role_name = f"{db_role_fqn.database}.{db_role_fqn.name}"
                grant_data = future_grants_by_db_role.get(fq_db_role_name, [])
                for data in grant_data:
                    on_type = data["granted_on"].lower()
                    collection = data["name"]
                    to = f"database_role/{fq_db_role_name}"
                    grants.append(
                        FQN(
                            name=ResourceName("GRANT"),
                            params={
                                "grant_type": "FUTURE",
                                "priv": data["privilege"],
                                "on": f"{on_type}/{collection}",
                                "to": to,
                            },
                        )
                    )
    else:
        logger.debug("list_grants: skipping future grants (none in manifest)")

    return grants


def list_iceberg_tables(session: SnowflakeConnection) -> list[FQN]:
    return list_schema_scoped_resource(session, "ICEBERG TABLES")


def list_image_repositories(session: SnowflakeConnection) -> list[FQN]:
    return list_schema_scoped_resource(session, "IMAGE REPOSITORIES")


def list_masking_policies(session: SnowflakeConnection) -> list[FQN]:
    return list_schema_scoped_resource(session, "MASKING POLICIES")


def list_mcp_servers(session: SnowflakeConnection) -> list[FQN]:
    return list_schema_scoped_resource(session, "MCP SERVERS")


def list_network_policies(session: SnowflakeConnection) -> list[FQN]:
    return list_account_scoped_resource(session, "NETWORK POLICIES")


def list_network_rules(session: SnowflakeConnection) -> list[FQN]:
    return list_schema_scoped_resource(session, "NETWORK RULES")


def list_notification_integrations(session: SnowflakeConnection) -> list[FQN]:
    return list_account_scoped_resource(session, "NOTIFICATION INTEGRATIONS")


def list_packages_policies(session: SnowflakeConnection) -> list[FQN]:
    return list_schema_scoped_resource(session, "PACKAGES POLICIES")


def list_password_policies(session: SnowflakeConnection) -> list[FQN]:
    return list_schema_scoped_resource(session, "PASSWORD POLICIES")


def list_pipes(session: SnowflakeConnection) -> list[FQN]:
    return list_schema_scoped_resource(session, "PIPES")


def list_procedures(session: SnowflakeConnection) -> list[FQN]:
    show_result = execute(session, "SHOW PROCEDURES IN ACCOUNT", cacheable=True)
    procedures = []
    for row in show_result:
        # Skip system procedures (empty database/schema) and system databases
        if not row["catalog_name"] or not row["schema_name"]:
            continue
        if row["catalog_name"] in SYSTEM_DATABASES:
            continue
        fqn, returns = _parse_function_arguments(row["arguments"])
        fqn.database = row["catalog_name"]
        fqn.schema = row["schema_name"]
        procedures.append(fqn)
    return procedures


def list_resource_monitors(session: SnowflakeConnection) -> list[FQN]:
    return list_account_scoped_resource(session, "RESOURCE MONITORS")


def list_row_access_policies(session: SnowflakeConnection) -> list[FQN]:
    return list_schema_scoped_resource(session, "ROW ACCESS POLICIES")


def list_roles(session: SnowflakeConnection) -> list[FQN]:
    # Use "SHOW ROLES IN ACCOUNT" to match _show_resources for cache consistency
    show_result = execute(session, "SHOW ROLES IN ACCOUNT", cacheable=True)
    return [
        FQN(name=resource_name_from_snowflake_metadata(row["name"]))
        for row in show_result
        if row["name"] not in SYSTEM_ROLES
    ]


def list_role_grants(session: SnowflakeConnection, use_account_usage: bool = False) -> list[FQN]:
    """
    List all role grants (role-to-role and role-to-user) in the account.

    When use_account_usage is True and ACCOUNT_USAGE access is available, uses:
    - GRANTS_TO_ROLES view for role-to-role grants (privilege=USAGE, granted_on=ROLE)
    - GRANTS_TO_USERS view for role-to-user grants

    Falls back to SHOW GRANTS OF ROLE commands when ACCOUNT_USAGE is unavailable.

    Returns:
        List of FQN objects representing role grants, with params indicating
        whether the grantee is a 'user' or 'role'.
    """
    # Use "SHOW ROLES IN ACCOUNT" to match _show_resources for cache consistency
    roles = execute(session, "SHOW ROLES IN ACCOUNT", cacheable=True)

    # Build set of role names for filtering grants
    # Include system roles so grants OF system roles (e.g., ACCOUNTADMIN → USER) can be tracked
    role_name_set: set[str] = set()
    role_names: list[ResourceName] = []
    for role in roles:
        role_name = resource_name_from_snowflake_metadata(role["name"])
        role_name_set.add(str(role_name).upper())
        if role_name in SYSTEM_ROLES:
            continue
        role_names.append(role_name)

    grants: list[FQN] = []

    # Try ACCOUNT_USAGE if enabled and accessible
    use_au = _should_use_account_usage(session, use_account_usage)
    au_succeeded = False

    if use_au:
        logger.debug("Using ACCOUNT_USAGE views for list_role_grants()")

        # Get role-to-role grants from GRANTS_TO_ROLES
        # These are grants where privilege=USAGE and granted_on=ROLE
        all_grants = _fetch_grants_from_account_usage(session)

        # If ACCOUNT_USAGE query succeeded, process results
        if all_grants is not None:
            for grant in all_grants:
                # Filter for role grants (USAGE on ROLE)
                if grant["privilege"] != "USAGE" or grant["granted_on"] != "ROLE":
                    continue

                role_being_granted = grant["name"]  # The role being granted
                grantee_name = grant["grantee_name"]  # Who receives the grant

                # Only include roles we're tracking
                if role_being_granted.upper() not in role_name_set:
                    continue

                # Skip grants between system roles (system hierarchy - not user-managed)
                if role_being_granted.upper() in SYSTEM_ROLES and grantee_name.upper() in SYSTEM_ROLES:
                    continue

                # The granted_to field indicates if grantee is ROLE or DATABASE ROLE
                if grant["granted_to"] == "ROLE":
                    grants.append(
                        FQN(
                            name=resource_name_from_snowflake_metadata(role_being_granted),
                            params={"role": grantee_name},
                        )
                    )

            # Get role-to-user grants from GRANTS_TO_USERS
            user_grants = _fetch_role_grants_to_users_from_account_usage(session)

            # If user grants query also succeeded, mark as successful
            if user_grants is not None:
                au_succeeded = True
                for grant in user_grants:
                    role_being_granted = grant["role"]

                    # Only include roles we're tracking (includes system roles for grant tracking)
                    if role_being_granted.upper() not in role_name_set:
                        continue

                    grants.append(
                        FQN(
                            name=resource_name_from_snowflake_metadata(role_being_granted),
                            params={"user": grant["grantee_name"]},
                        )
                    )
        # Fall through to SHOW queries if ACCOUNT_USAGE failed

    if not au_succeeded:
        # Fallback to SHOW GRANTS OF ROLE commands
        # Clear any partial results from failed ACCOUNT_USAGE attempt
        grants = []
        logger.debug("Using SHOW GRANTS OF ROLE for list_role_grants() (ACCOUNT_USAGE unavailable or disabled)")

        def error_handler(err: Exception, sql: str):
            if isinstance(err, ProgrammingError) and err.errno == DOES_NOT_EXIST_ERR:
                return
            raise err

        # Include system roles so grants OF them (e.g., ACCOUNTADMIN → USER) can be tracked
        all_role_names = list(role_names) + [ResourceName(r) for r in SYSTEM_ROLES]

        for name, result in execute_in_parallel(
            session,
            [(f"SHOW GRANTS OF ROLE {role_name}", role_name) for role_name in all_role_names],
            error_handler=error_handler,
            cacheable=True,
        ):
            for data in result:
                grantee_name = data["grantee_name"]
                # Skip grants between system roles (system hierarchy - not user-managed)
                if str(name).upper() in SYSTEM_ROLES and grantee_name.upper() in SYSTEM_ROLES:
                    continue
                subject = "user" if data["granted_to"] == "USER" else "role"
                grants.append(FQN(name=name, params={subject: grantee_name}))

    return grants


def list_scanner_packages(session: SnowflakeConnection) -> list[FQN]:
    try:
        scanner_packages = execute(
            session, "select * from snowflake.trust_center.scanner_packages WHERE state = 'TRUE'", cacheable=True
        )
    except ProgrammingError as err:
        # Trust Center may not be available on all accounts
        logger.debug(f"Could not query trust_center.scanner_packages: {err}")
        return []
    user_packages = []
    for pkg in scanner_packages:
        if pkg["ID"] == "SECURITY_ESSENTIALS":
            continue
        user_packages.append(FQN(name=resource_name_from_snowflake_metadata(pkg["ID"])))
    return user_packages


def list_schemas(session: SnowflakeConnection, database=None) -> list[FQN]:
    if database:
        in_ctx = f"DATABASE {database}"
        user_databases = None
    else:
        in_ctx = "ACCOUNT"
        user_databases = _list_databases(session)
    try:
        show_result = execute(session, f"SHOW SCHEMAS IN {in_ctx}", cacheable=True)
        schemas = []
        for row in show_result:
            # Skip system databases
            if row["database_name"] in SYSTEM_DATABASES:
                continue
            # Skip system schemas
            if row["name"] == "INFORMATION_SCHEMA":
                continue
            # Skip database shares
            if database is None and row["database_name"] not in (user_databases or []):
                continue
            schemas.append(
                FQN(
                    database=resource_name_from_snowflake_metadata(row["database_name"]),
                    name=resource_name_from_snowflake_metadata(row["name"]),
                )
            )
        return schemas
    except ProgrammingError as err:
        if err.errno == OBJECT_DOES_NOT_EXIST_ERR:
            return []
        raise


def list_git_repositories(session: SnowflakeConnection) -> list[FQN]:
    return list_schema_scoped_resource(session, "GIT REPOSITORIES")


def list_secrets(session: SnowflakeConnection) -> list[FQN]:
    return list_schema_scoped_resource(session, "SECRETS")


def list_security_integrations(session: SnowflakeConnection) -> list[FQN]:
    show_result = execute(session, "SHOW SECURITY INTEGRATIONS", cacheable=True)
    integrations = []
    for row in show_result:
        if row["name"] in SYSTEM_SECURITY_INTEGRATIONS:
            continue
        integrations.append(FQN(name=resource_name_from_snowflake_metadata(row["name"])))
    return integrations


def list_sequences(session: SnowflakeConnection) -> list[FQN]:
    return list_schema_scoped_resource(session, "SEQUENCES")


def list_shares(session: SnowflakeConnection) -> list[FQN]:
    show_result = execute(session, "SHOW SHARES", cacheable=True)
    shares = []
    for row in show_result:
        if row["kind"] == "INBOUND":
            continue
        shares.append(FQN(name=resource_name_from_snowflake_metadata(row["name"])))
    return shares


def _warn_account_usage_staleness(session: SnowflakeConnection) -> None:
    """Say once per session that a listing read from ACCOUNT_USAGE may be behind live state."""
    session_id = id(session)
    if session_id in _ACCOUNT_USAGE_STALENESS_WARNED:
        return
    _ACCOUNT_USAGE_STALENESS_WARNED.add(session_id)
    logger.warning(
        "Listing objects from ACCOUNT_USAGE, which lags live state by up to ~2 hours: "
        "recently created objects may be missing. Pass --no-use-account-usage to list with "
        "real-time SHOW instead."
    )


def _list_schema_scoped_from_account_usage(
    session: SnowflakeConnection, sql: str, use_account_usage: bool = False
) -> Optional[list[FQN]]:
    """
    List schema-scoped objects from ACCOUNT_USAGE, which SHOW ... IN ACCOUNT cannot past
    its 10,000-row cap (error 090153).

    `sql` must alias its columns to the names SHOW uses ("database_name", "schema_name",
    "name") and exclude dropped objects. Returns None when ACCOUNT_USAGE is off,
    unavailable, or the query fails, so the caller falls back to SHOW.
    """
    if not _should_use_account_usage(session, use_account_usage):
        return None
    try:
        rows = execute(session, sql, cacheable=True)
    except Exception as e:  # any failure should fall back to SHOW
        logger.warning(f"ACCOUNT_USAGE listing failed, falling back to SHOW: {e}")
        _mark_account_usage_fallback(session)
        return None

    _warn_account_usage_staleness(session)
    # Compare in ResourceName space: str() renders '"MyDb"' where ACCOUNT_USAGE returns
    # MyDb, so comparing rendered strings drops every quoted or mixed-case database.
    user_databases = _list_databases(session)
    results = []
    for row in rows:
        database = resource_name_from_snowflake_metadata(row["database_name"])
        if row["database_name"] in SYSTEM_DATABASES or database not in user_databases:
            continue
        if row["schema_name"] == "INFORMATION_SCHEMA":
            continue
        results.append(
            FQN(
                database=database,
                schema=resource_name_from_snowflake_metadata(row["schema_name"]),
                name=resource_name_from_snowflake_metadata(row["name"]),
            )
        )
    return results


def list_stages(session: SnowflakeConnection, use_account_usage: bool = False) -> list[FQN]:
    # Named stages only, matching the SHOW path's type filter below.
    from_account_usage = _list_schema_scoped_from_account_usage(
        session,
        """
        SELECT stage_catalog AS "database_name",
               stage_schema  AS "schema_name",
               stage_name    AS "name"
        FROM SNOWFLAKE.ACCOUNT_USAGE.STAGES
        WHERE deleted IS NULL
          AND stage_type IN ('Internal Named', 'External Named')
        """,
        use_account_usage=use_account_usage,
    )
    if from_account_usage is not None:
        return from_account_usage

    show_result = execute(session, "SHOW STAGES IN ACCOUNT", cacheable=True)
    stages = []
    for row in show_result:
        if row["database_name"] in SYSTEM_DATABASES:
            continue
        if row["type"] not in ("EXTERNAL", "INTERNAL", "INTERNAL NO CSE"):
            continue
        stages.append(
            FQN(
                database=resource_name_from_snowflake_metadata(row["database_name"]),
                schema=resource_name_from_snowflake_metadata(row["schema_name"]),
                name=resource_name_from_snowflake_metadata(row["name"]),
            )
        )
    return stages


def list_storage_integrations(session: SnowflakeConnection) -> list[FQN]:
    return list_account_scoped_resource(session, "STORAGE INTEGRATIONS")


def list_streams(session: SnowflakeConnection) -> list[FQN]:
    return list_schema_scoped_resource(session, "STREAMS")


def list_tables(session: SnowflakeConnection, use_account_usage: bool = False) -> list[FQN]:
    # The SHOW path's exclusions map onto table_type plus the is_* flags, which older
    # accounts may lack -- hence COALESCE.
    from_account_usage = _list_schema_scoped_from_account_usage(
        session,
        """
        SELECT table_catalog AS "database_name",
               table_schema  AS "schema_name",
               table_name    AS "name"
        FROM SNOWFLAKE.ACCOUNT_USAGE.TABLES
        WHERE deleted IS NULL
          AND table_type = 'BASE TABLE'
          AND COALESCE(is_iceberg, 'NO') = 'NO'
          AND COALESCE(is_dynamic, 'NO') = 'NO'
          AND COALESCE(is_hybrid,  'NO') = 'NO'
        """,
        use_account_usage=use_account_usage,
    )
    if from_account_usage is not None:
        return from_account_usage

    show_result = execute(session, "SHOW TABLES IN ACCOUNT", cacheable=True)
    user_databases = _list_databases(session)
    tables = []
    for row in show_result:
        if row["database_name"] in SYSTEM_DATABASES:
            continue
        if row["schema_name"] == "INFORMATION_SCHEMA":
            continue
        if row["database_name"] not in user_databases:
            continue
        if (
            row["is_external"] == "Y"
            or row["is_hybrid"] == "Y"
            or row["is_iceberg"] == "Y"
            or row["is_dynamic"] == "Y"
            or row["is_event"] == "Y"
        ):
            continue
        tables.append(
            FQN(
                database=resource_name_from_snowflake_metadata(row["database_name"]),
                schema=resource_name_from_snowflake_metadata(row["schema_name"]),
                name=resource_name_from_snowflake_metadata(row["name"]),
            )
        )
    return tables


def list_tag_references(session: SnowflakeConnection) -> list[FQN]:
    # FIXME
    # This function previously relied on a system table function with 2 hours of latency.

    try:
        # show_result = execute(session, "SHOW TAGS IN ACCOUNT")
        tag_references: list[FQN] = []
        # for tag in show_result:
        #     if tag["database_name"] in SYSTEM_DATABASES or tag["schema_name"] == "INFORMATION_SCHEMA":
        #         continue

        #     tag_refs = execute(
        #         session,
        #         f"""
        #             SELECT *
        #             FROM table(snowflake.account_usage.tag_references_with_lineage(
        #                 '{tag['database_name']}.{tag['schema_name']}.{tag['name']}'
        #             ))
        #         """,
        #     )

        #     for ref in tag_refs:
        #         if ref["OBJECT_DELETED"] is not None:
        #             continue

        #         tag_references.append(
        #             FQN(
        #                 database=resource_name_from_snowflake_metadata(ref["TAG_DATABASE"]),
        #                 schema=resource_name_from_snowflake_metadata(ref["TAG_SCHEMA"]),
        #                 name=resource_name_from_snowflake_metadata(ref["TAG_NAME"]),
        #             )
        #         )

        return tag_references

    except ProgrammingError as err:
        if err.errno == UNSUPPORTED_FEATURE:
            return []
        else:
            raise


def list_tags(session: SnowflakeConnection) -> list[FQN]:
    try:
        show_result = execute(session, "SHOW TAGS IN ACCOUNT", cacheable=True)
        tags = []
        for row in show_result:
            if row["database_name"] in SYSTEM_DATABASES or row["schema_name"] == "INFORMATION_SCHEMA":
                continue
            tags.append(
                FQN(
                    database=resource_name_from_snowflake_metadata(row["database_name"]),
                    schema=resource_name_from_snowflake_metadata(row["schema_name"]),
                    name=resource_name_from_snowflake_metadata(row["name"]),
                )
            )
        return tags
    except ProgrammingError as err:
        if err.errno == UNSUPPORTED_FEATURE:
            return []
        else:
            raise


def list_tag_masking_policy_references(session: SnowflakeConnection) -> list[FQN]:
    """
    List all tag-based masking policy references using INFORMATION_SCHEMA.POLICY_REFERENCES.

    Uses the INFORMATION_SCHEMA table function which shows tag-to-masking-policy associations
    directly, without requiring the tag to be applied to any columns first.
    """
    references = []

    # Get all tags first
    tags = list_tags(session)
    logger.debug(f"list_tag_masking_policy_references: checking {len(tags)} tags for masking policies")

    for tag_fqn in tags:
        try:
            # Use INFORMATION_SCHEMA.POLICY_REFERENCES table function with REF_ENTITY_DOMAIN='TAG'
            # This shows masking policies directly attached to the tag
            tag_full_name = f"{tag_fqn.database}.{tag_fqn.schema}.{tag_fqn.name}"
            result = execute(
                session,
                f"""
                SELECT
                    POLICY_DB,
                    POLICY_SCHEMA,
                    POLICY_NAME,
                    POLICY_KIND
                FROM TABLE({tag_fqn.database}.INFORMATION_SCHEMA.POLICY_REFERENCES(
                    REF_ENTITY_NAME => '{tag_full_name}',
                    REF_ENTITY_DOMAIN => 'TAG'
                ))
                WHERE POLICY_KIND = 'MASKING_POLICY'
                """,
                cacheable=True,
            )

            for row in result:
                # Build the masking policy FQN string (lowercase to match config format)
                policy_db = str(resource_name_from_snowflake_metadata(row["POLICY_DB"])).lower()
                policy_schema = str(resource_name_from_snowflake_metadata(row["POLICY_SCHEMA"])).lower()
                policy_name = str(resource_name_from_snowflake_metadata(row["POLICY_NAME"])).lower()
                masking_policy_fqn = f"{policy_db}.{policy_schema}.{policy_name}"
                fqn = FQN(
                    database=tag_fqn.database,
                    schema=tag_fqn.schema,
                    name=tag_fqn.name,
                    params={"masking_policy": masking_policy_fqn},
                )
                logger.debug(f"  Found tag masking policy reference: {fqn}")
                references.append(fqn)
        except ProgrammingError as err:
            if err.errno in (ACCESS_CONTROL_ERR, UNSUPPORTED_FEATURE, DOES_NOT_EXIST_ERR):
                # Skip tags we can't access or don't exist
                logger.debug(f"  Skipping tag {tag_fqn}: {err.msg}")
                continue
            else:
                raise

    logger.debug(f"list_tag_masking_policy_references: found {len(references)} total references")
    return references


def fetch_tag_masking_policy_reference(session: SnowflakeConnection, fqn: FQN) -> Optional[dict]:
    """
    Fetch a specific tag masking policy reference using INFORMATION_SCHEMA.POLICY_REFERENCES.

    Uses the INFORMATION_SCHEMA table function which shows tag-to-masking-policy associations
    directly, without requiring the tag to be applied to any columns first.
    """
    masking_policy_name = fqn.params.get("masking_policy")
    if not masking_policy_name:
        return None

    # Build the full tag name for the query
    tag_full_name = f"{fqn.database}.{fqn.schema}.{fqn.name}"
    masking_policy_name_upper = masking_policy_name.upper()

    try:
        result = execute(
            session,
            f"""
            SELECT
                POLICY_DB,
                POLICY_SCHEMA,
                POLICY_NAME
            FROM TABLE({fqn.database}.INFORMATION_SCHEMA.POLICY_REFERENCES(
                REF_ENTITY_NAME => '{tag_full_name}',
                REF_ENTITY_DOMAIN => 'TAG'
            ))
            WHERE POLICY_KIND = 'MASKING_POLICY'
              AND CONCAT(POLICY_DB, '.', POLICY_SCHEMA, '.', POLICY_NAME) = '{masking_policy_name_upper}'
            LIMIT 1
            """,
            cacheable=True,
        )

        if len(result) == 0:
            return None

        row = result[0]
        # Normalize to lowercase for consistent comparison
        tag_db = str(fqn.database).lower()
        tag_schema = str(fqn.schema).lower()
        tag_name_normalized = str(fqn.name).lower()
        policy_db = str(resource_name_from_snowflake_metadata(row["POLICY_DB"])).lower()
        policy_schema = str(resource_name_from_snowflake_metadata(row["POLICY_SCHEMA"])).lower()
        policy_name = str(resource_name_from_snowflake_metadata(row["POLICY_NAME"])).lower()
        return {
            "tag_name": f"{tag_db}.{tag_schema}.{tag_name_normalized}",
            "masking_policy_name": f"{policy_db}.{policy_schema}.{policy_name}",
        }
    except ProgrammingError as err:
        if err.errno in (ACCESS_CONTROL_ERR, UNSUPPORTED_FEATURE, DOES_NOT_EXIST_ERR):
            logger.debug(f"Cannot fetch tag masking policy reference {fqn}: {err.msg}")
            return None
        else:
            raise


def list_tasks(session: SnowflakeConnection) -> list[FQN]:
    return list_schema_scoped_resource(session, "TASKS")


def list_users(session: SnowflakeConnection) -> list[FQN]:
    show_result = execute(session, "SHOW USERS", cacheable=True)
    users = []
    for row in show_result:
        if row["name"] in SYSTEM_USERS:
            continue
        users.append(FQN(name=resource_name_from_snowflake_metadata(row["name"])))
    return users


def list_user_key_pairs(session: SnowflakeConnection) -> list[FQN]:
    # SHOW USER KEY PAIRS lists one user's key pairs, so the account-wide sweep is one
    # query per user.
    def error_handler(err: Exception, sql: str):
        # A user dropped between SHOW USERS and this query, or one whose key pairs this
        # role can't read, shouldn't fail the whole sweep.
        if isinstance(err, ProgrammingError) and err.errno in (DOES_NOT_EXIST_ERR, ACCESS_CONTROL_ERR):
            return
        raise err

    key_pairs = []
    for user, result in execute_in_parallel(
        session,
        [(_show_user_key_pairs_sql(user.name), user.name) for user in list_users(session)],
        error_handler=error_handler,
        cacheable=True,
    ):
        for row in result:
            # A sync sweep proposes dropping whatever config doesn't declare, so rows that
            # config cannot declare have to stay out of it.
            if not _key_pair_is_declarable(row):
                continue
            key_pairs.append(
                FQN(
                    name=resource_name_from_snowflake_metadata(row["name"]),
                    params={"user": str(user)},
                )
            )
    return key_pairs


def list_views(session: SnowflakeConnection, use_account_usage: bool = False) -> list[FQN]:
    # .TABLES, not .VIEWS: table_type excludes materialized views, as the SHOW path does.
    from_account_usage = _list_schema_scoped_from_account_usage(
        session,
        """
        SELECT table_catalog AS "database_name",
               table_schema  AS "schema_name",
               table_name    AS "name"
        FROM SNOWFLAKE.ACCOUNT_USAGE.TABLES
        WHERE deleted IS NULL
          AND table_type = 'VIEW'
        """,
        use_account_usage=use_account_usage,
    )
    if from_account_usage is not None:
        return from_account_usage

    show_result = execute(session, "SHOW VIEWS IN ACCOUNT", cacheable=True)
    views = []
    for row in show_result:
        if row["database_name"] in SYSTEM_DATABASES or row["schema_name"] == "INFORMATION_SCHEMA":
            continue
        if row["is_materialized"] == "true":
            continue
        views.append(
            FQN(
                database=resource_name_from_snowflake_metadata(row["database_name"]),
                schema=resource_name_from_snowflake_metadata(row["schema_name"]),
                name=resource_name_from_snowflake_metadata(row["name"]),
            )
        )
    return views


def list_warehouses(session: SnowflakeConnection) -> list[FQN]:
    show_result = execute(session, "SHOW WAREHOUSES", cacheable=True)
    warehouses = []
    for row in show_result:
        if row["name"].startswith("SYSTEM$"):
            continue
        warehouses.append(FQN(name=resource_name_from_snowflake_metadata(row["name"])))
    return warehouses
