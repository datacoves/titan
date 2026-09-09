import re
from dataclasses import dataclass, field
from typing import Optional

from ..enums import AccountEdition, ResourceType
from ..identifiers import FQN
from ..props import IntProp, Props, StringProp
from ..public_key import (
    FINGERPRINT_PREFIX,
    normalize_fingerprint,
    normalize_public_key,
    public_key_fingerprint,
)
from ..resource_name import ResourceName
from ..scope import AccountScope
from .resource import NamedResource, Resource, ResourceSpec
from .role import Role
from .user import User

__all__ = [
    "FINGERPRINT_PREFIX",
    "RESERVED_KEY_PAIR_NAMES",
    "UserKeyPair",
    "key_pair_is_rotated_out",
    "normalize_fingerprint",
    "normalize_public_key",
    "public_key_fingerprint",
    "user_key_pair_fqn",
]

# Snowflake reserves these names for the keys set through the legacy RSA_PUBLIC_KEY and
# RSA_PUBLIC_KEY_2 user properties. They can't be added, modified, rotated, or removed
# with the KEY PAIR commands.
RESERVED_KEY_PAIR_NAMES = (ResourceName("PUBLIC_KEY_1"), ResourceName("PUBLIC_KEY_2"))

# The shape of the name Snowflake generates for the prior key of a rotation. It is a
# naming convention, not a guarantee -- a fetched key pair is identified as rotated-out by
# the `rotated_to` column, never by its name -- so this is only used to keep a config from
# claiming a name in the namespace Snowflake generates into.
ROTATED_KEY_PAIR_NAME = re.compile(r"_ROTATED_\d+$")


def key_pair_is_rotated_out(name: str) -> bool:
    """True for a name shaped like the `<name>_ROTATED_<epoch_ms>` a rotation generates."""
    return ROTATED_KEY_PAIR_NAME.search(name) is not None


@dataclass(unsafe_hash=True)
class _UserKeyPair(ResourceSpec):
    name: ResourceName
    user: User
    # A key pair is not a standalone object in Snowflake and has no owner of its own.
    # This names the role that manages the user the key pair belongs to, which is the
    # role snowcap runs the ALTER USER statements as.
    owner: Role = field(default="USERADMIN", metadata={"fetchable": False})
    # Snowflake stores the public key but never returns it, so config is authoritative
    # and drift is detected through `fingerprint` instead.
    public_key: str = field(default=None, metadata={"fetchable": False})
    fingerprint: str = None
    role_restriction: Role = field(
        default=None,
        metadata={
            "triggers_replacement": True,
            "replacement_message": (
                "Snowflake cannot change the role restriction of an existing key pair. "
                "Remove the key pair from config, apply, then add it back with the new role_restriction."
            ),
        },
    )
    # Snowflake reports an absolute expires_at rather than the relative value that was
    # registered, so the duration itself can't be compared without reporting drift on
    # every plan. Config wins, and has_expiration catches the case that matters: an
    # expiration added to, or dropped from, a key pair that already exists.
    days_to_expiry: int = field(default=None, metadata={"fetchable": False})
    has_expiration: bool = field(
        default=None,
        metadata={
            "triggers_replacement": True,
            "replacement_message": (
                "Snowflake cannot add or remove the expiration of an existing key pair. "
                "Remove the key pair from config, apply, then add it back with the new days_to_expiry."
            ),
        },
    )
    # How long the prior key stays valid after a rotation. Not a property of the key pair
    # -- Snowflake never reports it -- but a directive for the next ROTATE KEY PAIR.
    expire_rotated_key_pair_after_hours: int = field(default=None, metadata={"fetchable": False})
    disabled: bool = False
    comment: str = None

    def __post_init__(self):
        super().__post_init__()

        # Name guardrails live on the resource constructor, not here: this spec is also
        # how remote state is deserialized, so it has to accept every name Snowflake can
        # report -- including a live key pair someone named to look rotated-out.
        if self.days_to_expiry is not None and self.days_to_expiry < 1:
            raise ValueError("days_to_expiry must be 1 or greater")
        if self.expire_rotated_key_pair_after_hours is not None and self.expire_rotated_key_pair_after_hours < 0:
            raise ValueError("expire_rotated_key_pair_after_hours must be 0 or greater")

        # A key pair fetched from Snowflake reports whether it expires; config says so by
        # declaring a duration. Leave the fetched value alone when there is no duration.
        if self.days_to_expiry is not None:
            self.has_expiration = True

        # Vars are resolved after the resource is constructed, so a public key that is
        # still a template is left alone here and normalized in to_dict instead.
        if isinstance(self.public_key, str):
            self.public_key = normalize_public_key(self.public_key)
            self.fingerprint = public_key_fingerprint(self.public_key)

    def to_dict(self, account_edition: AccountEdition):
        serialized = super().to_dict(account_edition)
        public_key = serialized.get("public_key")
        # Recompute rather than trust the stored value: a public key given as a var is a
        # template string until vars are resolved, which happens after __post_init__.
        if isinstance(public_key, str):
            serialized["public_key"] = normalize_public_key(public_key)
            serialized["fingerprint"] = public_key_fingerprint(serialized["public_key"])
        return serialized


class UserKeyPair(NamedResource, Resource):
    """
    Description:
        A named key pair registered for a user, used for key-pair authentication.

        Named key pairs are the recommended alternative to the legacy rsa_public_key and
        rsa_public_key_2 user properties: a user can hold up to 10 of them, and each one
        can carry its own role restriction, expiration, and comment.

        Snowflake never returns the public key itself, only its SHA-256 fingerprint, so
        snowcap compares the fingerprint of the configured key against the one Snowflake
        reports. Changing public_key plans a key rotation (ALTER USER ... ROTATE KEY PAIR),
        which keeps the prior key valid for a grace period so clients can pick up the new
        one without downtime. Set expire_rotated_key_pair_after_hours to control that grace
        period, or to 0 to revoke the prior key immediately when responding to a leak.

    Snowflake Docs:
        https://docs.snowflake.com/en/sql-reference/sql/alter-user-add-key-pair

    Fields:
        name (string, required): The name of the key pair.
        user (string or User, required): The user the key pair is registered for.
        public_key (string, required): The public key, with or without PEM delimiters.
        owner (string or Role): The role that manages the user. Defaults to "USERADMIN".
        role_restriction (string or Role): The role a session authenticated with this key pair
            is restricted to. The role must already be granted to the user.
        days_to_expiry (int): The number of days the key pair can be used for authentication.
        expire_rotated_key_pair_after_hours (int): How many hours the prior key stays valid
            after a rotation. 0 revokes it immediately. Defaults to Snowflake's 24 hours.
        disabled (bool): Whether the key pair is disabled. Defaults to False.
        comment (string): A comment for the key pair.

    Python:

        ```python
        key_pair = UserKeyPair(
            name="my_key",
            user="some_user",
            public_key="MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgK...",
            comment="primary workload key",
        )
        ```

    Yaml:

        ```yaml
        user_key_pairs:
          - name: my_key
            user: some_user
            public_key: MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgK...
            comment: primary workload key
        ```

    """

    resource_type = ResourceType.USER_KEY_PAIR
    props = Props(
        public_key=StringProp("public_key"),
        role_restriction=StringProp("role_restriction"),
        days_to_expiry=IntProp("days_to_expiry"),
        comment=StringProp("comment"),
    )
    scope = AccountScope()
    spec = _UserKeyPair

    def __init__(
        self,
        name: str,
        user: str,
        public_key: str = None,
        owner: str = "USERADMIN",
        role_restriction: str = None,
        days_to_expiry: int = None,
        expire_rotated_key_pair_after_hours: int = None,
        disabled: bool = False,
        comment: str = None,
        **kwargs,
    ):
        super().__init__(name, **kwargs)
        if public_key is None:
            raise ValueError(f"public_key is required for user key pair {name}")
        # A name given as a var is still a template here and is not re-checked once vars
        # resolve; Snowflake refuses the reserved names itself, so the cost is a worse
        # error message rather than a wrong apply.
        if self._name in RESERVED_KEY_PAIR_NAMES:
            raise ValueError(
                f"{self._name} is reserved by Snowflake for the legacy rsa_public_key and "
                "rsa_public_key_2 user properties. Set those on the user resource instead."
            )
        if key_pair_is_rotated_out(str(self._name)):
            raise ValueError(
                f"{self._name} names a rotated-out key pair. Snowflake generates those names "
                "during rotation, so declaring one would collide with a name Snowflake owns."
            )
        self._data: _UserKeyPair = _UserKeyPair(
            name=self._name,
            user=user,
            owner=owner,
            public_key=public_key,
            role_restriction=role_restriction,
            days_to_expiry=days_to_expiry,
            expire_rotated_key_pair_after_hours=expire_rotated_key_pair_after_hours,
            disabled=disabled,
            comment=comment,
        )
        self.requires(self._data.user)
        if self._data.role_restriction is not None:
            self.requires(self._data.role_restriction)

    def __repr__(self):  # pragma: no cover
        name = getattr(self._data, "name", "")
        user = getattr(self._data, "user", "")
        return f"UserKeyPair(name={name}, user={user})"

    @property
    def fqn(self):
        return user_key_pair_fqn(self._data)

    @property
    def fqn_params(self) -> dict:
        # A key pair is named within its user, so the user is part of its identity.
        return {"user": self._data.user.name}

    @property
    def user(self) -> User:
        return self._data.user

    @property
    def fingerprint(self) -> Optional[str]:
        return self._data.fingerprint


def user_key_pair_fqn(key_pair: _UserKeyPair) -> FQN:
    return FQN(name=key_pair.name, params={"user": str(key_pair.user.name)})
