import base64
import hashlib
import json
import logging

import pytest

from snowcap import lifecycle
from snowcap import resources as res
from snowcap.blueprint import (
    Blueprint,
    CreateResource,
    UpdateResource,
    compile_plan_to_sql,
    diff,
    dump_plan,
    execution_strategy_for_change,
    plan_from_dict,
)
from snowcap.data_provider import _key_pair_is_declarable, _user_key_pair_to_dict
from snowcap.enums import AccountEdition, ResourceType
from snowcap.exceptions import DuplicateResourceException, MarkedForReplacementException
from snowcap.gitops import collect_blueprint_config
from snowcap.identifiers import parse_URN
from snowcap.operations.export import EXPORT_ONLY_WHEN_ASKED_FOR, _format_resource_config
from snowcap.resource_name import ResourceName
from snowcap.resources.user_key_pair import (
    key_pair_is_rotated_out,
    normalize_fingerprint,
    normalize_public_key,
    public_key_fingerprint,
)
from tests.helpers import (
    TEST_PUBLIC_KEY,
    TEST_PUBLIC_KEY_2,
    TEST_PUBLIC_KEY_2_FINGERPRINT,
    TEST_PUBLIC_KEY_FINGERPRINT,
    flatten_sql_commands,
)

PUBLIC_KEY = TEST_PUBLIC_KEY
PUBLIC_KEY_FINGERPRINT = TEST_PUBLIC_KEY_FINGERPRINT
OTHER_PUBLIC_KEY = TEST_PUBLIC_KEY_2
OTHER_PUBLIC_KEY_FINGERPRINT = TEST_PUBLIC_KEY_2_FINGERPRINT

KEY_PAIR_URN = parse_URN("urn::ABCD123:user_key_pair/MY_KEY?user=SOME_USER")


@pytest.fixture
def session_ctx() -> dict:
    return {
        "account": "SOMEACCT",
        "account_edition": AccountEdition.ENTERPRISE,
        "account_locator": "ABCD123",
        "role": "SYSADMIN",
        "available_roles": ["SYSADMIN", "USERADMIN", "ACCOUNTADMIN", "SECURITYADMIN", "PUBLIC"],
    }


def remote_key_pair(**overrides) -> dict:
    """The state snowcap builds from what SHOW USER KEY PAIRS reports."""
    data = {
        "name": "MY_KEY",
        "user": "SOME_USER",
        "owner": "USERADMIN",
        "public_key": None,
        "fingerprint": PUBLIC_KEY_FINGERPRINT,
        "role_restriction": None,
        "days_to_expiry": None,
        "has_expiration": False,
        "expire_rotated_key_pair_after_hours": None,
        "disabled": False,
        "comment": None,
    }
    data.update(overrides)
    return data


class TestFingerprint:
    def test_fingerprint_matches_snowflakes_digest(self):
        expected = "SHA256:" + base64.b64encode(hashlib.sha256(base64.b64decode(PUBLIC_KEY)).digest()).decode()
        assert public_key_fingerprint(PUBLIC_KEY) == expected == PUBLIC_KEY_FINGERPRINT

    def test_pem_delimiters_and_newlines_are_ignored(self):
        pem = (
            "-----BEGIN PUBLIC KEY-----\n"
            + "\n".join(PUBLIC_KEY[i : i + 64] for i in range(0, len(PUBLIC_KEY), 64))
            + "\n-----END PUBLIC KEY-----\n"
        )
        assert normalize_public_key(pem) == PUBLIC_KEY
        assert public_key_fingerprint(pem) == PUBLIC_KEY_FINGERPRINT

    def test_invalid_key_material_is_rejected(self):
        with pytest.raises(ValueError):
            public_key_fingerprint("not a key")
        with pytest.raises(ValueError):
            public_key_fingerprint("")

    def test_normalize_fingerprint_accepts_either_form(self):
        assert normalize_fingerprint("wX178b99Nw5LQcMoiREuFn4pdqdJkSbRz9WSSGOm8oU=") == PUBLIC_KEY_FINGERPRINT
        assert normalize_fingerprint(f" {PUBLIC_KEY_FINGERPRINT} ") == PUBLIC_KEY_FINGERPRINT

    def test_rotated_out_names_are_recognized(self):
        assert key_pair_is_rotated_out("MY_KEY_ROTATED_1755000000000")
        assert not key_pair_is_rotated_out("MY_KEY")
        assert not key_pair_is_rotated_out("MY_ROTATED_KEY")


class TestUserKeyPair:
    def test_minimal(self):
        key_pair = res.UserKeyPair(name="my_key", user="some_user", public_key=PUBLIC_KEY)
        assert key_pair.resource_type == ResourceType.USER_KEY_PAIR
        assert key_pair.name == "my_key"
        assert key_pair.fqn.params == {"user": "SOME_USER"}
        assert str(key_pair.urn) == "urn:::user_key_pair/MY_KEY?user=SOME_USER"
        assert key_pair.fingerprint == PUBLIC_KEY_FINGERPRINT
        assert key_pair._data.owner.name == "USERADMIN"
        assert key_pair._data.disabled is False

    def test_all_properties(self):
        key_pair = res.UserKeyPair(
            name="my_key",
            user="some_user",
            public_key=PUBLIC_KEY,
            owner="SECURITYADMIN",
            role_restriction="some_role",
            days_to_expiry=90,
            expire_rotated_key_pair_after_hours=4,
            disabled=True,
            comment="primary workload key",
        )
        data = key_pair.to_dict()
        assert data == {
            "name": "MY_KEY",
            "user": "SOME_USER",
            "owner": "SECURITYADMIN",
            "public_key": PUBLIC_KEY,
            "fingerprint": PUBLIC_KEY_FINGERPRINT,
            "role_restriction": "SOME_ROLE",
            "days_to_expiry": 90,
            "has_expiration": True,
            "expire_rotated_key_pair_after_hours": 4,
            "disabled": True,
            "comment": "primary workload key",
        }

    def test_requires_user_and_role_restriction(self):
        key_pair = res.UserKeyPair(name="my_key", user="some_user", public_key=PUBLIC_KEY, role_restriction="some_role")
        required = {(ref.resource_type, str(ref.name)) for ref in key_pair.refs}
        assert (ResourceType.USER, "SOME_USER") in required
        assert (ResourceType.ROLE, "SOME_ROLE") in required

    def test_public_key_is_required(self):
        with pytest.raises(ValueError, match="public_key is required"):
            res.UserKeyPair(name="my_key", user="some_user")

    def test_reserved_names_are_rejected(self):
        with pytest.raises(ValueError, match="reserved by Snowflake"):
            res.UserKeyPair(name="public_key_1", user="some_user", public_key=PUBLIC_KEY)

    def test_rotated_out_names_are_rejected(self):
        with pytest.raises(ValueError, match="rotated-out key pair"):
            res.UserKeyPair(name="my_key_rotated_1755000000000", user="some_user", public_key=PUBLIC_KEY)

    def test_days_to_expiry_must_be_positive(self):
        with pytest.raises(ValueError, match="days_to_expiry"):
            res.UserKeyPair(name="my_key", user="some_user", public_key=PUBLIC_KEY, days_to_expiry=0)

    def test_var_public_key_is_resolved_before_the_fingerprint_is_computed(self, session_ctx):
        blueprint = Blueprint(
            resources=[res.UserKeyPair(name="my_key", user="some_user", public_key="{{ var.public_key }}")],
            vars={"public_key": PUBLIC_KEY},
        )
        manifest = blueprint.generate_manifest(session_ctx)
        entry = manifest[KEY_PAIR_URN]
        assert entry.data["public_key"] == PUBLIC_KEY
        assert entry.data["fingerprint"] == PUBLIC_KEY_FINGERPRINT


class TestUserKeyPairShortcut:
    def test_key_pairs_declared_on_a_user(self):
        user = res.User(
            name="some_user",
            type="SERVICE",
            key_pairs=[{"name": "my_key", "public_key": PUBLIC_KEY, "comment": "primary workload key"}],
        )
        key_pairs = [r for r in user.process_shortcuts() if isinstance(r, res.UserKeyPair)]
        assert len(key_pairs) == 1
        assert str(key_pairs[0].urn) == "urn:::user_key_pair/MY_KEY?user=SOME_USER"
        assert key_pairs[0]._data.comment == "primary workload key"

    def test_key_pairs_cannot_redeclare_the_user(self):
        user = res.User(
            name="some_user",
            key_pairs=[{"name": "my_key", "user": "other_user", "public_key": PUBLIC_KEY}],
        )
        with pytest.raises(ValueError, match="cannot also set 'user'"):
            user.process_shortcuts()

    def test_key_pairs_must_be_mappings(self):
        user = res.User(name="some_user", key_pairs=["my_key"])
        with pytest.raises(ValueError, match="Expected a mapping"):
            user.process_shortcuts()


class TestUserKeyPairLifecycle:
    def _create_sql(self, **kwargs):
        key_pair = res.UserKeyPair(name="my_key", user="some_user", public_key=PUBLIC_KEY, **kwargs)
        return key_pair.create_sql()

    def test_create(self):
        assert self._create_sql() == f"ALTER USER SOME_USER ADD KEY PAIR MY_KEY PUBLIC_KEY = $${PUBLIC_KEY}$$"

    def test_create_with_all_options(self):
        sql = self._create_sql(role_restriction="some_role", days_to_expiry=90, comment="primary workload key")
        assert sql == (
            f"ALTER USER SOME_USER ADD KEY PAIR MY_KEY PUBLIC_KEY = $${PUBLIC_KEY}$$ "
            "ROLE_RESTRICTION = $$SOME_ROLE$$ DAYS_TO_EXPIRY = 90 COMMENT = $$primary workload key$$"
        )

    def test_drop(self):
        key_pair = res.UserKeyPair(name="my_key", user="some_user", public_key=PUBLIC_KEY)
        assert key_pair.drop_sql() == "ALTER USER SOME_USER REMOVE KEY PAIR MY_KEY"
        assert key_pair.drop_sql(if_exists=True) == "ALTER USER IF EXISTS SOME_USER REMOVE KEY PAIR MY_KEY"

    def test_update_rotates_on_a_fingerprint_change(self):
        after = res.UserKeyPair(name="my_key", user="some_user", public_key=OTHER_PUBLIC_KEY).to_dict()
        sql = lifecycle.update_resource(
            KEY_PAIR_URN,
            {"fingerprint": after["fingerprint"]},
            res.UserKeyPair.props,
            after=after,
        )
        assert sql == [f"ALTER USER SOME_USER ROTATE KEY PAIR MY_KEY PUBLIC_KEY = $${OTHER_PUBLIC_KEY}$$"]

    def test_update_sets_properties(self):
        sql = lifecycle.update_resource(
            KEY_PAIR_URN,
            {"disabled": True, "comment": "retired"},
            res.UserKeyPair.props,
            after=remote_key_pair(disabled=True, comment="retired"),
        )
        assert sql == ["ALTER USER SOME_USER MODIFY KEY PAIR MY_KEY SET DISABLED = TRUE COMMENT = $$retired$$"]

    def test_update_combines_a_rotation_with_property_changes(self):
        after = res.UserKeyPair(
            name="my_key", user="some_user", public_key=OTHER_PUBLIC_KEY, comment="rotated"
        ).to_dict()
        sql = lifecycle.update_resource(
            KEY_PAIR_URN,
            {"fingerprint": after["fingerprint"], "comment": "rotated"},
            res.UserKeyPair.props,
            after=after,
        )
        assert sql == [
            f"ALTER USER SOME_USER ROTATE KEY PAIR MY_KEY PUBLIC_KEY = $${OTHER_PUBLIC_KEY}$$",
            "ALTER USER SOME_USER MODIFY KEY PAIR MY_KEY SET COMMENT = $$rotated$$",
        ]

    def test_update_without_the_new_public_key_fails_loudly(self):
        with pytest.raises(NotImplementedError, match="public key is missing"):
            lifecycle.update_resource(
                KEY_PAIR_URN,
                {"fingerprint": "SHA256:whatever"},
                res.UserKeyPair.props,
                after=remote_key_pair(public_key=None),
            )

    def test_update_of_an_immutable_attr_fails_loudly(self):
        with pytest.raises(NotImplementedError, match="days_to_expiry"):
            lifecycle.update_resource(
                KEY_PAIR_URN,
                {"days_to_expiry": 30},
                res.UserKeyPair.props,
                after=remote_key_pair(days_to_expiry=30),
            )


class TestUserKeyPairPlan:
    def _manifest(self, session_ctx, key_pair):
        return Blueprint(resources=[key_pair]).generate_manifest(session_ctx)

    def test_no_drift_when_the_key_is_unchanged(self, session_ctx):
        remote = {
            parse_URN("urn::ABCD123:account/ACCOUNT"): {},
            KEY_PAIR_URN: remote_key_pair(has_expiration=True),
        }
        # days_to_expiry itself is never compared -- Snowflake reports an absolute
        # expires_at -- so a key pair registered with an expiry plans nothing.
        key_pair = res.UserKeyPair(name="my_key", user="some_user", public_key=PUBLIC_KEY, days_to_expiry=90)
        assert diff(remote, self._manifest(session_ctx, key_pair)) == []

    def test_adding_an_expiry_to_an_existing_key_pair_is_refused(self, session_ctx):
        remote = {
            parse_URN("urn::ABCD123:account/ACCOUNT"): {},
            KEY_PAIR_URN: remote_key_pair(has_expiration=False),
        }
        key_pair = res.UserKeyPair(name="my_key", user="some_user", public_key=PUBLIC_KEY, days_to_expiry=90)
        with pytest.raises(MarkedForReplacementException, match="expiration of an existing key pair"):
            diff(remote, self._manifest(session_ctx, key_pair))

    def test_an_undeclared_expiry_is_left_alone(self, session_ctx):
        # None means "not managed" everywhere else in snowcap, and it means that here too.
        remote = {
            parse_URN("urn::ABCD123:account/ACCOUNT"): {},
            KEY_PAIR_URN: remote_key_pair(has_expiration=True),
        }
        key_pair = res.UserKeyPair(name="my_key", user="some_user", public_key=PUBLIC_KEY)
        assert diff(remote, self._manifest(session_ctx, key_pair)) == []

    def test_a_new_key_plans_a_rotation(self, session_ctx):
        remote = {
            parse_URN("urn::ABCD123:account/ACCOUNT"): {},
            KEY_PAIR_URN: remote_key_pair(),
        }
        key_pair = res.UserKeyPair(name="my_key", user="some_user", public_key=OTHER_PUBLIC_KEY)
        changes = diff(remote, self._manifest(session_ctx, key_pair))
        assert len(changes) == 1
        assert isinstance(changes[0], UpdateResource)
        assert changes[0].delta == {"fingerprint": OTHER_PUBLIC_KEY_FINGERPRINT}

        commands = flatten_sql_commands(compile_plan_to_sql(session_ctx, changes))
        assert f"ALTER USER SOME_USER ROTATE KEY PAIR MY_KEY PUBLIC_KEY = $${OTHER_PUBLIC_KEY}$$" in commands

    def test_changing_the_role_restriction_is_refused(self, session_ctx):
        remote = {
            parse_URN("urn::ABCD123:account/ACCOUNT"): {},
            KEY_PAIR_URN: remote_key_pair(role_restriction="OLD_ROLE"),
        }
        key_pair = res.UserKeyPair(name="my_key", user="some_user", public_key=PUBLIC_KEY, role_restriction="new_role")
        with pytest.raises(MarkedForReplacementException, match="role restriction"):
            diff(remote, self._manifest(session_ctx, key_pair))

    def test_create_disables_the_key_in_a_follow_up_statement(self, session_ctx):
        remote = {parse_URN("urn::ABCD123:account/ACCOUNT"): {}}
        key_pair = res.UserKeyPair(name="my_key", user="some_user", public_key=PUBLIC_KEY, disabled=True)
        changes = diff(remote, self._manifest(session_ctx, key_pair))
        assert len(changes) == 1
        assert isinstance(changes[0], CreateResource)

        commands = flatten_sql_commands(compile_plan_to_sql(session_ctx, changes))
        assert commands[-2:] == [
            f"ALTER USER SOME_USER ADD KEY PAIR MY_KEY PUBLIC_KEY = $${PUBLIC_KEY}$$",
            "ALTER USER SOME_USER MODIFY KEY PAIR MY_KEY SET DISABLED = TRUE",
        ]

    def test_key_pairs_are_managed_by_the_role_that_manages_the_user(self, session_ctx):
        remote = {parse_URN("urn::ABCD123:account/ACCOUNT"): {}}
        key_pair = res.UserKeyPair(name="my_key", user="some_user", public_key=PUBLIC_KEY)
        change = diff(remote, self._manifest(session_ctx, key_pair))[0]

        role, transfer_ownership = execution_strategy_for_change(
            change, session_ctx["available_roles"], ResourceName("SYSADMIN")
        )
        assert role == ResourceName("USERADMIN")
        assert transfer_ownership is False

    def test_no_ownership_transfer_for_a_custom_owner(self, session_ctx):
        remote = {
            parse_URN("urn::ABCD123:account/ACCOUNT"): {},
            KEY_PAIR_URN: remote_key_pair(),
        }
        key_pair = res.UserKeyPair(
            name="my_key", user="some_user", public_key=PUBLIC_KEY, owner="SECURITYADMIN", comment="managed"
        )
        changes = diff(remote, self._manifest(session_ctx, key_pair))
        assert [type(change) for change in changes] == [UpdateResource]
        assert changes[0].delta == {"comment": "managed"}


class TestUserKeyPairFetch:
    def _show_row(self, **overrides):
        row = {
            "name": "MY_KEY",
            "user_name": "SOME_USER",
            "fingerprint": PUBLIC_KEY_FINGERPRINT,
            "role_scope": None,
            "status": "ACTIVE",
            "comment": None,
            "created_on": "2026-08-01 00:00:00",
            "created_by": "SNOWCAP_SVC",
            "last_used_on": None,
            "expires_at": None,
            "rotated_to": None,
        }
        row.update(overrides)
        return row

    def test_show_output_maps_to_resource_fields(self):
        assert _user_key_pair_to_dict(self._show_row(role_scope="SOME_ROLE", comment="hi")) == {
            "name": "MY_KEY",
            "user": "SOME_USER",
            "fingerprint": PUBLIC_KEY_FINGERPRINT,
            "role_restriction": "SOME_ROLE",
            "disabled": False,
            "has_expiration": False,
            "comment": "hi",
        }

    def test_an_expiring_key_pair_reports_that_it_expires(self):
        row = self._show_row(expires_at="2026-11-01 00:00:00")
        assert _user_key_pair_to_dict(row)["has_expiration"] is True

    def test_disabled_status(self):
        assert _user_key_pair_to_dict(self._show_row(status="DISABLED"))["disabled"] is True

    def test_expired_is_not_disabled(self):
        # Expiration is fixed when the key pair is registered, so an expired key pair is
        # not the `disabled` field drifting. Snowflake reports DISABLED when a key pair is
        # both disabled and expired, so a disabled key never reads back as enabled.
        assert _user_key_pair_to_dict(self._show_row(status="EXPIRED"))["disabled"] is False

    def test_rotated_out_and_reserved_key_pairs_are_not_declarable(self):
        assert _key_pair_is_declarable(self._show_row())
        assert not _key_pair_is_declarable(self._show_row(rotated_to="MY_KEY"))
        # The legacy rsa_public_key / rsa_public_key_2 properties show up under these
        # names; they are managed on the user resource, not as key pairs.
        assert not _key_pair_is_declarable(self._show_row(name="PUBLIC_KEY_1"))
        assert not _key_pair_is_declarable(self._show_row(name="PUBLIC_KEY_2"))

    def test_a_live_key_pair_named_like_a_tombstone_is_still_visible(self):
        # `rotated_to` is what Snowflake sets on a rotated-out key. The generated name is
        # only a convention, and anyone who can register a key pair can imitate it -- if
        # the name were trusted, such a key would be invisible to drift and to sync.
        row = self._show_row(name="MY_KEY_ROTATED_1755000000000", rotated_to=None)
        assert _key_pair_is_declarable(row)

    def test_fetched_state_round_trips_through_the_spec(self):
        data = _user_key_pair_to_dict(self._show_row())
        assert res.UserKeyPair.spec(**data).to_dict(AccountEdition.ENTERPRISE) == remote_key_pair()


class TestUserKeyPairConfig:
    def test_key_pairs_from_yaml_config(self):
        config = {
            "users": [
                {
                    "name": "svc_user",
                    "type": "SERVICE",
                    "key_pairs": [{"name": "my_key", "public_key": PUBLIC_KEY}],
                }
            ],
            "user_key_pairs": [
                {
                    "name": "other_key",
                    "user": "svc_user",
                    "public_key": OTHER_PUBLIC_KEY,
                    "days_to_expiry": 90,
                }
            ],
        }
        resources = collect_blueprint_config(config).resources
        key_pairs = {str(r.fqn): r for r in resources if isinstance(r, res.UserKeyPair)}
        assert set(key_pairs) == {"MY_KEY?user=SVC_USER", "OTHER_KEY?user=SVC_USER"}
        assert key_pairs["OTHER_KEY?user=SVC_USER"]._data.days_to_expiry == 90


class TestUserKeyPairIdentity:
    def test_the_same_key_pair_name_on_two_users(self, session_ctx):
        # A key pair is named within its user, so two users can each have a MY_KEY.
        blueprint = Blueprint(
            resources=[
                res.UserKeyPair(name="my_key", user="user_a", public_key=PUBLIC_KEY),
                res.UserKeyPair(name="my_key", user="user_b", public_key=OTHER_PUBLIC_KEY),
            ]
        )
        manifest = blueprint.generate_manifest(session_ctx)
        assert parse_URN("urn::ABCD123:user_key_pair/MY_KEY?user=USER_A") in manifest.urns
        assert parse_URN("urn::ABCD123:user_key_pair/MY_KEY?user=USER_B") in manifest.urns

    def test_a_genuine_duplicate_is_still_rejected(self, session_ctx):
        blueprint = Blueprint(
            resources=[
                res.UserKeyPair(name="my_key", user="user_a", public_key=PUBLIC_KEY),
                res.UserKeyPair(name="my_key", user="user_a", public_key=OTHER_PUBLIC_KEY),
            ]
        )
        with pytest.raises(DuplicateResourceException):
            blueprint.generate_manifest(session_ctx)

    def test_a_declared_owner_survives_an_update(self, session_ctx):
        remote = {
            parse_URN("urn::ABCD123:account/ACCOUNT"): {},
            KEY_PAIR_URN: remote_key_pair(),
        }
        key_pair = res.UserKeyPair(name="my_key", user="some_user", public_key=OTHER_PUBLIC_KEY, owner="SECURITYADMIN")
        change = diff(remote, Blueprint(resources=[key_pair]).generate_manifest(session_ctx))[0]

        # `owner` isn't fetchable, so remote state carries the default -- the role that
        # runs the rotation has to come from what config declares.
        role, transfer_ownership = execution_strategy_for_change(
            change, session_ctx["available_roles"], ResourceName("SYSADMIN")
        )
        assert role == ResourceName("SECURITYADMIN")
        assert transfer_ownership is False


class TestUserKeyPairPlanFile:
    def test_a_rotation_survives_the_two_step_plan_workflow(self, session_ctx):
        # `snowcap plan --out plan.json` then `snowcap apply --plan plan.json` rebuilds
        # the change from JSON, and the rotation SQL needs the public key from `after`.
        remote = {
            parse_URN("urn::ABCD123:account/ACCOUNT"): {},
            KEY_PAIR_URN: remote_key_pair(),
        }
        key_pair = res.UserKeyPair(name="my_key", user="some_user", public_key=OTHER_PUBLIC_KEY)
        plan = diff(remote, Blueprint(resources=[key_pair]).generate_manifest(session_ctx))

        reloaded = plan_from_dict(json.loads(dump_plan(plan, format="json")))
        commands = flatten_sql_commands(compile_plan_to_sql(session_ctx, reloaded))
        assert f"ALTER USER SOME_USER ROTATE KEY PAIR MY_KEY PUBLIC_KEY = $${OTHER_PUBLIC_KEY}$$" in commands


class TestUserKeyPairRotation:
    def test_rotation_uses_snowflakes_default_grace_period(self):
        after = res.UserKeyPair(name="my_key", user="some_user", public_key=OTHER_PUBLIC_KEY).to_dict()
        sql = lifecycle.update_resource(
            KEY_PAIR_URN, {"fingerprint": after["fingerprint"]}, res.UserKeyPair.props, after=after
        )
        assert sql == [f"ALTER USER SOME_USER ROTATE KEY PAIR MY_KEY PUBLIC_KEY = $${OTHER_PUBLIC_KEY}$$"]

    def test_rotation_can_revoke_the_prior_key_immediately(self):
        # The response to a leaked private key: rotate with no grace period.
        after = res.UserKeyPair(
            name="my_key",
            user="some_user",
            public_key=OTHER_PUBLIC_KEY,
            expire_rotated_key_pair_after_hours=0,
        ).to_dict()
        sql = lifecycle.update_resource(
            KEY_PAIR_URN, {"fingerprint": after["fingerprint"]}, res.UserKeyPair.props, after=after
        )
        assert sql == [
            f"ALTER USER SOME_USER ROTATE KEY PAIR MY_KEY PUBLIC_KEY = $${OTHER_PUBLIC_KEY}$$ "
            "EXPIRE_ROTATED_KEY_PAIR_AFTER_HOURS = 0"
        ]

    def test_rotation_can_widen_the_grace_period(self):
        after = res.UserKeyPair(
            name="my_key",
            user="some_user",
            public_key=OTHER_PUBLIC_KEY,
            expire_rotated_key_pair_after_hours=72,
        ).to_dict()
        sql = lifecycle.update_resource(
            KEY_PAIR_URN, {"fingerprint": after["fingerprint"]}, res.UserKeyPair.props, after=after
        )
        assert sql[0].endswith("EXPIRE_ROTATED_KEY_PAIR_AFTER_HOURS = 72")

    def test_the_grace_period_is_not_part_of_the_add_statement(self):
        # ALTER USER ... ADD KEY PAIR has no such option; it only applies to a rotation.
        key_pair = res.UserKeyPair(
            name="my_key", user="some_user", public_key=PUBLIC_KEY, expire_rotated_key_pair_after_hours=0
        )
        assert "EXPIRE_ROTATED" not in key_pair.create_sql()

    def test_the_grace_period_alone_is_not_a_change(self, session_ctx):
        # It describes the next rotation, not the state of the key pair, so changing it
        # on its own must not plan anything.
        remote = {
            parse_URN("urn::ABCD123:account/ACCOUNT"): {},
            KEY_PAIR_URN: remote_key_pair(),
        }
        key_pair = res.UserKeyPair(
            name="my_key", user="some_user", public_key=PUBLIC_KEY, expire_rotated_key_pair_after_hours=0
        )
        assert diff(remote, Blueprint(resources=[key_pair]).generate_manifest(session_ctx)) == []

    def test_a_negative_grace_period_is_rejected(self):
        with pytest.raises(ValueError, match="expire_rotated_key_pair_after_hours"):
            res.UserKeyPair(
                name="my_key", user="some_user", public_key=PUBLIC_KEY, expire_rotated_key_pair_after_hours=-1
            )

    def test_the_plan_says_the_prior_key_survives(self, session_ctx, caplog):
        remote = {
            parse_URN("urn::ABCD123:account/ACCOUNT"): {},
            KEY_PAIR_URN: remote_key_pair(),
        }
        blueprint = Blueprint(resources=[res.UserKeyPair(name="my_key", user="some_user", public_key=OTHER_PUBLIC_KEY)])
        plan = diff(remote, blueprint.generate_manifest(session_ctx))
        with caplog.at_level(logging.WARNING, logger="snowcap"):
            blueprint._warning_for_nonconforming_plan(session_ctx, plan)
        assert "will be rotated" in caplog.text
        assert "24 hours" in caplog.text

    def test_the_plan_says_when_the_prior_key_is_revoked_immediately(self, session_ctx, caplog):
        remote = {
            parse_URN("urn::ABCD123:account/ACCOUNT"): {},
            KEY_PAIR_URN: remote_key_pair(),
        }
        blueprint = Blueprint(
            resources=[
                res.UserKeyPair(
                    name="my_key",
                    user="some_user",
                    public_key=OTHER_PUBLIC_KEY,
                    expire_rotated_key_pair_after_hours=0,
                )
            ]
        )
        plan = diff(remote, blueprint.generate_manifest(session_ctx))
        with caplog.at_level(logging.WARNING, logger="snowcap"):
            blueprint._warning_for_nonconforming_plan(session_ctx, plan)
        assert "revoked immediately" in caplog.text


class TestLegacyKeyRotation:
    """The rsa_public_key / rsa_public_key_2 properties, which pre-date named key pairs."""

    def _remote_user(self, **overrides):
        fetched = {
            "name": "SVC",
            "login_name": None,
            "display_name": None,
            "first_name": None,
            "middle_name": None,
            "last_name": None,
            "email": None,
            "comment": None,
            "disabled": False,
            "must_change_password": None,
            "default_warehouse": None,
            "default_namespace": None,
            "default_role": None,
            "default_secondary_roles": None,
            "type": "SERVICE",
            "rsa_public_key": PUBLIC_KEY,
            "rsa_public_key_2": None,
            "network_policy": None,
            "owner": "USERADMIN",
        }
        fetched.update(overrides)
        return res.User.spec(**fetched).to_dict(AccountEdition.ENTERPRISE)

    def test_the_second_key_is_compared_not_re_applied_every_plan(self, session_ctx):
        # Staging a second key is the first half of a legacy rotation. It has to settle:
        # once applied, the next plan must be empty.
        remote = {
            parse_URN("urn::ABCD123:account/ACCOUNT"): {},
            parse_URN("urn::ABCD123:user/SVC"): self._remote_user(rsa_public_key_2=OTHER_PUBLIC_KEY),
        }
        user = res.User(name="svc", type="SERVICE", rsa_public_key=PUBLIC_KEY, rsa_public_key_2=OTHER_PUBLIC_KEY)
        assert diff(remote, Blueprint(resources=[user]).generate_manifest(session_ctx)) == []

    def test_staging_a_second_key_plans_one_update(self, session_ctx):
        remote = {
            parse_URN("urn::ABCD123:account/ACCOUNT"): {},
            parse_URN("urn::ABCD123:user/SVC"): self._remote_user(),
        }
        user = res.User(name="svc", type="SERVICE", rsa_public_key=PUBLIC_KEY, rsa_public_key_2=OTHER_PUBLIC_KEY)
        changes = diff(remote, Blueprint(resources=[user]).generate_manifest(session_ctx))
        assert len(changes) == 1
        assert changes[0].delta == {"rsa_public_key_2": OTHER_PUBLIC_KEY}

    def test_a_pem_wrapped_key_matches_what_snowflake_reports(self, session_ctx):
        # DESC USER reports keys without delimiters, and Snowflake's SQL wants them that
        # way, so a key pasted out of a .pub file must not read as drift.
        pem = (
            "-----BEGIN PUBLIC KEY-----\n"
            + "\n".join(PUBLIC_KEY[i : i + 64] for i in range(0, len(PUBLIC_KEY), 64))
            + "\n-----END PUBLIC KEY-----\n"
        )
        remote = {
            parse_URN("urn::ABCD123:account/ACCOUNT"): {},
            parse_URN("urn::ABCD123:user/SVC"): self._remote_user(),
        }
        user = res.User(name="svc", type="SERVICE", rsa_public_key=pem)
        assert diff(remote, Blueprint(resources=[user]).generate_manifest(session_ctx)) == []
        assert f"RSA_PUBLIC_KEY = $${PUBLIC_KEY}$$" in user.create_sql()


class TestUserKeyPairExport:
    def _show_row(self, **overrides):
        row = {
            "name": "MY_KEY",
            "user_name": "SOME_USER",
            "fingerprint": PUBLIC_KEY_FINGERPRINT,
            "role_scope": None,
            "status": "ACTIVE",
            "comment": "primary workload key",
            "created_on": "2026-08-01 00:00:00",
            "created_by": "SNOWCAP_SVC",
            "last_used_on": None,
            "expires_at": None,
            "rotated_to": None,
        }
        row.update(overrides)
        return row

    def test_an_exported_key_pair_loads_once_the_key_is_filled_in(self):
        # Snowflake never returns the key, so the derived fields have to be dropped or the
        # export produces a block the loader refuses outright.
        block = _format_resource_config(
            KEY_PAIR_URN,
            _user_key_pair_to_dict(self._show_row()),
            ResourceType.USER_KEY_PAIR,
        )
        assert "fingerprint" not in block
        assert "has_expiration" not in block
        assert block["public_key"] is None

        with pytest.raises(ValueError, match="public_key is required"):
            res.UserKeyPair(**block)

        key_pair = res.UserKeyPair(**{**block, "public_key": PUBLIC_KEY})
        assert key_pair.fqn == KEY_PAIR_URN.fqn
        assert key_pair._data.comment == "primary workload key"

    def test_a_sweep_export_leaves_key_pairs_out(self):
        assert ResourceType.USER_KEY_PAIR in EXPORT_ONLY_WHEN_ASKED_FOR


class TestUserKeyPairRemoteState:
    def test_the_spec_accepts_every_name_snowflake_can_report(self):
        # The spec deserializes remote state as well as config, so a live key pair named
        # to look rotated-out must round-trip. Refusing it here aborts the whole plan.
        data = _user_key_pair_to_dict(
            {
                "name": "MY_KEY_ROTATED_1755000000000",
                "user_name": "SOME_USER",
                "fingerprint": PUBLIC_KEY_FINGERPRINT,
                "role_scope": None,
                "status": "ACTIVE",
                "comment": None,
                "created_on": "",
                "created_by": "",
                "last_used_on": None,
                "expires_at": None,
                "rotated_to": None,
            }
        )
        assert res.UserKeyPair.spec(**data).name == "MY_KEY_ROTATED_1755000000000"

    def test_config_still_refuses_those_names(self):
        with pytest.raises(ValueError, match="rotated-out key pair"):
            res.UserKeyPair(name="my_key_rotated_1755000000000", user="some_user", public_key=PUBLIC_KEY)
        with pytest.raises(ValueError, match="reserved by Snowflake"):
            res.UserKeyPair(name="public_key_1", user="some_user", public_key=PUBLIC_KEY)
