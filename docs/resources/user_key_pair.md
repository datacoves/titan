---
description: >-
  A named key pair registered for a user, used for key-pair authentication.
---

# UserKeyPair

[Snowflake Documentation](https://docs.snowflake.com/en/sql-reference/sql/alter-user-add-key-pair) | Snowcap CLI label: `user_key_pair`

A named key pair registered for a user, used for key-pair authentication.

Named key pairs are the recommended alternative to the legacy `rsa_public_key` and `rsa_public_key_2` user properties: a user can hold up to 10 of them, and each one can carry its own role restriction, expiration, and comment.

Snowflake never returns the public key itself, only its SHA-256 fingerprint, so Snowcap compares the fingerprint of the configured key against the one Snowflake reports.

## Examples

### YAML

Key pairs can be declared on their own:

```yaml
user_key_pairs:
  - name: my_key
    user: some_user
    public_key: MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgK...
    comment: primary workload key
```

...or inline on the user that owns them:

```yaml
users:
  - name: some_user
    type: SERVICE
    key_pairs:
      - name: my_key
        public_key: MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgK...
      - name: scoped_key
        public_key: MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgK...
        role_restriction: some_role
        days_to_expiry: 90
```

### Python

```python
key_pair = UserKeyPair(
    name="my_key",
    user="some_user",
    public_key="MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgK...",
    comment="primary workload key",
)
```


## Rotating a key

Change `public_key` and apply. Snowcap plans `ALTER USER ... ROTATE KEY PAIR`, which replaces the stored key while keeping the key pair's name, role restriction, expiration, and comment:

```yaml
user_key_pairs:
  - name: my_key
    user: some_user
    public_key: <the new public key>   # was: <the old public key>
```

The prior key stays valid for a grace period so clients that haven't picked up the new key keep authenticating — 24 hours by default. Snowflake retains it under a generated `<name>_ROTATED_<epoch_ms>` name until it expires, and Snowcap leaves it alone rather than removing it early. The plan says so explicitly when it contains a rotation.

**Responding to a leaked private key.** Set `expire_rotated_key_pair_after_hours: 0` so the rotation revokes the old key immediately instead of leaving it usable for a day:

```yaml
user_key_pairs:
  - name: my_key
    user: some_user
    public_key: <the new public key>
    expire_rotated_key_pair_after_hours: 0
```

The field describes how the *next* rotation behaves, so changing it on its own plans nothing. Rotated-out keys count against the per-user limit of 10 until they expire.

## Fields

* `name` (string, required) - The name of the key pair. `PUBLIC_KEY_1` and `PUBLIC_KEY_2` are reserved by Snowflake for the legacy user properties and cannot be used.
* `user` (string or [User](user.md), required) - The user the key pair is registered for.
* `public_key` (string, required) - The public key, with or without PEM delimiters. RSA keys and EC keys on the P-256, P-384, and P-521 curves are supported.
* `owner` (string or [Role](role.md)) - The role that manages the user, and therefore the role Snowcap runs the `ALTER USER` statements as. Defaults to "USERADMIN".
* `role_restriction` (string or [Role](role.md)) - The role a session authenticated with this key pair is restricted to. The role must already be granted to the user.
* `days_to_expiry` (int) - The number of days the key pair can be used for authentication. Must be 1 or greater. Defaults to no expiration.
* `expire_rotated_key_pair_after_hours` (int) - How many hours the prior key stays valid after a rotation. `0` revokes it immediately. Defaults to Snowflake's 24 hours. Only applies to a rotation, never to registering a key pair.
* `disabled` (bool) - Whether the key pair is disabled. A disabled key pair keeps its metadata but cannot authenticate. Defaults to False.
* `comment` (string) - A comment for the key pair.

## Notes

* Managing key pairs requires `OWNERSHIP` of the user or the `MODIFY PROGRAMMATIC AUTHENTICATION METHODS` privilege on it.
* `role_restriction` and `days_to_expiry` are fixed when the key pair is registered. Snowflake offers no way to change them, so Snowcap fails the plan and tells you to remove the key pair, apply, and add it back. That covers a changed `role_restriction`, and an expiration added to or dropped from an existing key pair. A change to the *length* of an existing expiration is not detected, because Snowflake reports an absolute expiration timestamp rather than the relative value that was registered.
* A key pair past its expiration reports as expired rather than disabled, which Snowcap does not treat as drift on `disabled`.
