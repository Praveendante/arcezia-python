"""The client's action binding must equal the one the service computes.

The service returns `action_binding` on every verdict; a backend that mints an
approval for exactly that action passes it as the token's `act` claim. The two
sides never share code, so both pin the same golden vector.
"""
from __future__ import annotations

from arcezia.signing import action_binding

GOLDEN_ARGS = ("execute_sql", "database_ops",
               "UPDATE customers SET tier='pro' WHERE id = 42", {"id": 42, "tier": "pro"})
GOLDEN = "19c848c03cec83c30067437ef708c39a86319d8c28174e8aa7fbd44242b9b31b"


def test_golden_vector_matches_the_engine():
    assert action_binding(*GOLDEN_ARGS) == GOLDEN


def test_parameters_are_part_of_the_identity():
    t, d, desc, params = GOLDEN_ARGS
    assert action_binding(t, d, desc, params) != action_binding(t, d, desc, {"id": 43, "tier": "pro"})
    assert action_binding(t, d, desc, {"tier": "pro", "id": 42}) == action_binding(t, d, desc, params)


def test_mint_token_carries_the_binding_as_act():
    import base64, json
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from arcezia.signing import mint_token
    tok = mint_token(Ed25519PrivateKey.generate(), api_key_id=26, token_type="user",
                     session_id="sess-1", action=GOLDEN)
    payload = tok.split(".")[0]
    claims = json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))
    assert claims["act"] == GOLDEN and claims["typ"] == "user" and claims["acct"] == 26
