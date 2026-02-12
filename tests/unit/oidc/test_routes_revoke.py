"""Tests for the OAuth revocation endpoint."""

from httpx import AsyncClient


class TestRevoke:
    """Tests for POST /oauth/revoke."""

    async def test_revoke_unknown_token_succeeds(self, client: AsyncClient) -> None:
        resp = await client.post(
            "/oauth/revoke",
            data={"token": "unknown-token-value"},
        )
        assert resp.status_code == 200
