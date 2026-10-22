import uuid
import pytest
import jwt
from datetime import datetime, timedelta, timezone
from app.core.security import create_access_token, verify_access_token


def test_create_and_verify_token():
    """Test that create_access_token() creates a token that verify_access_token() accepts."""
    user_id = uuid.uuid4()
    token = create_access_token(user_id)

    # Token should be accepted
    claims = verify_access_token(token)

    # Decoded sub should match the supplied user ID
    assert claims["sub"] == str(user_id)

    # iat and exp should be present
    assert "iat" in claims
    assert "exp" in claims


def test_token_expiry_is_15_minutes():
    """Test that expiry is approximately 15 minutes after issuance."""
    from app.core.security import ACCESS_TOKEN_EXPIRE_MINUTES

    user_id = uuid.uuid4()
    created_at = datetime.now(timezone.utc)
    token = create_access_token(user_id)

    claims = verify_access_token(token)

    # Verify expiry is approximately 15 minutes from now
    exp_time = datetime.fromtimestamp(claims["exp"], tz=timezone.utc)
    expected_exp = created_at + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)

    # Allow 1 second tolerance
    time_diff = abs((exp_time - expected_exp).total_seconds())
    assert time_diff < 1.0


def test_token_signed_with_different_secret():
    """Test that a token signed with a different secret is rejected."""
    user_id = uuid.uuid4()
    expire = datetime.now(timezone.utc) + timedelta(minutes=15)

    payload = {
        "sub": str(user_id),
        "iat": datetime.now(timezone.utc),
        "exp": expire,
    }

    # Sign with a different secret
    different_secret = "different-secret-key-12345"
    token = jwt.encode(payload, different_secret, algorithm="HS256")

    with pytest.raises(jwt.InvalidSignatureError):
        verify_access_token(token)


def test_malformed_token_rejected():
    """Test that a malformed token is rejected."""
    malformed_tokens = [
        "not.a.token",
        "",
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9",  # incomplete base64
    ]

    for token in malformed_tokens:
        with pytest.raises(jwt.InvalidTokenError):
            verify_access_token(token)


def test_token_missing_required_claim_rejected():
    """Test that a token missing a required claim is rejected."""
    from app.core.security import JWT_SECRET_KEY, ALGORITHM

    # Create a token without the 'exp' claim
    payload = {
        "sub": str(uuid.uuid4()),
        "iat": datetime.now(timezone.utc).timestamp(),
    }

    token = jwt.encode(payload, JWT_SECRET_KEY, algorithm=ALGORITHM)

    with pytest.raises(jwt.InvalidTokenError):
        verify_access_token(token)


def test_expired_token_rejected():
    """Test that an expired token is rejected (without waiting 15 minutes)."""
    from app.core.security import JWT_SECRET_KEY, ALGORITHM

    user_id = str(uuid.uuid4())
    past_time = datetime.now(timezone.utc) - timedelta(minutes=20)

    payload = {
        "sub": user_id,
        "iat": past_time,
        "exp": past_time,
    }

    token = jwt.encode(payload, JWT_SECRET_KEY, algorithm=ALGORITHM)

    with pytest.raises(jwt.ExpiredSignatureError):
        verify_access_token(token)
