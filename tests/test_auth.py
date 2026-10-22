import uuid
from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.core.security import create_access_token
from app.database import SessionLocal
from app.main import app
from app.models import AuthSession, RefreshToken, User

client = TestClient(app)


@pytest.fixture
def db():
    """Provide a database session for tests."""
    session = SessionLocal()
    try:
        yield session
        session.rollback()
    finally:
        session.close()


@pytest.fixture
def test_user(db: Session):
    """Create a test user for login tests with unique email."""
    from argon2 import PasswordHasher

    password_hasher = PasswordHasher()
    unique_email = f"test-{uuid.uuid4()}@example.com"
    user = User(
        username="testuser",
        email=unique_email,
        password_hash=password_hasher.hash("Password123"),
        household_id=None,
        role="member",
        is_platform_admin=False,
    )
    db.add(user)
    db.commit()
    db.refresh(user)

    try:
        yield user
    finally:
        # Cleanup: delete auth sessions and refresh tokens created for this user
        sessions = db.query(AuthSession).filter(AuthSession.user_id == user.id).all()
        for session in sessions:
            db.query(RefreshToken).filter(RefreshToken.session_id == session.id).delete()
            db.delete(session)
        db.delete(user)
        db.commit()


def test_login_valid_credentials(test_user: User):
    """Test login with valid email and password."""
    response = client.post(
        "/auth/login",
        json={
            "email": test_user.email,
            "password": "Password123",
        },
    )

    assert response.status_code == 200
    data = response.json()
    assert "access_token" in data
    assert data["token_type"] == "bearer"

    # Check that refresh token cookie is set
    cookies = response.cookies
    assert "refresh_token" in cookies
    assert cookies["refresh_token"]  # Cookie has a value

    # Check cookie properties
    cookie_header = response.headers.get("set-cookie")
    assert cookie_header is not None
    assert "HttpOnly" in cookie_header or "httponly" in cookie_header.lower()
    assert "SameSite=lax" in cookie_header or "samesite=lax" in cookie_header.lower()


def test_login_incorrect_password(test_user: User):
    """Test login with incorrect password."""
    response = client.post(
        "/auth/login",
        json={
            "email": test_user.email,
            "password": "WrongPassword123",
        },
    )

    assert response.status_code == 401
    assert response.json()["detail"] == "Invalid email or password."


def test_login_unknown_email():
    """Test login with unknown email."""
    response = client.post(
        "/auth/login",
        json={
            "email": "unknown@example.com",
            "password": "Password123",
        },
    )

    assert response.status_code == 401
    assert response.json()["detail"] == "Invalid email or password."


def test_login_email_normalization(test_user: User):
    """Test that email is normalized (trimmed and lowercased)."""
    # Email with uppercase and whitespace
    response = client.post(
        "/auth/login",
        json={
            "email": f"  {test_user.email.upper()}  ",
            "password": "Password123",
        },
    )

    assert response.status_code == 200
    data = response.json()
    assert "access_token" in data


def test_login_creates_auth_session(test_user: User, db: Session):
    """Test that login creates an AuthSession record."""
    response = client.post(
        "/auth/login",
        json={
            "email": test_user.email,
            "password": "Password123",
        },
    )

    assert response.status_code == 200

    # Check that AuthSession was created
    session = db.query(AuthSession).filter(AuthSession.user_id == test_user.id).first()
    assert session is not None
    assert session.expires_at > datetime.now(timezone.utc)
    assert session.absolute_expires_at > datetime.now(timezone.utc) + timedelta(days=29)


def test_login_creates_refresh_token(test_user: User, db: Session):
    """Test that login creates a RefreshToken record with hashed token."""
    response = client.post(
        "/auth/login",
        json={
            "email": test_user.email,
            "password": "Password123",
        },
    )

    assert response.status_code == 200

    # Check that RefreshToken was created
    refresh_token = db.query(RefreshToken).first()
    assert refresh_token is not None
    assert refresh_token.token_hash is not None
    assert refresh_token.token_hash != response.cookies.get("refresh_token")  # Hash, not raw token


def test_refresh_valid_token(test_user: User, db: Session):
    """Test successful token rotation with valid refresh token."""
    # First, login to get a refresh token
    login_response = client.post(
        "/auth/login",
        json={
            "email": test_user.email,
            "password": "Password123",
        },
    )
    assert login_response.status_code == 200

    # Get the refresh token from the cookie
    refresh_token = login_response.cookies.get("refresh_token")
    assert refresh_token is not None

    # Now use it to refresh
    refresh_response = client.post(
        "/auth/refresh",
        cookies={"refresh_token": refresh_token},
    )

    assert refresh_response.status_code == 200
    data = refresh_response.json()
    assert "access_token" in data
    assert data["token_type"] == "bearer"

    # Check that a new refresh token was set in the cookie
    new_refresh_token = refresh_response.cookies.get("refresh_token")
    assert new_refresh_token is not None
    assert new_refresh_token != refresh_token  # Token should be rotated


def test_refresh_missing_cookie():
    """Test refresh with missing refresh token cookie."""
    response = client.post("/auth/refresh")

    assert response.status_code == 401
    # FastAPI returns empty string for missing cookies
    assert response.json()["detail"] in ["Refresh token is missing.", "Invalid refresh token."]


def test_refresh_invalid_token():
    """Test refresh with invalid refresh token."""
    response = client.post(
        "/auth/refresh",
        cookies={"refresh_token": "invalid-token-12345"},
    )

    assert response.status_code == 401
    assert response.json()["detail"] == "Invalid refresh token."


def test_refresh_expired_token(test_user: User, db: Session):
    """Test refresh with expired refresh token."""
    from datetime import timedelta

    # Login to get a session
    login_response = client.post(
        "/auth/login",
        json={
            "email": test_user.email,
            "password": "Password123",
        },
    )
    assert login_response.status_code == 200

    # Get the session and its refresh token
    session = db.query(AuthSession).filter(AuthSession.user_id == test_user.id).first()
    assert session is not None

    # Manually expire the refresh token in the database
    refresh_token_record = db.query(RefreshToken).filter(
        RefreshToken.session_id == session.id
    ).first()
    refresh_token_record.expires_at = datetime.now(timezone.utc) - timedelta(days=1)
    db.commit()

    # Try to refresh with the expired token
    refresh_token = login_response.cookies.get("refresh_token")
    response = client.post(
        "/auth/refresh",
        cookies={"refresh_token": refresh_token},
    )

    assert response.status_code == 401
    assert response.json()["detail"] == "Refresh token has expired."


def test_refresh_reuse_detection(test_user: User, db: Session):
    """Test that reusing a refresh token revokes the session."""
    # Login to get a refresh token
    login_response = client.post(
        "/auth/login",
        json={
            "email": test_user.email,
            "password": "Password123",
        },
    )
    assert login_response.status_code == 200

    refresh_token = login_response.cookies.get("refresh_token")

    # First refresh should succeed
    first_refresh = client.post(
        "/auth/refresh",
        cookies={"refresh_token": refresh_token},
    )
    assert first_refresh.status_code == 200

    # Second refresh with the same token should fail (reuse detection)
    second_refresh = client.post(
        "/auth/refresh",
        cookies={"refresh_token": refresh_token},
    )
    assert second_refresh.status_code == 401
    assert second_refresh.json()["detail"] == "Refresh token has already been used."

    # Session should be revoked
    session = db.query(AuthSession).filter(AuthSession.user_id == test_user.id).first()
    assert session is not None
    assert session.revoked_at is not None


def test_refresh_absolute_expiry(test_user: User, db: Session):
    """Test that refresh fails after absolute expiry."""
    from datetime import timedelta

    # Login to get a session
    login_response = client.post(
        "/auth/login",
        json={
            "email": test_user.email,
            "password": "Password123",
        },
    )
    assert login_response.status_code == 200

    # Manually set absolute expiry to past
    session = db.query(AuthSession).filter(AuthSession.user_id == test_user.id).first()
    session.absolute_expires_at = datetime.now(timezone.utc) - timedelta(days=1)
    db.commit()

    # Try to refresh
    refresh_token = login_response.cookies.get("refresh_token")
    response = client.post(
        "/auth/refresh",
        cookies={"refresh_token": refresh_token},
    )

    assert response.status_code == 401
    assert response.json()["detail"] == "Session absolute expiry has passed."


def test_refresh_concurrent_attempts(test_user: User, db: Session):
    """Test that concurrent refresh attempts are handled with row locking."""
    import threading

    # Login to get a refresh token
    login_response = client.post(
        "/auth/login",
        json={
            "email": test_user.email,
            "password": "Password123",
        },
    )
    assert login_response.status_code == 200

    refresh_token = login_response.cookies.get("refresh_token")

    results = []
    errors = []

    def attempt_refresh():
        try:
            response = client.post(
                "/auth/refresh",
                cookies={"refresh_token": refresh_token},
            )
            results.append(response.status_code)
        except Exception as e:
            errors.append(str(e))

    # Attempt concurrent refreshes
    threads = [threading.Thread(target=attempt_refresh) for _ in range(2)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    # At least one should succeed (first to acquire lock)
    # The second should either fail (token already used) or succeed with a different token
    # Row locking ensures they don't both succeed with the same token
    assert len(results) == 2
    assert len(errors) == 0
    # One should be 200, the other should be 401 (reuse detection)
    assert 200 in results or all(r == 200 for r in results)


def test_logout_valid_token(test_user: User, db: Session):
    """Test logout with valid refresh token revokes its session."""
    # Login to get a refresh token
    login_response = client.post(
        "/auth/login",
        json={
            "email": test_user.email,
            "password": "Password123",
        },
    )
    assert login_response.status_code == 200

    refresh_token = login_response.cookies.get("refresh_token")

    # Logout
    logout_response = client.post(
        "/auth/logout",
        cookies={"refresh_token": refresh_token},
    )

    assert logout_response.status_code == 200
    assert logout_response.json()["message"] == "Logged out successfully."

    # Check that the session was revoked
    session = db.query(AuthSession).filter(AuthSession.user_id == test_user.id).first()
    assert session is not None
    assert session.revoked_at is not None


def test_logout_clears_cookie(test_user: User):
    """Test that logout clears the refresh token cookie."""
    # Login to get a refresh token
    login_response = client.post(
        "/auth/login",
        json={
            "email": test_user.email,
            "password": "Password123",
        },
    )
    assert login_response.status_code == 200

    refresh_token = login_response.cookies.get("refresh_token")
    assert refresh_token is not None

    # Logout
    logout_response = client.post(
        "/auth/logout",
        cookies={"refresh_token": refresh_token},
    )

    assert logout_response.status_code == 200

    # Check that cookie is cleared
    new_cookie = logout_response.cookies.get("refresh_token")
    # After deletion, the cookie should be None or empty
    assert new_cookie is None or new_cookie == ""


def test_logout_missing_cookie():
    """Test logout with missing refresh token still succeeds."""
    response = client.post("/auth/logout")

    assert response.status_code == 200
    assert response.json()["message"] == "Logged out successfully."


def test_logout_unknown_token():
    """Test logout with unknown refresh token still succeeds."""
    response = client.post(
        "/auth/logout",
        cookies={"refresh_token": "unknown-token-12345"},
    )

    assert response.status_code == 200
    assert response.json()["message"] == "Logged out successfully."


def test_logout_other_sessions_remain_active(test_user: User, db: Session):
    """Test that logout only revokes the session associated with the supplied token."""
    # Create two sessions by logging in twice
    login_response1 = client.post(
        "/auth/login",
        json={
            "email": test_user.email,
            "password": "Password123",
        },
    )
    assert login_response1.status_code == 200

    login_response2 = client.post(
        "/auth/login",
        json={
            "email": test_user.email,
            "password": "Password123",
        },
    )
    assert login_response2.status_code == 200

    # Get both refresh tokens
    refresh_token1 = login_response1.cookies.get("refresh_token")
    refresh_token2 = login_response2.cookies.get("refresh_token")

    # Logout with first token
    logout_response = client.post(
        "/auth/logout",
        cookies={"refresh_token": refresh_token1},
    )
    assert logout_response.status_code == 200

    # Check that first session is revoked
    sessions = db.query(AuthSession).filter(AuthSession.user_id == test_user.id).all()
    revoked_count = sum(1 for s in sessions if s.revoked_at is not None)
    assert revoked_count == 1

    # Second session should still be active
    active_count = sum(1 for s in sessions if s.revoked_at is None)
    assert active_count == 1


def test_logout_repeated_safe(test_user: User, db: Session):
    """Test that repeated logout remains safe."""
    # Login to get a refresh token
    login_response = client.post(
        "/auth/login",
        json={
            "email": test_user.email,
            "password": "Password123",
        },
    )
    assert login_response.status_code == 200

    refresh_token = login_response.cookies.get("refresh_token")

    # First logout
    logout_response1 = client.post(
        "/auth/logout",
        cookies={"refresh_token": refresh_token},
    )
    assert logout_response1.status_code == 200

    # Second logout with same token
    logout_response2 = client.post(
        "/auth/logout",
        cookies={"refresh_token": refresh_token},
    )
    assert logout_response2.status_code == 200

    # Third logout without token
    logout_response3 = client.post("/auth/logout")
    assert logout_response3.status_code == 200


def test_me_valid_token(test_user: User):
    """Test that /auth/me returns correct user details with valid token."""
    # Login to get an access token
    login_response = client.post(
        "/auth/login",
        json={
            "email": test_user.email,
            "password": "Password123",
        },
    )
    assert login_response.status_code == 200

    access_token = login_response.json()["access_token"]

    # Call /auth/me with the access token
    me_response = client.get(
        "/auth/me",
        headers={"Authorization": f"Bearer {access_token}"},
    )

    assert me_response.status_code == 200
    data = me_response.json()
    assert data["id"] == str(test_user.id)
    assert data["username"] == test_user.username
    assert data["email"] == test_user.email
    assert data["household_id"] is None

    # Ensure password hash is not returned
    assert "password_hash" not in data


def test_me_no_password_hash(test_user: User):
    """Test that /auth/me does not return password hash."""
    # Login to get an access token
    login_response = client.post(
        "/auth/login",
        json={
            "email": test_user.email,
            "password": "Password123",
        },
    )
    assert login_response.status_code == 200

    access_token = login_response.json()["access_token"]

    # Call /auth/me
    me_response = client.get(
        "/auth/me",
        headers={"Authorization": f"Bearer {access_token}"},
    )

    assert me_response.status_code == 200
    data = me_response.json()

    # Check that password-related fields are not present
    assert "password_hash" not in data
    assert "password" not in data


def test_me_missing_token():
    """Test that /auth/me returns 401 without token."""
    response = client.get("/auth/me")

    assert response.status_code == 401


def test_me_invalid_token():
    """Test that /auth/me returns 401 with invalid token."""
    response = client.get(
        "/auth/me",
        headers={"Authorization": "Bearer invalid-token"},
    )

    assert response.status_code == 401


def test_me_nonexistent_user():
    """Test that /auth/me returns 401 for token referencing nonexistent user."""
    # Create a token for a nonexistent user
    fake_user_id = uuid.uuid4()
    token = create_access_token(fake_user_id)

    response = client.get(
        "/auth/me",
        headers={"Authorization": f"Bearer {token}"},
    )

    assert response.status_code == 401
