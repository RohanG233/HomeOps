import uuid
from datetime import datetime, timedelta, timezone

import jwt
import pytest
from fastapi import HTTPException
from fastapi.security import HTTPAuthorizationCredentials
from sqlalchemy.orm import Session

from app.core.security import create_access_token, get_current_user, JWT_SECRET_KEY, ALGORITHM
from app.database import SessionLocal
from app.models import User


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
    """Create a test user for authentication tests."""
    from argon2 import PasswordHasher

    password_hasher = PasswordHasher()
    user = User(
        username="testuser",
        email=f"test-{uuid.uuid4()}@example.com",
        password_hash=password_hasher.hash("Password123"),
        household_id=None,
        role="member",
        is_platform_admin=False,
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return user


def test_get_current_user_valid_token(test_user: User):
    """Test that get_current_user returns user for valid token."""
    # Create a valid access token
    token = create_access_token(test_user.id)

    # Create a mock dependency call
    from fastapi.security import HTTPAuthorizationCredentials

    credentials = HTTPAuthorizationCredentials(
        scheme="bearer",
        credentials=token,
    )

    # Use the dependency
    db = SessionLocal()
    try:
        user = get_current_user(credentials=credentials, db=db)
        assert user.id == test_user.id
        assert user.email == test_user.email
    finally:
        db.close()


def test_get_current_user_expired_token(test_user: User):
    """Test that get_current_user raises 401 for expired token."""
    # Create an expired token manually
    past_time = datetime.now(timezone.utc) - timedelta(minutes=20)
    payload = {
        "sub": str(test_user.id),
        "iat": past_time,
        "exp": past_time,
    }

    token = jwt.encode(payload, JWT_SECRET_KEY, algorithm=ALGORITHM)

    credentials = HTTPAuthorizationCredentials(
        scheme="bearer",
        credentials=token,
    )

    db = SessionLocal()
    try:
        with pytest.raises(HTTPException) as exc_info:
            get_current_user(credentials=credentials, db=db)
        assert exc_info.value.status_code == 401
        assert "expired" in str(exc_info.value.detail).lower()
    finally:
        db.close()


def test_get_current_user_invalid_token():
    """Test that get_current_user raises 401 for invalid token."""
    credentials = HTTPAuthorizationCredentials(
        scheme="bearer",
        credentials="invalid.token.here",
    )

    db = SessionLocal()
    try:
        with pytest.raises(HTTPException) as exc_info:
            get_current_user(credentials=credentials, db=db)
        assert exc_info.value.status_code == 401
    finally:
        db.close()


def test_get_current_user_nonexistent_user():
    """Test that get_current_user raises 401 if user doesn't exist."""
    # Create a token for a non-existent user
    fake_user_id = uuid.uuid4()
    token = create_access_token(fake_user_id)

    credentials = HTTPAuthorizationCredentials(
        scheme="bearer",
        credentials=token,
    )

    db = SessionLocal()
    try:
        with pytest.raises(HTTPException) as exc_info:
            get_current_user(credentials=credentials, db=db)
        assert exc_info.value.status_code == 401
        assert "not found" in str(exc_info.value.detail).lower()
    finally:
        db.close()


def test_get_current_user_malformed_user_id(test_user: User):
    """Test that get_current_user raises 401 for malformed user ID in token."""
    # Create a token with invalid user ID
    payload = {
        "sub": "not-a-uuid",
        "iat": datetime.now(timezone.utc),
        "exp": datetime.now(timezone.utc) + timedelta(minutes=15),
    }

    token = jwt.encode(payload, JWT_SECRET_KEY, algorithm=ALGORITHM)

    credentials = HTTPAuthorizationCredentials(
        scheme="bearer",
        credentials=token,
    )

    db = SessionLocal()
    try:
        with pytest.raises(HTTPException) as exc_info:
            get_current_user(credentials=credentials, db=db)
        assert exc_info.value.status_code == 401
    finally:
        db.close()
