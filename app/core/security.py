import os
import uuid
from datetime import datetime, timedelta, timezone
from typing import Union

import jwt
from dotenv import load_dotenv
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy.orm import Session

from app.database import get_db
from app.models import User

load_dotenv()

JWT_SECRET_KEY = os.getenv("JWT_SECRET_KEY")

if not JWT_SECRET_KEY:
    raise RuntimeError("JWT_SECRET_KEY is missing from the .env file")

ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 15


def create_access_token(user_id: Union[str, uuid.UUID]) -> str:
    """
    Create a JWT access token for the given user ID.

    Args:
        user_id: The user's UUID (as UUID or string)

    Returns:
        Encoded JWT token string
    """
    # Convert UUID to string if necessary
    if isinstance(user_id, uuid.UUID):
        user_id = str(user_id)

    # Calculate expiry time (15 minutes from now)
    expire = datetime.now(timezone.utc) + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)

    # Create token payload
    payload = {
        "sub": user_id,
        "iat": datetime.now(timezone.utc),
        "exp": expire,
    }

    # Encode and return token
    token = jwt.encode(payload, JWT_SECRET_KEY, algorithm=ALGORITHM)
    return token


def verify_access_token(token: str) -> dict:
    """
    Verify and decode a JWT access token.

    Args:
        token: The JWT token string to verify

    Returns:
        Decoded token claims (dictionary)

    Raises:
        jwt.InvalidTokenError: If the token is invalid, expired, or malformed
        jwt.ExpiredSignatureError: If the token has expired
        jwt.InvalidSignatureError: If the token signature is invalid
    """
    # Decode and verify the token, requiring sub, iat, and exp claims
    claims = jwt.decode(
        token,
        JWT_SECRET_KEY,
        algorithms=[ALGORITHM],
        options={"require": ["sub", "iat", "exp"]},
    )
    return claims


# FastAPI security scheme for Bearer tokens
security = HTTPBearer()


def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(security),
    db: Session = Depends(get_db),
) -> "User":
    """
    FastAPI dependency to get the currently authenticated user from a JWT access token.

    Args:
        credentials: The Bearer token credentials from the Authorization header
        db: The database session

    Returns:
        The authenticated User object

    Raises:
        HTTPException: If the token is invalid, expired, or the user doesn't exist
    """
    # Extract token from credentials
    token = credentials.credentials

    # Verify the token
    try:
        claims = verify_access_token(token)
    except jwt.ExpiredSignatureError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token has expired",
        )
    except jwt.InvalidSignatureError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token signature",
        )
    except jwt.InvalidTokenError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token",
        )

    # Extract user ID from sub claim
    user_id_str = claims.get("sub")
    if not user_id_str:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token payload",
        )

    # Convert to UUID
    try:
        user_id = uuid.UUID(user_id_str)
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid user ID in token",
        )

    # Fetch user from database
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found",
        )

    return user
