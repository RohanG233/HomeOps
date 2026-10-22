import os
import secrets
import hashlib
from datetime import datetime, timedelta, timezone

from argon2 import PasswordHasher
from fastapi import APIRouter, Cookie, Depends, HTTPException, Response, status
from sqlalchemy.orm import Session

from app.core.security import create_access_token, get_current_user
from app.database import get_db
from app.models import AuthSession, RefreshToken, User
from app.schemas.auth import LoginRequest, LoginResponse, MeResponse, SignupRequest, SignupResponse

router = APIRouter()
password_hasher = PasswordHasher()

# Cookie security setting
SECURE_COOKIES = os.getenv("SECURE_COOKIES", "false").lower() == "true"


@router.post("/signup", response_model=SignupResponse, status_code=status.HTTP_201_CREATED)
def signup(request: SignupRequest, db: Session = Depends(get_db)):
    # Normalize email: trim whitespace and convert to lowercase
    normalized_email = request.email.strip().lower()

    # Check if email already exists
    existing_user = db.query(User).filter(User.email == normalized_email).first()
    if existing_user:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="This email is already registered."
        )

    # Hash the password using Argon2id
    password_hash = password_hasher.hash(request.password)

    # Create new user
    new_user = User(
        username=request.username,
        email=normalized_email,
        password_hash=password_hash,
        household_id=None,
        role="member",
        is_platform_admin=False,
    )

    try:
        db.add(new_user)
        db.commit()
        db.refresh(new_user)
    except Exception:
        db.rollback()
        raise

    # Return response with user data
    return SignupResponse(
        id=new_user.id,
        username=new_user.username,
        email=new_user.email,
    )


@router.post("/login", response_model=LoginResponse, status_code=status.HTTP_200_OK)
def login(request: LoginRequest, response: Response, db: Session = Depends(get_db)):
    # Normalize email: trim whitespace and convert to lowercase
    normalized_email = request.email.strip().lower()

    # Find user by email
    user = db.query(User).filter(User.email == normalized_email).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password."
        )

    # Verify password
    try:
        if not password_hasher.verify(user.password_hash, request.password):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid email or password."
            )
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password."
        )

    # Calculate expiry times
    now = datetime.now(timezone.utc)
    session_expires_at = now + timedelta(days=7)
    absolute_expires_at = now + timedelta(days=30)

    # Create auth session
    auth_session = AuthSession(
        user_id=user.id,
        device_label=None,
        expires_at=session_expires_at,
        absolute_expires_at=absolute_expires_at,
    )

    # Generate cryptographically secure refresh token
    refresh_token = secrets.token_urlsafe(32)

    # Hash the refresh token using SHA-256
    token_hash = hashlib.sha256(refresh_token.encode()).hexdigest()

    try:
        # Add and flush to get the session ID
        db.add(auth_session)
        db.flush()

        # Create refresh token record with the session ID
        refresh_token_record = RefreshToken(
            session_id=auth_session.id,
            token_hash=token_hash,
            expires_at=session_expires_at,
        )
        db.add(refresh_token_record)

        # Commit both records together
        db.commit()
        db.refresh(auth_session)
        db.refresh(refresh_token_record)
    except Exception:
        db.rollback()
        raise

    # Generate JWT access token
    access_token = create_access_token(user.id)

    # Set refresh token in HttpOnly cookie
    response.set_cookie(
        key="refresh_token",
        value=refresh_token,
        httponly=True,
        samesite="lax",
        secure=SECURE_COOKIES,
        max_age=7 * 24 * 60 * 60,  # 7 days in seconds
    )

    # Return access token in response body
    return LoginResponse(
        access_token=access_token,
        token_type="bearer",
    )


@router.post("/refresh", response_model=LoginResponse, status_code=status.HTTP_200_OK)
def refresh(
    response: Response,
    db: Session = Depends(get_db),
    refresh_token: str | None = Cookie(None),
):
    # Check if refresh token cookie is present
    if refresh_token is None or refresh_token == "":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Refresh token is missing."
        )

    # Hash the supplied token
    token_hash = hashlib.sha256(refresh_token.encode()).hexdigest()

    # Look up the refresh token record with row locking for concurrency control
    refresh_token_record = db.query(RefreshToken).filter(
        RefreshToken.token_hash == token_hash
    ).with_for_update().first()

    if not refresh_token_record:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid refresh token."
        )

    # Check if token has already been used (reuse detection)
    if refresh_token_record.used_at is not None:
        # Revoke the session to prevent further token reuse
        session = db.query(AuthSession).filter(
            AuthSession.id == refresh_token_record.session_id
        ).first()
        if session:
            session.revoked_at = datetime.now(timezone.utc)
            db.commit()
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Refresh token has already been used."
        )

    # Get the session with row locking
    session = db.query(AuthSession).filter(
        AuthSession.id == refresh_token_record.session_id
    ).with_for_update().first()

    if not session:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Session not found."
        )

    # Validate session
    now = datetime.now(timezone.utc)

    # Check if session is revoked
    if session.revoked_at is not None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Session has been revoked."
        )

    # Check if session has expired
    if session.expires_at < now:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Session has expired."
        )

    # Check if absolute expiry has passed
    if session.absolute_expires_at < now:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Session absolute expiry has passed."
        )

    # Check if refresh token has expired
    if refresh_token_record.expires_at < now:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Refresh token has expired."
        )

    try:
        # Generate new refresh token
        new_refresh_token = secrets.token_urlsafe(32)
        new_token_hash = hashlib.sha256(new_refresh_token.encode()).hexdigest()

        # Create new refresh token record
        new_refresh_token_record = RefreshToken(
            session_id=session.id,
            token_hash=new_token_hash,
            expires_at=session.expires_at,  # Will be updated below
        )
        db.add(new_refresh_token_record)
        db.flush()  # Get the new token's ID

        # Mark old token as used and set replaced_by_id
        refresh_token_record.used_at = now
        refresh_token_record.replaced_by_id = new_refresh_token_record.id

        # Update session last_used_at
        session.last_used_at = now

        # Extend session expires_at to 7 days from now, but not beyond absolute_expires_at
        new_session_expires_at = now + timedelta(days=7)
        session.expires_at = min(new_session_expires_at, session.absolute_expires_at)

        # Update new refresh token expiry to match session expiry
        new_refresh_token_record.expires_at = session.expires_at

        # Commit all changes atomically
        db.commit()
        db.refresh(session)
        db.refresh(refresh_token_record)
        db.refresh(new_refresh_token_record)

        # Generate new access token
        access_token = create_access_token(session.user_id)

        # Set new refresh token in HttpOnly cookie
        response.set_cookie(
            key="refresh_token",
            value=new_refresh_token,
            httponly=True,
            samesite="lax",
            secure=SECURE_COOKIES,
            max_age=7 * 24 * 60 * 60,  # 7 days in seconds
        )

        # Return access token in response body
        return LoginResponse(
            access_token=access_token,
            token_type="bearer",
        )
    except Exception:
        db.rollback()
        raise


@router.post("/logout", status_code=status.HTTP_200_OK)
def logout(
    response: Response,
    db: Session = Depends(get_db),
    refresh_token: str | None = Cookie(None),
):
    # Logout always succeeds, even without a valid token
    # This prevents information leakage about session existence

    if refresh_token and refresh_token != "":
        # Hash the supplied token
        token_hash = hashlib.sha256(refresh_token.encode()).hexdigest()

        # Look up the refresh token record
        refresh_token_record = db.query(RefreshToken).filter(
            RefreshToken.token_hash == token_hash
        ).first()

        if refresh_token_record:
            # Lock the session for update
            session = db.query(AuthSession).filter(
                AuthSession.id == refresh_token_record.session_id
            ).with_for_update().first()

            if session and session.revoked_at is None:
                # Revoke the session
                session.revoked_at = datetime.now(timezone.utc)
                try:
                    db.commit()
                except Exception:
                    db.rollback()
                    # Still return success on logout even if revocation fails
                    pass

    # Clear the refresh token cookie
    response.delete_cookie(
        key="refresh_token",
        httponly=True,
        samesite="lax",
        secure=SECURE_COOKIES,
    )

    return {"message": "Logged out successfully."}


@router.get("/me", response_model=MeResponse, status_code=status.HTTP_200_OK)
def me(current_user: User = Depends(get_current_user)):
    """
    Get the currently authenticated user's information.

    Returns:
        User information including id, username, email, and household_id
    """
    return MeResponse(
        id=current_user.id,
        username=current_user.username,
        email=current_user.email,
        household_id=current_user.household_id,
    )
