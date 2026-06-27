from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from ..core.auth import authenticate_user, create_access_token, hash_password
from ..core.database import get_db
from ..models.scan import User
from ..schemas.scan import AuthCredentials, TokenResponse, UserCreate, UserRead


router = APIRouter(prefix='/auth', tags=['auth'])


import json
from ..models.scan import User, Workspace


def user_to_read(user: User) -> dict:
    return {
        'id': user.id,
        'email': user.email,
        'role': user.role,
        'default_workspace_id': user.default_workspace_id,
        'avatar': user.avatar or 'avatar_default',
        'preferences': json.loads(user.preferences) if user.preferences else {},
        'created_at': user.created_at,
    }


@router.post('/register', response_model=TokenResponse, status_code=status.HTTP_201_CREATED)
def register(payload: UserCreate, db: Session = Depends(get_db)):
    existing_user = db.query(User).filter(User.email == payload.email.lower()).first()
    if existing_user is not None:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail='Email is already registered')

    user = User(
        email=payload.email.lower(),
        hashed_password=hash_password(payload.password),
        role=payload.role or 'analyst',
        avatar='avatar_default',
        preferences='{}',
    )
    db.add(user)
    db.commit()
    db.refresh(user)

    personal_ws = Workspace(
        user_id=user.id,
        name="Personal Workspace",
        description="Default workspace for individual packet analysis.",
        color_theme="violet",
        icon="Folder",
        labels=json.dumps(["Personal"]),
    )
    db.add(personal_ws)
    db.commit()
    db.refresh(personal_ws)

    user.default_workspace_id = personal_ws.id
    db.commit()
    db.refresh(user)

    token = create_access_token(subject=user.email, extra_claims={'role': user.role, 'user_id': user.id})
    return {'access_token': token, 'token_type': 'bearer', 'user': user_to_read(user)}


@router.post('/login', response_model=TokenResponse)
def login(payload: AuthCredentials, db: Session = Depends(get_db)):
    user = authenticate_user(db, payload.email, payload.password)
    if user is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail='Invalid email or password')

    # If user somehow doesn't have a workspace, ensure they get one
    if not user.default_workspace_id:
        personal_ws = db.query(Workspace).filter(Workspace.user_id == user.id, Workspace.name == "Personal Workspace").first()
        if not personal_ws:
            personal_ws = Workspace(
                user_id=user.id,
                name="Personal Workspace",
                description="Default workspace for individual packet analysis.",
                color_theme="violet",
                icon="Folder",
                labels=json.dumps(["Personal"]),
            )
            db.add(personal_ws)
            db.commit()
            db.refresh(personal_ws)
        user.default_workspace_id = personal_ws.id
        db.commit()
        db.refresh(user)

    token = create_access_token(subject=user.email, extra_claims={'role': user.role, 'user_id': user.id})
    return {'access_token': token, 'token_type': 'bearer', 'user': user_to_read(user)}