from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from ..core.auth import authenticate_user, create_access_token, hash_password
from ..core.database import get_db
from ..models.scan import User
from ..schemas.scan import AuthCredentials, TokenResponse, UserCreate, UserRead


router = APIRouter(prefix='/auth', tags=['auth'])


def user_to_read(user: User) -> UserRead:
    return UserRead.model_validate(user)


@router.post('/register', response_model=TokenResponse, status_code=status.HTTP_201_CREATED)
def register(payload: UserCreate, db: Session = Depends(get_db)):
    existing_user = db.query(User).filter(User.email == payload.email.lower()).first()
    if existing_user is not None:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail='Email is already registered')

    user = User(
        email=payload.email.lower(),
        hashed_password=hash_password(payload.password),
        role=payload.role or 'analyst',
    )
    db.add(user)
    db.commit()
    db.refresh(user)

    token = create_access_token(subject=user.email, extra_claims={'role': user.role, 'user_id': user.id})
    return {'access_token': token, 'token_type': 'bearer', 'user': user_to_read(user)}


@router.post('/login', response_model=TokenResponse)
def login(payload: AuthCredentials, db: Session = Depends(get_db)):
    user = authenticate_user(db, payload.email, payload.password)
    if user is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail='Invalid email or password')

    token = create_access_token(subject=user.email, extra_claims={'role': user.role, 'user_id': user.id})
    return {'access_token': token, 'token_type': 'bearer', 'user': user_to_read(user)}