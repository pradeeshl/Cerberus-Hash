import json
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from ..core.auth import get_current_user
from ..core.database import get_db
from ..models.scan import User, Workspace
from ..schemas.scan import ProfileUpdate, UserRead

router = APIRouter(prefix='/users', tags=['users'])

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

@router.get('/profile', response_model=UserRead)
def get_profile(current_user: User = Depends(get_current_user)):
    return user_to_read(current_user)

@router.put('/profile', response_model=UserRead)
def update_profile(
    payload: ProfileUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    if payload.email is not None:
        # Check if email is already taken
        existing_user = db.query(User).filter(User.email == payload.email.lower(), User.id != current_user.id).first()
        if existing_user:
            raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail='Email is already registered')
        current_user.email = payload.email.lower()
        
    if payload.role is not None:
        current_user.role = payload.role
        
    if payload.default_workspace_id is not None:
        # Verify the workspace exists and belongs to the user
        ws = db.query(Workspace).filter(Workspace.id == payload.default_workspace_id, Workspace.user_id == current_user.id).first()
        if not ws:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail='Workspace not found')
        current_user.default_workspace_id = payload.default_workspace_id
        
    if payload.avatar is not None:
        current_user.avatar = payload.avatar
        
    if payload.preferences is not None:
        current_user.preferences = json.dumps(payload.preferences)
        
    db.commit()
    db.refresh(current_user)
    return user_to_read(current_user)
