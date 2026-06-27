import json
from datetime import datetime, timezone
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from ..core.auth import get_current_user
from ..core.database import get_db
from ..models.scan import User, Workspace
from ..schemas.scan import WorkspaceCreate, WorkspaceRead, WorkspaceUpdate

router = APIRouter(prefix='/workspaces', tags=['workspaces'])

def workspace_to_dict(ws: Workspace) -> dict:
    return {
        'id': ws.id,
        'user_id': ws.user_id,
        'name': ws.name,
        'description': ws.description,
        'color_theme': ws.color_theme,
        'icon': ws.icon,
        'labels': json.loads(ws.labels) if ws.labels else [],
        'created_at': ws.created_at,
        'last_accessed_at': ws.last_accessed_at,
    }

@router.get('', response_model=list[WorkspaceRead])
def list_workspaces(db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    workspaces = db.query(Workspace).filter(Workspace.user_id == current_user.id).order_by(Workspace.last_accessed_at.desc()).all()
    return [workspace_to_dict(ws) for ws in workspaces]

@router.post('', response_model=WorkspaceRead, status_code=status.HTTP_201_CREATED)
def create_workspace(payload: WorkspaceCreate, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    ws = Workspace(
        user_id=current_user.id,
        name=payload.name,
        description=payload.description,
        color_theme=payload.color_theme,
        icon=payload.icon,
        labels=json.dumps(payload.labels) if payload.labels is not None else '[]',
    )
    db.add(ws)
    db.commit()
    db.refresh(ws)
    return workspace_to_dict(ws)

@router.put('/{id}', response_model=WorkspaceRead)
def update_workspace(id: int, payload: WorkspaceUpdate, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    ws = db.query(Workspace).filter(Workspace.id == id, Workspace.user_id == current_user.id).first()
    if not ws:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail='Workspace not found')
    
    if payload.name is not None:
        ws.name = payload.name
    if payload.description is not None:
        ws.description = payload.description
    if payload.color_theme is not None:
        ws.color_theme = payload.color_theme
    if payload.icon is not None:
        ws.icon = payload.icon
    if payload.labels is not None:
        ws.labels = json.dumps(payload.labels)
        
    db.commit()
    db.refresh(ws)
    return workspace_to_dict(ws)

@router.post('/{id}/access', response_model=WorkspaceRead)
def access_workspace(id: int, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    ws = db.query(Workspace).filter(Workspace.id == id, Workspace.user_id == current_user.id).first()
    if not ws:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail='Workspace not found')
        
    ws.last_accessed_at = datetime.now(timezone.utc)
    db.commit()
    db.refresh(ws)
    return workspace_to_dict(ws)

@router.delete('/{id}', status_code=status.HTTP_204_NO_CONTENT)
def delete_workspace(id: int, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    ws = db.query(Workspace).filter(Workspace.id == id, Workspace.user_id == current_user.id).first()
    if not ws:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail='Workspace not found')
        
    # Check if this is the default workspace. If so, clear it on User
    if current_user.default_workspace_id == id:
        current_user.default_workspace_id = None
        
    db.delete(ws)
    db.commit()
    return None
