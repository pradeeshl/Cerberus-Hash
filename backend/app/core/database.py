from sqlalchemy import create_engine, event
from sqlalchemy.orm import declarative_base, sessionmaker

from .config import settings


engine_kwargs = {}
if settings.DATABASE_URL.startswith('sqlite'):
    engine_kwargs['connect_args'] = {'check_same_thread': False}

engine = create_engine(settings.DATABASE_URL, **engine_kwargs)

@event.listens_for(engine, 'connect')
def set_sqlite_pragma(dbapi_connection, connection_record):
    if settings.DATABASE_URL.startswith('sqlite'):
        cursor = dbapi_connection.cursor()
        cursor.execute('PRAGMA journal_mode=WAL')
        cursor.execute('PRAGMA busy_timeout=5000')
        cursor.execute('PRAGMA synchronous=NORMAL')
        cursor.close()

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def init_db() -> None:
    from ..models.scan import Detection, Packet, Scan, User, Workspace  # noqa: F401

    # Run ALTER TABLE commands if column missing
    import sqlite3
    db_url = settings.DATABASE_URL
    if db_url.startswith('sqlite:///'):
        db_path = db_url.replace('sqlite:///', '')
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        try:
            cursor.execute("PRAGMA table_info(users)")
            user_cols = [row[1] for row in cursor.fetchall()]
            if 'default_workspace_id' not in user_cols:
                cursor.execute("ALTER TABLE users ADD COLUMN default_workspace_id INTEGER")
            if 'avatar' not in user_cols:
                cursor.execute("ALTER TABLE users ADD COLUMN avatar TEXT")
            if 'preferences' not in user_cols:
                cursor.execute("ALTER TABLE users ADD COLUMN preferences TEXT")
                
            cursor.execute("PRAGMA table_info(scans)")
            scan_cols = [row[1] for row in cursor.fetchall()]
            if 'workspace_id' not in scan_cols:
                cursor.execute("ALTER TABLE scans ADD COLUMN workspace_id INTEGER REFERENCES workspaces(id) ON DELETE CASCADE")
                
            conn.commit()
        except Exception as e:
            print(f"Migration error: {e}")
        finally:
            conn.close()

    Base.metadata.create_all(bind=engine)

    # Backfill default workspaces for users
    db = SessionLocal()
    try:
        users = db.query(User).all()
        for user in users:
            personal_ws = db.query(Workspace).filter(Workspace.user_id == user.id, Workspace.name == "Personal Workspace").first()
            if not personal_ws:
                personal_ws = Workspace(
                    user_id=user.id,
                    name="Personal Workspace",
                    description="Default workspace for individual packet analysis.",
                    color_theme="violet",
                    icon="Folder",
                    labels="[\"Personal\"]",
                )
                db.add(personal_ws)
                db.flush()
            
            if not user.default_workspace_id:
                user.default_workspace_id = personal_ws.id
                db.flush()
                
            # Assign existing scans that don't have a workspace
            scans_to_update = db.query(Scan).filter(Scan.user_id == user.id, Scan.workspace_id == None).all()
            for scan in scans_to_update:
                scan.workspace_id = personal_ws.id
            
        db.commit()
    except Exception as e:
        print(f"Error backfilling default workspaces: {e}")
        db.rollback()
    finally:
        db.close()