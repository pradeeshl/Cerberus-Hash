from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from .api.auth import router as auth_router
from .api.scans import router as scans_router
from .core.database import init_db


app = FastAPI(
    title='Cerberus-Hash API',
    description='Modern PCAP analysis and threat detection engine',
    version='1.0.0',
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        'http://localhost:5173',
        'http://localhost:3000',
    ],
    allow_credentials=True,
    allow_methods=['*'],
    allow_headers=['*'],
)


@app.on_event('startup')
def on_startup() -> None:
    init_db()


@app.get('/')
def read_root():
    return {'status': 'online', 'message': 'Cerberus-Hash API is running'}


app.include_router(auth_router)
app.include_router(scans_router)
