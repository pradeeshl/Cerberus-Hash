import json

from fastapi import APIRouter, Depends, File, HTTPException, UploadFile, status
from sqlalchemy.orm import Session

from ..core.auth import get_current_user
from ..core.database import get_db
from ..models.scan import Detection, Packet, Scan, User
from ..schemas.scan import DetectionRead, PacketRead, ScanDetailRead, ScanSummaryRead, ScanUploadResponse
from ..services.scan_service import (
    detection_to_dict,
    get_scan_or_404,
    packet_to_dict,
    persist_scan,
    save_upload_file,
    scan_to_dict,
)


router = APIRouter(prefix='/scans', tags=['scans'])


def _validate_upload(file: UploadFile) -> None:
    if not file or not file.filename:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail='A PCAP file is required')

    lower_name = file.filename.lower()
    if not (lower_name.endswith('.pcap') or lower_name.endswith('.pcapng')):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail='Only .pcap and .pcapng files are supported')

    # Enforce file size check (50MB maximum)
    MAX_SIZE = 50 * 1024 * 1024
    file.file.seek(0, 2)
    file_size = file.file.tell()
    file.file.seek(0)
    
    if file_size > MAX_SIZE:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail='PCAP file size exceeds maximum limit of 50MB'
        )

    # Validate file magic headers (signature verification)
    magic = file.file.read(4)
    file.file.seek(0)
    
    # 0xa1b2c3d4 or 0xd4c3b2a1 (PCAP), 0x0a0d0d0a (PCAPNG)
    PCAP_MAGIC = [b'\xa1\xb2\xc3\xd4', b'\xd4\xc3\xb2\xa1', b'\x0a\x0d\x0d\x0a']
    if magic not in PCAP_MAGIC:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail='Invalid PCAP file header magic signature'
        )


@router.post('/upload', response_model=ScanUploadResponse, status_code=status.HTTP_201_CREATED)
def upload_scan(
    workspace_id: int,
    file: UploadFile = File(...),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    from ..models.scan import Workspace
    ws = db.query(Workspace).filter(Workspace.id == workspace_id, Workspace.user_id == current_user.id).first()
    if not ws:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail='Workspace not found')

    _validate_upload(file)
    file_path = save_upload_file(file)

    try:
        scan = persist_scan(db, current_user.id, file, file_path, workspace_id)
    finally:
        file.close()

    return build_scan_detail(db, scan)


@router.get('', response_model=list[ScanSummaryRead])
def list_scans(
    workspace_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    from ..models.scan import Workspace
    ws = db.query(Workspace).filter(Workspace.id == workspace_id, Workspace.user_id == current_user.id).first()
    if not ws:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail='Workspace not found')

    scans = (
        db.query(Scan)
        .filter(Scan.user_id == current_user.id, Scan.workspace_id == workspace_id)
        .order_by(Scan.started_at.desc())
        .all()
    )
    return [scan_to_dict(scan) for scan in scans]


@router.get('/{scan_id}', response_model=ScanDetailRead)
def get_scan(scan_id: str, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    scan = get_scan_or_404(db, scan_id, current_user.id)
    return build_scan_detail(db, scan)


@router.get('/{scan_id}/packets', response_model=list[PacketRead])
def get_packets(scan_id: str, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    scan = get_scan_or_404(db, scan_id, current_user.id)
    packets = db.query(Packet).filter(Packet.scan_id == scan.id).order_by(Packet.packet_index.asc()).all()
    return [packet_to_dict(packet) for packet in packets]


@router.get('/{scan_id}/detections', response_model=list[DetectionRead])
def get_detections(scan_id: str, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    scan = get_scan_or_404(db, scan_id, current_user.id)
    detections = db.query(Detection).filter(Detection.scan_id == scan.id).order_by(Detection.packet_index.asc()).all()
    return [
        {
            **detection_to_dict(detection),
            'tags': json.loads(detection.tags) if detection.tags else [],
        }
        for detection in detections
    ]


def build_scan_detail(db: Session, scan: Scan) -> dict:
    packets = db.query(Packet).filter(Packet.scan_id == scan.id).order_by(Packet.packet_index.asc()).all()
    detections = db.query(Detection).filter(Detection.scan_id == scan.id).order_by(Detection.packet_index.asc()).all()

    return {
        **scan_to_dict(scan),
        'packets': [packet_to_dict(packet) for packet in packets],
        'detections': [
            {
                **detection_to_dict(detection),
                'tags': json.loads(detection.tags) if detection.tags else [],
            }
            for detection in detections
        ],
    }