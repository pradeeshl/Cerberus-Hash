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


def _validate_upload(filename: str | None) -> None:
    if not filename:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail='A PCAP file is required')

    lower_name = filename.lower()
    if not (lower_name.endswith('.pcap') or lower_name.endswith('.pcapng')):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail='Only .pcap and .pcapng files are supported')


@router.post('/upload', response_model=ScanUploadResponse, status_code=status.HTTP_201_CREATED)
def upload_scan(
    file: UploadFile = File(...),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    _validate_upload(file.filename)
    file_path = save_upload_file(file)

    try:
        scan = persist_scan(db, current_user.id, file, file_path)
    finally:
        file.close()

    return build_scan_detail(db, scan)


@router.get('', response_model=list[ScanSummaryRead])
def list_scans(db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    scans = (
        db.query(Scan)
        .filter(Scan.user_id == current_user.id)
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