from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4

from fastapi import HTTPException, UploadFile, status
from sqlalchemy.orm import Session

from ..core.config import settings
from ..core.pcap_parser import parse_pcap
from ..core.yara_scanner import scan_with_yara
from ..models.scan import Detection, Packet, Scan


def _format_bytes(size_in_bytes: int) -> str:
    size = float(size_in_bytes)
    units = ['B', 'KB', 'MB', 'GB']
    unit_index = 0

    while size >= 1024 and unit_index < len(units) - 1:
        size /= 1024
        unit_index += 1

    return f"{size:.0f} {units[unit_index]}" if size >= 10 or unit_index == 0 else f"{size:.1f} {units[unit_index]}"


def save_upload_file(upload_file: UploadFile) -> Path:
    original_name = Path(upload_file.filename or 'capture.pcap').name
    settings.UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
    destination = settings.UPLOAD_DIR / f"{uuid4()}_{original_name}"

    with destination.open('wb') as output_file:
        while True:
            chunk = upload_file.file.read(1024 * 1024)
            if not chunk:
                break
            output_file.write(chunk)

    upload_file.file.seek(0)
    return destination


def persist_scan(db: Session, user_id: int, upload_file: UploadFile, file_path: Path) -> Scan:
    pcap_data = parse_pcap(file_path)
    packet_records = pcap_data['packets']
    detections = scan_with_yara(packet_records)
    threat_indexes = {detection['packet_index'] for detection in detections}

    started_at = datetime.now(timezone.utc)
    completed_at = datetime.now(timezone.utc)

    scan = Scan(
        user_id=user_id,
        filename=Path(upload_file.filename or file_path.name).name,
        file_size=_format_bytes(file_path.stat().st_size),
        total_packets=len(packet_records),
        threat_count=len(detections),
        status='completed',
        started_at=started_at,
        completed_at=completed_at,
    )
    db.add(scan)
    db.flush()

    for packet in packet_records:
        db.add(
            Packet(
                scan_id=scan.id,
                packet_index=packet['packet_index'],
                timestamp=packet['timestamp'],
                source_ip=packet['source_ip'],
                dest_ip=packet['dest_ip'],
                protocol=packet['protocol'],
                length=packet['length'],
                info=packet['info'],
                is_threat=packet['packet_index'] in threat_indexes,
                raw_payload=packet['raw_payload'],
                payload_hash=packet['payload_hash'],
            )
        )

    for detection in detections:
        db.add(
            Detection(
                scan_id=scan.id,
                packet_index=detection['packet_index'],
                md5_hash=detection['md5_hash'],
                rule_name=detection['rule_name'],
                description=detection['description'],
                author=detection['author'],
                tags=detection['tags'],
                severity=detection['severity'],
                vt_positives=detection['vt_positives'],
                vt_total=detection['vt_total'],
                raw_payload=detection['raw_payload'],
            )
        )

    db.commit()
    db.refresh(scan)
    return scan


def scan_to_dict(scan: Scan) -> dict:
    return {
        'id': scan.id,
        'user_id': scan.user_id,
        'filename': scan.filename,
        'file_size': scan.file_size,
        'total_packets': scan.total_packets,
        'threat_count': scan.threat_count,
        'status': scan.status,
        'started_at': scan.started_at,
        'completed_at': scan.completed_at,
    }


def packet_to_dict(packet: Packet) -> dict:
    return {
        'id': packet.id,
        'scan_id': packet.scan_id,
        'packet_index': packet.packet_index,
        'timestamp': packet.timestamp,
        'source_ip': packet.source_ip,
        'dest_ip': packet.dest_ip,
        'protocol': packet.protocol,
        'length': packet.length,
        'info': packet.info,
        'is_threat': packet.is_threat,
        'raw_payload': packet.raw_payload,
        'payload_hash': packet.payload_hash,
    }


def detection_to_dict(detection: Detection) -> dict:
    return {
        'id': detection.id,
        'scan_id': detection.scan_id,
        'packet_index': detection.packet_index,
        'md5_hash': detection.md5_hash,
        'rule_name': detection.rule_name,
        'description': detection.description,
        'author': detection.author,
        'tags': detection.tags,
        'severity': detection.severity,
        'vt_positives': detection.vt_positives,
        'vt_total': detection.vt_total,
        'raw_payload': detection.raw_payload,
    }


def get_scan_or_404(db: Session, scan_id: str, user_id: int) -> Scan:
    scan = db.query(Scan).filter(Scan.id == scan_id, Scan.user_id == user_id).first()
    if scan is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail='Scan not found')
    return scan