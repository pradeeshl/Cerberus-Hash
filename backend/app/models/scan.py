from datetime import datetime, timezone
from uuid import uuid4

from sqlalchemy import Boolean, Column, DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.orm import relationship

from ..core.database import Base


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class User(Base):
    __tablename__ = 'users'

    id = Column(Integer, primary_key=True, index=True)
    email = Column(String(255), unique=True, index=True, nullable=False)
    hashed_password = Column(String(255), nullable=False)
    role = Column(String(50), nullable=False, default='analyst')
    created_at = Column(DateTime(timezone=True), nullable=False, default=utcnow)

    scans = relationship('Scan', back_populates='owner', cascade='all, delete-orphan')


class Scan(Base):
    __tablename__ = 'scans'

    id = Column(String(36), primary_key=True, index=True, default=lambda: str(uuid4()))
    user_id = Column(Integer, ForeignKey('users.id'), nullable=False, index=True)
    filename = Column(String(255), nullable=False)
    file_size = Column(String(50), nullable=False)
    total_packets = Column(Integer, nullable=False, default=0)
    threat_count = Column(Integer, nullable=False, default=0)
    status = Column(String(32), nullable=False, default='completed')
    started_at = Column(DateTime(timezone=True), nullable=False, default=utcnow)
    completed_at = Column(DateTime(timezone=True), nullable=True)
    created_at = Column(DateTime(timezone=True), nullable=False, default=utcnow)

    owner = relationship('User', back_populates='scans')
    packets = relationship('Packet', back_populates='scan', cascade='all, delete-orphan', order_by='Packet.packet_index')
    detections = relationship('Detection', back_populates='scan', cascade='all, delete-orphan', order_by='Detection.packet_index')


class Packet(Base):
    __tablename__ = 'packets'

    id = Column(String(36), primary_key=True, index=True, default=lambda: str(uuid4()))
    scan_id = Column(String(36), ForeignKey('scans.id'), nullable=False, index=True)
    packet_index = Column(Integer, nullable=False, index=True)
    timestamp = Column(String(64), nullable=False)
    source_ip = Column(String(64), nullable=False)
    dest_ip = Column(String(64), nullable=False)
    protocol = Column(String(32), nullable=False)
    length = Column(Integer, nullable=False)
    info = Column(Text, nullable=False, default='')
    is_threat = Column(Boolean, nullable=False, default=False)
    raw_payload = Column(Text, nullable=True)
    payload_hash = Column(String(64), nullable=True, index=True)

    scan = relationship('Scan', back_populates='packets')


class Detection(Base):
    __tablename__ = 'detections'

    id = Column(String(36), primary_key=True, index=True, default=lambda: str(uuid4()))
    scan_id = Column(String(36), ForeignKey('scans.id'), nullable=False, index=True)
    packet_index = Column(Integer, nullable=False, index=True)
    md5_hash = Column(String(64), nullable=False, index=True)
    rule_name = Column(String(255), nullable=False)
    description = Column(Text, nullable=False, default='')
    author = Column(String(255), nullable=False, default='Unknown')
    tags = Column(Text, nullable=False, default='[]')
    severity = Column(String(32), nullable=False, default='medium')
    vt_positives = Column(Integer, nullable=False, default=0)
    vt_total = Column(Integer, nullable=False, default=0)
    raw_payload = Column(Text, nullable=True)
    created_at = Column(DateTime(timezone=True), nullable=False, default=utcnow)

    scan = relationship('Scan', back_populates='detections')