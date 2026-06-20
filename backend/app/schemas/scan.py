from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, EmailStr, Field


class UserBase(BaseModel):
    email: EmailStr


class UserCreate(UserBase):
    password: str = Field(min_length=8)
    role: str = 'analyst'


class UserRead(UserBase):
    model_config = ConfigDict(from_attributes=True)

    id: int
    role: str
    created_at: datetime


class AuthCredentials(BaseModel):
    email: EmailStr
    password: str


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = 'bearer'
    user: UserRead


class PacketRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    scan_id: str
    packet_index: int
    timestamp: str
    source_ip: str
    dest_ip: str
    protocol: str
    length: int
    info: str
    is_threat: bool
    raw_payload: str | None = None
    payload_hash: str | None = None


class DetectionRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    scan_id: str
    packet_index: int
    md5_hash: str
    rule_name: str
    description: str
    author: str
    tags: list[str] = Field(default_factory=list)
    severity: str
    vt_positives: int
    vt_total: int
    raw_payload: str | None = None


class ScanBase(BaseModel):
    id: str
    filename: str
    file_size: str
    total_packets: int
    threat_count: int
    status: str
    started_at: datetime
    completed_at: datetime | None = None


class ScanSummaryRead(ScanBase):
    model_config = ConfigDict(from_attributes=True)


class ScanDetailRead(ScanSummaryRead):
    user_id: int
    packets: list[PacketRead] = Field(default_factory=list)
    detections: list[DetectionRead] = Field(default_factory=list)


class ScanUploadResponse(ScanDetailRead):
    pass


class ErrorResponse(BaseModel):
    detail: Any