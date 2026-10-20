from datetime import datetime

from pydantic import BaseModel


class Event(BaseModel):
    timestamp: datetime
    src_ip: str
    user_agent: str
    method: str
    path: str
    status: int
    label: str