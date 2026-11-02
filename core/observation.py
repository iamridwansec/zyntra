from dataclasses import dataclass
from datetime import datetime


@dataclass
class Observation:
    category: str
    source: str
    data: object
    timestamp: datetime
