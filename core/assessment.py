from dataclasses import dataclass, field
from datetime import datetime


@dataclass
class Assessment:
    assessment_id: str
    target: object
    started_at: datetime
    status: str = "running"
    observations: list = field(default_factory=list)

    def add_observation(self, observation):
        self.observations.append(observation)
