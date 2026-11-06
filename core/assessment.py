
from dataclasses import dataclass, field
from datetime import datetime


@dataclass
class Assessment:
    assessment_id: str
    target: object
    started_at: datetime
    status: str = "running"
    finished_at: datetime | None = None
    observations: list = field(default_factory=list)

    def add_observation(self, observation):
        self.observations.append(observation)

    def complete(self):
        self._finish("completed")

    def mark_partial(self):
        self._finish("partial")

    def fail(self):
        self._finish("failed")

    def _finish(self, status):
        if self.status != "running":
            raise ValueError(
                f"Cannot finish an assessment with status: {self.status}"
            )

        self.status = status
        self.finished_at = datetime.now()
