import json
from pathlib import Path


def assessment_to_dict(assessment):
    return {
        "assessment_id": assessment.assessment_id,
        "target": {
            "value": assessment.target.value,
            "type": assessment.target.target_type,
            "hostname": assessment.target.hostname
        },
        "started_at": assessment.started_at.isoformat(),
        "status": assessment.status,
        "observations": [
            {
                "category": observation.category,
                "source": observation.source,
                "data": observation.data,
                "timestamp": observation.timestamp.isoformat()
            }
            for observation in assessment.observations
        ]
    }


def save_assessment(assessment, path):
    data = assessment_to_dict(assessment)
    
    Path(path).parent.mkdir(parents=True, exist_ok=True)

    with open(path, "w") as file:
        json.dump(data, file, indent=4)
