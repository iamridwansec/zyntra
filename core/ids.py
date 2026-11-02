from pathlib import Path

COUNTER_FILE = Path("data/assessment_counter.txt")


def generate_assessment_id():
    if COUNTER_FILE.exists():
        counter = int(COUNTER_FILE.read_text().strip())
    else:
        counter = 0

    counter += 1

    COUNTER_FILE.parent.mkdir(parents=True, exist_ok=True)
    COUNTER_FILE.write_text(str(counter))

    return f"ZYN-{counter:08d}"
