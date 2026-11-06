from config.paths import ASSESSMENT_COUNTER_FILE


def generate_assessment_id():
    if ASSESSMENT_COUNTER_FILE.exists():
        counter = int(ASSESSMENT_COUNTER_FILE.read_text().strip())
    else:
        counter = 0

    counter += 1

    ASSESSMENT_COUNTER_FILE.parent.mkdir(parents=True, exist_ok=True)
    ASSESSMENT_COUNTER_FILE.write_text(str(counter))

    return f"ZYN-{counter:08d}"
