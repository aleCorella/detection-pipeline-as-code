import random
from datetime import UTC, datetime

from faker import Faker

from detection_pipeline_as_code.generator import generate_benign

START = datetime(2026, 10, 1, tzinfo=UTC)

def build(seed: int, n: int = 100):
    rng = random.Random(seed)
    fake = Faker()
    fake.seed_instance(seed)

    return generate_benign(n, rng, fake, START)

def test_seed_give_same_data():
    assert build(1) == build(1)


def test_different_seed_give_different_data():
    assert build(1) != build(2)

def test_login_rate_is_about_10_percent():
    events = build(1, 1000)
    logins = 0
    for e in events:
        if e.path == "/login":
            logins += 1
    rate = logins / len(events)
    assert 0.07 <= rate <= 0.13