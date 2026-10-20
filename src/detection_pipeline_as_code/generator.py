import random
from datetime import datetime, timedelta

from faker import Faker

from detection_pipeline_as_code.event import Event

BROWSER_UAS = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Safari/605.1.15",
]

PAGES = ["/", "/products", "/cart", "/account"]

def make_benign_event(rng: random.Random, ips: list[str], start: datetime) -> Event:
    is_login = rng.random() < 0.10

    if is_login:
        status = 200 if rng.random() < 0.92 else 401
    else:
        status = 200

    return Event(
        timestamp=start + timedelta(seconds=rng.uniform(0, 3600)),
        src_ip=rng.choice(ips),
        user_agent=rng.choice(BROWSER_UAS),
        method="POST" if is_login else "GET",
        path="/login" if is_login else rng.choice(PAGES),
        status=status,
        label="benign",
    )

def generate_benign(n: int, rgn: random.Random, fake: Faker, start: datetime) -> list[Event]:
    ips =[fake.ipv4_public() for _ in range(50)]
    return [make_benign_event(rgn, ips, start) for _ in range(n)]