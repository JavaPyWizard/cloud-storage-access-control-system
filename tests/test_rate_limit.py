from app.security_rate_limit import LoginRateLimiter


def test_blocks_after_five_failures():
    limiter = LoginRateLimiter(5, 300)
    key = "127.0.0.1:testuser"

    for _ in range(5):
        assert not limiter.is_blocked(key)
        limiter.record_failure(key)

    assert limiter.is_blocked(key)


def test_reset_after_success():
    limiter = LoginRateLimiter(3, 300)
    key = "127.0.0.1:testuser"

    for _ in range(3):
        limiter.record_failure(key)

    assert limiter.is_blocked(key)

    limiter.reset(key)

    assert not limiter.is_blocked(key)


def test_different_users():
    limiter = LoginRateLimiter(2, 300)

    limiter.record_failure("127.0.0.1:user1")
    limiter.record_failure("127.0.0.1:user1")

    assert limiter.is_blocked("127.0.0.1:user1")
    assert not limiter.is_blocked("127.0.0.1:user2")
