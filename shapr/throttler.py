# Adapted from http://flask.pocoo.org/snippets/70/
import time
from collections import defaultdict
from functools import wraps
from flask import request, g

# Use an in-memory store. Since it is single-threaded app, it shouldn't be
# an issue. TODO: fix this before deploying in prod to serve billion of users.
throttling_store = defaultdict(lambda: (0, 0))

class RateLimit(object):
    expiration_window = 10

    def __init__(self, key, limit, per):
        self.reset = int(time.time()) + per
        self.key = key
        self.limit = limit
        self.per = per

        n, exp = throttling_store[self.key]
        if exp < time.time():
            n = 0
        n += 1
        throttling_store[self.key] = (n, self.reset)
        self.current = n

    remaining = property(lambda x: x.limit - x.current)
    over_limit = property(lambda x: x.current >= x.limit)
    def exceeded_again(self):
        return self.current != self.limit

    def clear(self):
        throttling_store[self.key] = (0, 0)

def get_view_rate_limit():
    return getattr(g, '_view_rate_limit', None)

def on_over_limit(limit):
    return 'Too Many Requests', 429

def ratelimit(limit, per=300,
              over_limit=on_over_limit,
              scope_func=lambda: request.remote_addr,
              key_func=lambda: request.endpoint):
    def decorator(f):
        @wraps(f)
        def rate_limited(*args, **kwargs):
            key = 'rate-limit/%s/%s/' % (key_func(), scope_func())
            rlimit = RateLimit(key, limit, per)
            g._view_rate_limit = rlimit
            if over_limit is not None and rlimit.over_limit:
                return over_limit(rlimit)
            return f(*args, **kwargs)
        return rate_limited
    return decorator
