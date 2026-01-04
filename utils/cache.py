# utils/cache.py

import shelve
import os
import time
import threading
from typing import Any, Optional
from .config import CACHE_DIR, CACHE_FILE, CACHE_TTL_SECONDS

# Ensure cache directory exists
os.makedirs(CACHE_DIR, exist_ok=True)

# Lock for thread safety (though SpamJam is single-threaded, good practice)
_cache_lock = threading.Lock()

def get(key: str) -> Optional[Any]:
    """Get value from disk cache if not expired."""
    with _cache_lock:
        try:
            with shelve.open(CACHE_FILE) as db:
                if key in db:
                    value, timestamp = db[key]
                    if time.time() - timestamp < CACHE_TTL_SECONDS:
                        return value
                    else:
                        # Expired — delete it
                        del db[key]
        except Exception as e:
            # If cache file is corrupt, it's safe to ignore
            pass
    return None

def set(key: str, value: Any) -> None:
    """Store value in disk cache with timestamp."""
    with _cache_lock:
        try:
            with shelve.open(CACHE_FILE) as db:
                db[key] = (value, time.time())
        except Exception as e:
            # Fail silently — caching is optional
            pass