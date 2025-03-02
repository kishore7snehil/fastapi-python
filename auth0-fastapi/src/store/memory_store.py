from typing import Any, Optional
from .base_store import BaseStore
import threading

class MemoryStore(BaseStore):
    """
    Simple thread-safe in-memory key-value store.
    """

    def __init__(self):
        self._store = {}
        self._lock = threading.Lock()

    def get(self, key: str, default: Optional[Any] = None) -> Any:
        with self._lock:
            return self._store.get(key, default)

    def set(self, key: str, value: Any) -> None:
        with self._lock:
            self._store[key] = value

    def delete(self, key: str) -> None:
        with self._lock:
            if key in self._store:
                del self._store[key]

    def clear(self) -> None:
        """Clear the entire store."""
        with self._lock:
            self._store.clear()

    def keys(self) -> list[str]:
        """Return all keys in the store."""
        with self._lock:
            return list(self._store.keys())
