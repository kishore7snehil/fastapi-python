from abc import ABC, abstractmethod
from typing import Any, Optional

class BaseStore(ABC):
    """
    Abstract base class for a simple key-value store.
    All concrete stores (memory, cookie, etc.) must implement these methods.
    """

    @abstractmethod
    def get(self, key: str, default: Optional[Any] = None) -> Any:
        """
        Retrieve a value by `key`.
        :param key: The key to look up.
        :param default: Value to return if key is not found.
        :return: The stored value or `default`.
        """
        pass

    @abstractmethod
    def set(self, key: str, value: Any) -> None:
        """
        Store `value` under `key`.
        :param key: The key under which to store the value.
        :param value: The value to store.
        """
        pass

    @abstractmethod
    def delete(self, key: str) -> None:
        """
        Remove a value from the store by `key`.
        :param key: The key to remove.
        """
        pass

    def clear(self) -> None:
        """
        Optional: Clear the entire store (helpful for testing). Default is no-op.
        """
        pass