from __future__ import annotations
from typing import Any, Dict, Optional
import jwt
import time

from .storage.base_store import BaseStore
from .storage.local_store import LocalStore


class SessionManager:
    """
    Manages session operations including encryption, storage, and retrieval.
    Maintains exact compatibility with original implementation.
    """

    def __init__(
        self,
        auth_client: Any,
        use_local_cache: bool = True,
        get_ext_sessions=None,
        get_ext_session=None,
        set_ext_session=None,
        delete_ext_session=None,
        store: Optional[BaseStore] = None
    ):
        """
        Initialize session manager with original parameters plus optional store.

        Args:
            auth_client: Parent AIAuth instance
            use_local_cache: Whether to use local cache (default: True)
            get_ext_sessions: Optional custom get_sessions function
            get_ext_session: Optional custom get_session function
            set_ext_session: Optional custom set_session function
            delete_ext_session: Optional custom delete_session function
            store: Optional custom store implementation
        """
        self.auth_client = auth_client
        self.store = store or LocalStore(use_local_cache=use_local_cache)
        self.secret_key = auth_client.secret_key

        # Custom function handlers
        self.get_ext_sessions = get_ext_sessions
        self.get_ext_session = get_ext_session
        self.set_ext_session = set_ext_session
        self.delete_ext_session = delete_ext_session

    # Original interface methods with exact same names and signatures
    def _get_stored_sessions(self) -> Any:
        """Get all stored session IDs"""
        if hasattr(self, 'get_ext_sessions') and self.get_ext_sessions:
            return self.get_ext_sessions()
        return self.store.get_stored_sessions()

    def _get_stored_session(self, user_id: str) -> str:
        """Get a specific stored session"""
        if hasattr(self, 'get_ext_session') and self.get_ext_session:
            return self.get_ext_session()
        return self.store.get_stored_session(user_id)

    def _set_stored_session(self, user_id: str, encrypted_session_data: str) -> None:
        """Store a session"""
        if hasattr(self, 'set_ext_session') and self.set_ext_session:
            self.set_ext_session()
        else:
            self.store.set_stored_session(user_id, encrypted_session_data)

    def _delete_stored_session(self, user_id: str) -> None:
        """Delete a stored session"""
        if hasattr(self, 'delete_ext_session') and self.delete_ext_session:
            self.delete_ext_session()
        else:
            self.store.delete_stored_session(user_id)

    # Session encryption and management methods (from original auth_client.py)
    async def set_encrypted_session(self, token_data: dict, state: str | None = None, user_id : str | None = None) -> str:
        """Create or update encrypted session"""
        id_token = token_data.get("id_token", "")
        decoded_id_token = {}
        # use user_id is already provided
        if user_id:
            user_id = user_id
        #check if id_token is provided, get user_id from id_token
        elif id_token:
            try:
                decoded_id_token = await self.auth_client.token_verifier.verify_signature(id_token)
                user_id = decoded_id_token.get("sub")
                if not user_id:
                    raise ValueError("ID token missing 'sub' claim.")
            except Exception as e:
                raise ValueError(f"Invalid ID token: {str(e)}")
        # use user_id from state (linking/unlinking) scenario
        else:
            user_id = self.auth_client.state_store[state].get(
                "user_id") if state else None

        existing_encrypted_session = self._get_stored_session(user_id)
        existing_user_details = {}
        existing_id_token_details = {}
        existing_linked_connections = {}
        existing_token_set = {}
        existing_refresh_token = {}

        if existing_encrypted_session:
            # found existing session, check if there is a refresh token to keep
            existing_session = self.get_encrypted_session(user_id)

            existing_user_details = existing_session.get("user")
            existing_id_token_details = existing_session.get("id_token")
            existing_token_set = existing_session.get("tokens", [])
            existing_refresh_token = existing_session.get(
                "refresh_token", None)
            existing_linked_connections = existing_session.get(
                "linked_connections")

        session_data = {}
        session_data = {
            "user": self._get_user(decoded_id_token, existing_user_details),
            "id_token": self._get_id_token(id_token, decoded_id_token, existing_id_token_details),
            "refresh_token": self._get_refresh_token(token_data, existing_refresh_token),
            "tokens": await self._get_token_set(token_data, existing_token_set),
            "linked_connections": self._get_linked_details(state, existing_linked_connections)
        }

        encrypted_session_data = jwt.encode(
            session_data, self.secret_key, algorithm="HS256")
        self._set_stored_session(user_id, encrypted_session_data)

        if state:
            self.auth_client.state_store[state]["user_id"] = user_id

        return encrypted_session_data

    def get_encrypted_session(self, user_id: str) -> Dict[str, Any]:
        """Retrieve and decrypt session data"""
        encrypted_session = self._get_stored_session(user_id)

        if not encrypted_session:
            return {"not found"}

        try:
            decoded_data = jwt.decode(
                encrypted_session, self.secret_key, algorithms=["HS256"])

            token_expiry = decoded_data.get("id_token", {}).get(
                "id_token_expiry", 0)
            if token_expiry > int(time.time()):
                return decoded_data
            else:
                self._delete_stored_session(user_id)
                return {"session expired"}

        except jwt.ExpiredSignatureError:
            return {"Session cookie has expired."}
        except jwt.InvalidTokenError:
            return {"Invalid session."}

    def _update_encrypted_session(self, user_id: str, refresh_token: str) -> None:
        """Update session with refreshed tokens"""
        token_manager = self.auth_client.token_manager
        updated_tokens = token_manager.refresh_tokens(
            refresh_token=refresh_token)
        if updated_tokens:
            self.set_encrypted_session(updated_tokens)

    def get_session(self, user: Any) -> Dict[str, Any]:
        """Get session for user object"""
        if user.user_id in self._get_stored_sessions():
            session = self.get_encrypted_session(user.user_id)
            return (session.get("user"))
        else:
            return {"user_id not found in session store"}

    def _get_user(self, id_token_data: dict, existing_user: dict | None = None) -> dict:
        """Builds the user object for the session based on existing info and receive id_token."""
        return id_token_data or existing_user

    def _get_id_token(self, id_token: str, decoded_id_token: dict, existing_id_token: dict) -> dict:
        if id_token:
            return {"id_token": id_token, "id_token_expiry": decoded_id_token.get("exp")}
        else:
            return existing_id_token

    def _get_refresh_token(self, token_data: dict, existing_refresh_token: str | None = None) -> dict:
        if token_data and "refresh_token" in token_data:
            return token_data.get("refresh_token")
        else:
            return existing_refresh_token

    async def _get_token_set(self, token_data: dict, existing_token_set: list[dict] | None = None) -> list[dict]:
        """Extracts the access token, scope, refresh token, and expiry time from the token_data."""

        decoded_at = await self.auth_client.token_manager.verify_token(token_data.get("access_token", {}))
        decoded_at_aud = f"https://{self.auth_client.domain}/userinfo"

        if decoded_at and "aud" in decoded_at:
            decoded_at_aud = decoded_at.get("aud")

        token_list = [{
            "aud": decoded_at_aud,
            "access_token": token_data.get("access_token"),
            "scope": token_data.get("scope"),
            "expires_at": {"epoch": int(time.time()) + token_data["expires_in"]},
        }]

        for token in existing_token_set:
            if "aud" in token and token.get("aud") != decoded_at_aud:
                token_list.append(token)

        return token_list

    def _get_linked_details(self, state: str, existing_linked_connections: list[str] | None = None) -> list[str]:

        linked_connections = set(existing_linked_connections or [])

        if "operation" in self.auth_client.state_store[state]:
            operation = self.auth_client.state_store[state].get(
                "operation").get("type")

            if operation == "linking":
                linked_connections.add(self.auth_client.state_store[state].get(
                    "operation").get("connection"))

            if operation == "unlinking":
                linked_connections.remove(
                    self.auth_client.state_store[state].get("operation").get("connection"))

        return list(linked_connections)

    def _get_user_response(self, decoded_data: dict) -> dict:
        """Extracts user info from decoded session data"""
        res = {}
        res["user"] = decoded_data.get("user")
        res["tokens"] = decoded_data.get("tokens")
        res["linked_connections"] = decoded_data.get("linked_connections")
        return res