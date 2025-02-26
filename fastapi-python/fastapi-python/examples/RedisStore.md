# Examples
## Integration of Third Party Storage
### Redis Store
## Setting Up Redis Store
### Installation
```bash
pip install redis
```

### Changes to manager.py (Session Module)
```python
# Initialize store based on configuration
if store:
    self.store = store
elif use_redis:
    # Use Redis only
    self.store = RedisStore(
        host=os.environ.get("REDIS_HOST", "localhost"),
        port=int(os.environ.get("REDIS_PORT", 6379)),
        password=os.environ.get("REDIS_PASSWORD", None),
        db=int(os.environ.get("REDIS_DB", 0)),
        prefix=os.environ.get("REDIS_PREFIX", "auth0_session:"),
        ttl=int(os.environ.get("REDIS_TTL", 86400))
    )
else:
    # Use local store only (original behavior)
    self.store = LocalStore(use_local_cache=use_local_cache)
```

### Extending Base Store
```python
class RedisStore(BaseStore):
    """
    Redis-based session storage implementation.
    """
    def __init__(
        self,
        host: str = "localhost",
        port: int = 6379,
        db: int = 0,
        password: Optional[str] = None,
        prefix: str = "auth0_session:",
        ttl: Optional[int] = None,
        **kwargs
    ):
        """
        Initialize Redis store.
        Args:
            host: Redis host
            port: Redis port
            db: Redis database number
            password: Redis password
            prefix: Key prefix for session data
            ttl: Time to live for session data in seconds
            **kwargs: Additional Redis connection arguments
        """
        self.prefix = prefix
        self.ttl = ttl
        try:
            self.redis = redis.Redis(
                host=host,
                port=port,
                db=db,
                password=password,
                decode_responses=True,
                **kwargs
            )
            # Test connection
            self.redis.ping()
        except RedisError as e:
            logger.error(f"Failed to connect to Redis: {str(e)}")
            raise
```
### Usage Example
```python
from auth0_ai import AIAuth
from auth0_ai.session.stores import RedisStore
# Create a Redis store
redis_store = RedisStore(
    host="redis.example.com",
    port=6379,
    password="your_redis_password",
    ttl=3600  # 1 hour session TTL
)
# Initialize AIAuth with Redis store
auth = AIAuth(session_store=redis_store)
# Proceed with authentication as normal
user = await auth.interactive_login(connection="github")
```
### Environment Variable Configuration
Redis connection can be configured using environment variables:
- `REDIS_HOST`: Redis server hostname (default: "localhost")
- `REDIS_PORT`: Redis server port (default: 6379)
- `REDIS_PASSWORD`: Redis password (default: None)
- `REDIS_DB`: Redis database number (default: 0)
- `REDIS_PREFIX`: Key prefix for session data (default: "auth0_session:")
- `REDIS_TTL`: Session time-to-live in seconds (default: 86400)
