from typing import Set

# In-memory token blacklist.
# In a real application, this should be a persistent store like Redis or a database table.
TOKEN_BLACKLIST: Set[str] = set()

class TokenService:
    """
    Manages token revocation and blacklisting.
    """

    def add_to_blacklist(self, jti: str):
        """Adds a token's JTI (unique identifier) to the blacklist."""
        TOKEN_BLACKLIST.add(jti)

    def is_blacklisted(self, jti: str) -> bool:
        """Checks if a token's JTI is in the blacklist."""
        return jti in TOKEN_BLACKLIST
