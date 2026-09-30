import bcrypt


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verifies a plain password against the stored bcrypt hash using native bcrypt."""
    password_bytes = plain_password.encode("utf-8")
    hash_bytes = hashed_password.encode("utf-8")
    return bcrypt.checkpw(password_bytes, hash_bytes)


def get_password_hash(password: str) -> str:
    """Generates a secure bcrypt password hash using native bcrypt."""
    password_bytes = password.encode("utf-8")
    salt = bcrypt.gensalt()
    return bcrypt.hashpw(password_bytes, salt).decode("utf-8")
