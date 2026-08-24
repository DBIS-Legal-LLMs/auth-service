import re

from email_validator import validate_email, EmailNotValidError
from passlib.context import CryptContext

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


# ----- E-Mail -----

def validate_email_address(email: str) -> str:
    try:
        v = validate_email(email, check_deliverability=True)
        return v.email
    except EmailNotValidError:
        raise ValueError("EMAIL_INVALID")


# ----- PASSWORDS -----

def validate_password_policy(password: str) -> list[str]:
    errors = []
    if len(password) < 8:
        errors.append("PASSWORD_TOO_SHORT")
    if not re.search(r"[A-Z]", password):
        errors.append("PASSWORD_NO_UPPERCASE")
    if not re.search(r"[a-z]", password):
        errors.append("PASSWORD_NO_LOWERCASE")
    if not re.search(r"[0-9]", password):
        errors.append("PASSWORD_NO_DIGIT")
    if not re.search(r"[!@#$%^&*()\-_=+{}\[\]|;:'\",.<>/?]", password):
        errors.append("PASSWORD_NO_SPECIAL")
    return errors


def hash_password(password: str) -> str:
    return pwd_context.hash(password)


def verify_password(plain_password: str, password_hash: str) -> bool:
    return pwd_context.verify(plain_password, password_hash)
