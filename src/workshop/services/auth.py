from datetime import datetime, timedelta

from fastapi import HTTPException, status, Depends
from fastapi.security import OAuth2PasswordBearer
from jose import JWSError, jwt
from passlib.hash import bcrypt
from pydantic import ValidationError
from sqlalchemy.orm import Session

from ..database import get_session
from ..models.auth import User, Token, UserCreate
from ..settings import settings
from ..tables import User as tableUser

oauth2_scheme = OAuth2PasswordBearer(tokenUrl='/auth/sign-in')


def get_current_user(token: str = Depends(oauth2_scheme)) -> User:
    return AuthService.validate_token(token)


class AuthService:
    @classmethod
    def verify_password(cls, plain_password: str, hashed_password: str) -> bool:
        return bcrypt.verify(plain_password, hashed_password)

    @classmethod
    def hash_password(cls, plain_password: str) -> str:
        return bcrypt.hash(plain_password)

    @classmethod
    def validate_token(cls, token: str) -> User:
        exceptions = HTTPException(status_code=status.HTTP_401_UNAUTHORIZED)
        try:
            payload = jwt.decode(token, settings.jwt_secret, algorithms=settings.jwt_algorithm)
        except JWSError:
            raise exceptions from None

        user_data = payload.get('user')
        try:
            user = User.parse_obj(user_data)
        except ValidationError:
            raise exceptions from None

        return user

    @classmethod
    def create_token(cls, user: tableUser) -> Token:
        user_data = User.from_orm(user)

        now = datetime.utcnow()

        payload = {
            'iat': now,
            'nbf': now,
            'exp': now + timedelta(seconds=settings.jwt_expiration),
            'sub': str(user.id),
            'user': user_data.dict(),
        }
        token = jwt.encode(payload, settings.jwt_secret, settings.jwt_algorithm)

        return Token(access_token=token)

    def __init__(self, session: Session = Depends(get_session)):
        self.session = session

    def register(self, user_data: UserCreate) -> Token:
        user = tableUser(
            email=user_data.email,
            username=user_data.username,
            password=self.hash_password(user_data.password),
        )

        self.session.add(user)
        self.session.commit()

        return self.create_token(user)

    def authenticate(self, username: str, password: str) -> Token:
        exceptions = HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail='invalid username or password',
        )
        user = self.session.query(tableUser).filter(tableUser.username == username).first()
        if not user:
            raise exceptions
        if not self.verify_password(password, user.password):
            raise exceptions
        return self.create_token(user)
