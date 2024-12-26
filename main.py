from fastapi import FastAPI
from pydantic import BaseModel
from typing import Optional
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from config import secret_key, algorithm, access_token_exp
from datetime import datetime, timedelta
from jose import jwt

app = FastAPI(docs_url='/')


class Token(BaseModel):
    access_token: str
    token_type: str


class TokenData(BaseModel):
    username: str


class User(BaseModel):
    username: str
    password: str


fake_db = {
    "johndoe": {
        "username": "johndoe",
        "password": "123"
    }
}


# Функция для проверки пароля
def verify_password(password, hashed_password):
    return password == hashed_password


# Схема для авторизации


# Функция для получения пользователя
def get_user(db: dict, username: str):  # johndoe
    if username in db:
        print(db)
        print(username)
        user_dict = db[username]  # {"username": "johndoe","password": "123"}
        return User(**user_dict)  # User(username=johndoe, password=123)


# Функция для создания токена доступа
def create_access_token(data: dict, expire_date: Optional[timedelta] = None):
    # Копируем данные
    to_encode = data.copy()
    # Если приходит параметр expire_date то мы указываем наш
    # таймер для действия токена доступа, если нет то указываем 10 минут
    if expire_date:
        expire = datetime.utcnow() + expire_date
    else:
        expire = datetime.utcnow() + timedelta(minutes=10)
    # Обновляем наши данные
    to_encode.update({'exp': expire})

    encoded_jwt = jwt.encode(to_encode, secret_key=secret_key,
                             algorithm=algorithm)
    return encoded_jwt


# Функция для авторизации
def authenticate_user(db: dict, username: str, password: str):
    user = get_user(db, username)
    if user and verify_password(password, user.password):
        return user
    return False


from fastapi import HTTPException, Depends


@app.post("/token", response_model=Token)
async def login(form: OAuth2PasswordRequestForm = Depends()):
    user = authenticate_user(fake_db, form.username, form.password)
    if not user:
        return HTTPException(status_code=404,
                             detail="Неправильный user или password")
    access_token_expire = timedelta(minutes=int(access_token_exp))
    access_token = create_access_token(data={"sub": user.username},
                                       expire_date=access_token_expire)
    return {"access_token": access_token,
            "token_type": "bearer"}


oauth_schema = OAuth2PasswordBearer(tokenUrl="token")


async def get_current_user(token: str = Depends(oauth_schema)):
    exception = HTTPException(status_code=404,
                              detail="ERROR")
    try:
        payload = jwt.decode(token, secret_key, algorithms=algorithm)
        username = payload.get("sub")
        if username is None:
            raise exception
        token_data = TokenData(username)
    except jwt.JWTError:
        raise exception
    user = get_user(fake_db, token_data.username)
    if user is None:
        raise exception
    return user


@app.get("/user/me", response_model=User)
async def user_me(user: User = Depends(get_current_user)):
    return user
