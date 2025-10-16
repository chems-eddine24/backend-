<<<<<<< HEAD
from typing import Optional
from pydantic import BaseModel
from sqlalchemy import create_engine, MetaData, Column, String, Boolean, INTEGER
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.orm import declarative_base
import sqlalchemy as sa
from fastapi import Depends, HTTPException, status, FastAPI
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import jwt, JWTError
from datetime import datetime, timedelta
from sqlalchemy.orm import Session
from passlib.context import CryptContext






#Pydantic models
class UserCreate(BaseModel):
    name: str
    email: str
    password: str
    

class UpdateUser(BaseModel):
    email: Optional[str] = None
    password: Optional[str] = None
  
class UserResponse(BaseModel):
    id: int
    email: str
    name: str
    is_active: bool

    class Config:
        orm_mode = True

class Login(BaseModel):
    email: str
    password: str

class Token(BaseModel):
    access_token: str
    token_type: str

class TokenData(BaseModel):
    email: Optional[str] = None



#DB config



engine = create_engine("sqlite:////home/james-dine/Apps/Python/FastApi/test.db", echo=True)
connection = engine.connect()
Base = declarative_base()
metadata = MetaData()


class User(Base):
    __tablename__ = "users"
    id = sa.Column(INTEGER, primary_key=True)
    email = sa.Column(String, nullable=False, unique=True)
    name = sa.Column(String, nullable=False)
    password = sa.Column(String, nullable=False)
    password_hash = sa.Column(String, nullable=False)
    is_active = sa.Column(Boolean, default=True)
Base.metadata.create_all(bind=engine)



SECRET_KEY = "codewithjames"
ALGORITHM = "HS256"
TOKEN_EXPIRES = 30

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

SessionLocal = sessionmaker(autoflush=False, autocommit=False, bind=engine)

def get_db():
    db = SessionLocal()
=======
from fastapi import FastAPI, Depends, HTTPException
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.orm import declarative_base
from sqlalchemy import create_engine
from models import *
from db import *
from typing import List
import requests
from security import *


db_url = "/home/james-dine/Apps/Python/FastApi/library.db"
engine = create_engine(f"sqlite:///{db_url}")
connection = engine.connect()

def get_db():
    db = Sessionlocal()
>>>>>>> 7282bcc (Initial commit: FastAPI book library project)
    try:
        yield db
    finally:
        db.close()

<<<<<<< HEAD
def verify_password(plain_pwd: str, hashed_pwd: str) -> bool:
    return pwd_context.verify(plain_pwd, hashed_pwd)

def get_password_hash(password: str) -> str:
    return pwd_context.hash(password)

def create_access_token(data: dict, expires_delta: timedelta | None = None):
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=15))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

def verify_token(token: str) -> TokenData:
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email: str = payload.get("sub")
        if email is None:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")
        return TokenData(email=email)
    except JWTError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")

def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    token_data = verify_token(token)
    user = db.query(User).filter(User.email == token_data.email).first()
    if not user:
        raise HTTPException(status_code=401, detail="User not found")
    return user

def get_current_active_user(current_user: User = Depends(get_current_user)):
    if not current_user.is_active:
        raise HTTPException(status_code=400, detail="Inactive user")
    return current_user


app = FastAPI(title="Who's Gonna Carry the Boats And The Logs")

#Auth endpoint
@app.post('/register', response_model=UserResponse)
def register_user(user: UserCreate, db: Session = Depends(get_db)):
    if db.query(User).filter(User.email == user.email).first():
        raise HTTPException(
            status_code=404,
            detail="User already exists"
        )
    hashed_pwd = get_password_hash(user.password)
    db_user = User(
        name=user.name,
        email=user.email,
        password=user.password,
        password_hash=hashed_pwd
=======

app = FastAPI(title="Book Library")

#Auth Endpoints (Register user, give them a token ..etc)
@app.post("/register", response_model=UserResponse)
def register_user(user:UserCreate, db: Session = Depends(get_db)):
    if db.query(User).filter(User.email==user.email).first():
        raise HTTPException(
            status_code=404,
            detail="User already exists!"
        )
    db_user = User(
        id=user.id,
        email=user.email,
        password=user.password,
        password_hash=get_password_hash(user.password),
        is_active=True
>>>>>>> 7282bcc (Initial commit: FastAPI book library project)
    )
    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    return db_user

<<<<<<< HEAD
@app.post('/token', response_model=Token)
def login_for_access_token(from_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    user = db.query(User).filter(User.email == from_data.username).first()
    if not user or not verify_password(from_data.password, user.password_hash):
        raise HTTPException(
            status_code=404,
            detail="Wrong Info"
=======

@app.post('/token', response_model=Token)
def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    user = db.query(User).filter(User.email==form_data.username).first()
    if not user or not verify_password(form_data.password, user.password_hash):
        raise HTTPException(
            status_code=404,
            detail="wrong info!"
>>>>>>> 7282bcc (Initial commit: FastAPI book library project)
        )
    if not user.is_active:
        raise HTTPException(
            status_code=404,
<<<<<<< HEAD
            detail="User Inactive"
        )
    access_token_expires = timedelta(minutes=TOKEN_EXPIRES)
    access_token = create_access_token(
        data={"sub":user.email}, expires_delta=access_token_expires
    )
    return {"access_token":access_token, "token_type":"bearer"}


#CRUD

@app.get('/user/', response_model=list[UserResponse])
def get_all_users(current_user:User = Depends(get_current_active_user), db: Session = Depends(get_db)):
    return db.query(User).all()

@app.get('/profile', response_model=UserResponse)
def get_profile(current_user: User = Depends(get_current_active_user)):
    return current_user

@app.get('/verify-token')
def verify_token_endpoint(current_user:User = Depends(get_current_active_user)):
    return {
        "valid":True,
        'user':{
            "id":current_user.id,
            "name":current_user.name,
            "email":current_user.email,
            "is_active":current_user.is_active
        }
    }

@app.post("/users/", response_model=UserResponse)
def create_user(user: UserCreate, current_user:User = Depends(get_current_active_user), db: Session = Depends(get_db)):
    db_user = db.query(User).filter(User.email == user.email).first()
    if db_user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Email already used"
        )
    db_user = User(
        name = user.name,
        email = user.email,
        password = user.password,
        password_hash=get_password_hash(user.password)
    )
    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    return db_user

@app.patch('/user/{email}')
def update_user(email: str, user: UpdateUser , db:Session = Depends(get_db)):
    db_user = db.query(User).filter(User.email == email).first()
    if not db_user:
        raise HTTPException(
            status_code=404,
            detail="User not found"
        )
    db_user.email = user.email
    db_user.password = user.password
    db.commit()
    db.refresh(db_user)
    return {"message":"User updated!"}
   

@app.get("/users/{user_id}", response_model=UserResponse)
def get_user_by_id(user_id: int, current_user:User = Depends(get_current_active_user) ,db: Session = Depends(get_db)):
    db_user = db.query(User).filter(User.id == user_id).first()
    if not db_user:
       raise HTTPException(
            status_code=404,
            detail="User not found"
       )
    return db_user

@app.delete('/users/{user_id}')
def delete_user(user_id: int, db: Session = Depends(get_db)):
    db_user = db.query(User).filter(User.id == user_id).first()
    if not db_user:
        raise HTTPException(
            status_code=404,
            detail="User not found"
        )
    db.delete(db_user)
    db.commit()
    return "User deleted"
=======
            detail="Inactive User!"
        )
    token_expires = timedelta(minutes=TOKEN_EXPIRES)
    access_token = create_access_token(
        data={"sub":user.email}, expires_delta=token_expires
    )
    return {"access_token":access_token, "token_type":"bearer"}

@app.get('verfy-token')
def verfy_token_endponit(current_user: User = Depends(get_current_active_user)):
    return{
        "valid":True,
        "user":{
            "id":current_user.id,
            "email":current_user.email,
            "password":current_user.password
        }
    }

@app.get("/profile", response_model=UserResponse)
def get_current_profile(current_user: User = Depends(get_current_active_user)):
    return current_user

@app.post("/books/")
def add_book(book: add_book, current_user: User = Depends(get_current_active_user), db: Session = Depends(get_db)):
    add_book = Book(
        title=book.title,
        author=book.author,
        release_date=book.release_date,
        genre=book.genre,
    )
    db.add(add_book)
    db.commit()
    db.refresh(add_book)
    return add_book

@app.patch("/books/", response_model=edit_book)
def edit_book(book_id:int, book: edit_book, urrent_user: User = Depends(get_current_active_user), db:Session = Depends(get_db)):
    search = db.query(Book).filter(Book.id == book_id).first()
    if not search:
        raise HTTPException(
            status_code=404,
            detail="Book Not Found"
        )
    search.title = book.title
    search.author = book.author
    search.genre = book.genre
    search.release_date = book.release_date
    db.commit()
    db.refresh(search)
    return search

@app.delete("/books/{book_id}")
def delete_book(book_id:int, confirm:delete_book,urrent_user: User = Depends(get_current_active_user), db:Session = Depends(get_db)):
   db_book = db.query(Book).filter(Book.id==book_id).first()
   if not db_book:
       raise HTTPException(
           status_code=404,
           detail="Book id not found!"
       )
   db.delete(db_book)
   db.commit()
   return db.query(Book).all()


@app.get('/books/', response_model=List[retrieving_book])
def get_all_books(urrent_user: User = Depends(get_current_active_user), db:Session = Depends(get_db)):
    return db.query(Book).all()


@app.get("/search/books/")
def get_book(book_name: str, urrent_user: User = Depends(get_current_active_user)):
    API_KEY = "AIzaSyC-WwPWyLqa-Yzj1a99EBMVYZVRpKjeB0g"
    url = f"https://www.googleapis.com/books/v1/volumes?q={book_name}&key={API_KEY}"
    r = requests.get(url)
    data = r.json()

    books = []
    for item in data.get("items", []):
        volume_info = item.get("volumeInfo", {})
        book_data = {
            "title": volume_info.get("title", "No title"),
            "authors": volume_info.get("authors", ["Unknown author"]),
            "description": volume_info.get("description", "No description available")[:250] + "..."
        }
        books.append(book_data)

    return {"results": books}


>>>>>>> 7282bcc (Initial commit: FastAPI book library project)
