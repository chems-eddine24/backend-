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
import os
from dotenv import load_dotenv
load_dotenv()


engine = create_engine(f"sqlite:///{os.getenv("DB_URL")}")
connection = engine.connect()

def get_db():
    db = Sessionlocal()
    try:
        yield db
    finally:
        db.close()


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
    )
    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    return db_user


@app.post('/token', response_model=Token)
def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    user = db.query(User).filter(User.email==form_data.username).first()
    if not user or not verify_password(form_data.password, user.password_hash):
        raise HTTPException(
            status_code=404,
            detail="wrong info!"
        )
    if not user.is_active:
        raise HTTPException(
            status_code=404,
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
    
    url = f"https://www.googleapis.com/books/v1/volumes?q={book_name}&key={os.getenv("API_KEY")}"
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


