from pydantic import BaseModel
from typing import Optional
from datetime import date



class add_book(BaseModel):
    title: str
    author: str
    genre: str
    release_date: date
class retrieving_book(BaseModel):
    id:int
    title: str
    author: str
    genre: str
    release_date: date

    class Config:
        orm_mode = True

class edit_book(BaseModel):
    title: Optional[str] = None
    author: Optional[str] = None
    genre: Optional[str] = None
    release_date: Optional[date] = None

class delete_book(BaseModel):
    confirmation: str

class TokenData(BaseModel):
    email: Optional[str] = None

class UserCreate(BaseModel):
    email : str
    password: str

class UserResponse(BaseModel):
    email: str
    password: str
    is_active: bool

class Token(BaseModel):
    access_token: str
    token_type: str

class TokenData(BaseModel):
    email: Optional[str] = None
