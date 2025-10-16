from sqlalchemy import create_engine, MetaData, text, Column, String, Boolean, Integer, Date
from sqlalchemy.orm import declarative_base, sessionmaker
import sqlalchemy as sa
from datetime import date, time

engine = create_engine("sqlite:///library.db", echo=True)
connection = engine.connect()
Base = declarative_base()
Sessionlocal = sessionmaker(autoflush=False, autocommit=False, bind=engine)
metadata = MetaData()

class Book(Base):
    __tablename__="books"
    id = sa.Column(Integer, primary_key=True)
    title = sa.Column(String, nullable=False)
    author = sa.Column(String, nullable=False)
    release_date = sa.Column(Date, nullable=False)
    genre = sa.Column(String, nullable=False)

class User(Base):
    __tablename__ = "users"
    id = sa.Column(Integer, primary_key=True)
    email = sa.Column(String, nullable=False, unique=True)
    password = sa.Column(String, nullable=False)
    password_hash = sa.Column(String, unique=True)
    is_active = sa.Column(Boolean)
Base.metadata.create_all(bind=engine)


