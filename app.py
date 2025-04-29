# Most of initialization from professor's async example
from fastapi import FastAPI, HTTPException, Depends  # FastAPI core components
from pydantic import BaseModel, EmailStr, Field, List  # For data validation and parsing
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine  # Async engine and session from SQLAlchemy
from sqlalchemy.ext.declarative import declarative_base  # Base class for SQLAlchemy models
from sqlalchemy.orm import sessionmaker, declarative_base  # ORM tools
from sqlalchemy import Column, Integer, String, select  # Column types and SQL expressions
import re  # Regular expressions module

import secret_keys

# ------------------- FastAPI Initialization -------------------
app = FastAPI()  # Initialize FastAPI app instance

# ------------------- Database Configuration -------------------
DATABASE_URL = "mysql+aiomysql://"+secret_keys.db_username+":"+secret_keys.db_password+"localhost/inventory_management" # Async MySQL DB URL

engine = create_async_engine(DATABASE_URL, echo=True)  # Create async engine

# Create an async session class
AsyncSessionLocal = sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)

# Base class for ORM models
Base = declarative_base()

# Dependency to get async DB session
async def get_db():  # Dependency function to yield a DB session
    async with AsyncSessionLocal() as session:  # Context manager to open and close session
        yield session

# ------------------- Database Models -------------------

# Item model
class Item(Base):
    __tablename__ = "items"  # Name of the table

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(100), nullable=False)
    description = Column(String(250), nullable=False)
    quantity = Column(Integer, nullable=False)
    price = Column(float, nullable=False)
    department = Column(String(50), nullable=False)
    location = Column(String(50), nullable=False)

# User model
class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(50), unique=True, nullable=False)
    password = Column(String(255), nullable=False) # Should be hashed

# ------------------- Pydantic Schemas -------------------

class UserCreate(BaseModel):
    uername: str = Field(..., ge=3, le=50)
    password: str = Field(..., ge=8, le=255) # Should be hashed

    class Config:
        orm_mode = True

class UserOut(BaseModel):
    id: int
    username: str

    class Config:
        orm_mode = True

class ItemCreate(BaseModel):
    name: str = Field(..., ge=3, le=100)
    description: str = Field(..., le=250)
    quantity: int
    price: float
    # We want this to be a List[str] that is constrained, but im not sure how to do that, most I could get is this site
    # https://docs.python.org/3/library/typing.html#typing.Annotated
    department: str = Field(..., le=50)
    location: str = Field(..., le=50)

    class Config:
        orm_mode = True

class ItemOut(BaseModel):
    id: int
    name: str
    description: str
    quantity: int
    price: float
    # We want this to be a List[str] that is constrained, but im not sure how to do that, most I could get is this site
    # https://docs.python.org/3/library/typing.html#typing.Annotated
    department: str
    location: str

    class Config:
        orm_mode = True

