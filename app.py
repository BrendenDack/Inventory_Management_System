# Most of initialization from professor's async example
from contextlib import asynccontextmanager
from fastapi import FastAPI, HTTPException, Depends, Request  # FastAPI core components
from fastapi.responses import JSONResponse
from pydantic import BaseModel, EmailStr, Field  # For data validation and parsing
from typing import List
import jwt as jwt
from datetime import datetime, timedelta, timezone
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine  # Async engine and session from SQLAlchemy
from sqlalchemy.ext.declarative import declarative_base  # Base class for SQLAlchemy models
from sqlalchemy.orm import sessionmaker, declarative_base  # ORM tools
from sqlalchemy import Column, Integer, String, Float, select, text  # Column types and SQL expressions
import re  # Regular expressions module

import secret_keys


# ------------------- Database Configuration -------------------
DATABASE_URL = "mysql+aiomysql://"+secret_keys.db_username+":"+secret_keys.db_password+"@localhost/inventory_management" # Async MySQL DB URL

engine = create_async_engine(DATABASE_URL, echo=True)  # Create async engine

# Create an async session class
AsyncSessionLocal = sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)

# Base class for ORM models
Base = declarative_base()

# Dependency to get async DB session
async def get_db():  # Dependency function to yield a DB session
    async with AsyncSessionLocal() as session:  # Context manager to open and close session
        yield session

# ------------------- FastAPI Initialization -------------------

async def init_models():
    async with engine.begin() as conn:
        print("Creating tables if they don't exist...")
        await conn.run_sync(Base.metadata.create_all)

@asynccontextmanager
async def lifespan(app: FastAPI):
    await init_models()     
    yield                   

app = FastAPI(lifespan=lifespan)  # Initialize FastAPI app instance


# ------------------- JWT -------------------
async def require_token(request: Request):
    token = request.cookies.get("inventory-access-token")

    if not token:
        raise HTTPException(status_code=401, detail="Missing token")

    try:
        payload = jwt.decode(token, secret_keys.encrypt_key, algorithms=["HS256"])
        username = payload.get("sub")
        if not username:
            raise HTTPException(status_code=401, detail="Invalid token")
        request.state.user = username  # Optional: save user in request
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except jwt.JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")
    
    return payload

@app.get("/protected")
async def protected_route(request: Request, _: None = Depends(require_token)):
    return {"message": f"Welcome {request.state.user}!"}

def create_access_token(data: dict, expires_delta: timedelta = None):
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + (expires_delta or timedelta(minutes=30))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, secret_keys.encrypt_key, algorithm="HS256")

def validate_password(password: str):  # Validate password strength
    if len(password) < 8:
        return "Password must be at least 8 characters long."
    if not re.search(r'\d', password):
        return "Password must contain at least one digit."
    if not re.search(r'[A-Z]', password):
        return "Password must contain at least one uppercase letter."
    if not re.search(r'[a-z]', password):
        return "Password must contain at least one lowercase letter."
    if not re.search(r'[\W_]', password):
        return "Password must contain at least one special character."
    return None  # Return None if valid

# ------------------- Database Models -------------------

# Item model
class Item(Base):
    __tablename__ = "items"  # Name of the table

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(100), nullable=False)
    description = Column(String(250), nullable=False)
    quantity = Column(Integer, nullable=False)
    price = Column(Float, nullable=False)
    department = Column(String(50), nullable=False)
    location = Column(String(50), nullable=False)

# User model
class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(50), unique=True, nullable=False)
    password = Column(String(255), nullable=False) # Should be hashed
    email = Column(String(255), nullable=False)
    isAdmin = Column(bool, nullable=False)

# ------------------- Pydantic Schemas -------------------

class UserCreate(BaseModel):
    username: str = Field(..., min_length=3, max_length=50)
    password: str = Field(..., min_length=8, max_length=255) # Should be hashed
    email: str = Field(..., max_length=255)

    class Config:
        orm_mode = True

class UserLogin(BaseModel):
    username: str = Field(..., min_length=3, max_length=50)
    password: str = Field(..., min_length=8, max_length=255) # Should be hashed

    class Config:
        orm_mode = True

class PromoteAdmin(BaseModel):
    username: str = Field(..., min_length=3, max_length=50)
    adminPassword: str = Field(..., min_length=8, max_length=255) # Should be hashed

class UserOut(BaseModel):
    id: int
    username: str

    class Config:
        orm_mode = True

class ItemCreate(BaseModel):
    name: str = Field(..., min_length=3, max_length=100)
    description: str = Field(..., max_length=250)
    quantity: int
    price: float
    # We want this to be a List[str] that is constrained, but im not sure how to do that, most I could get is this site
    # https://docs.python.org/3/library/typing.html#typing.Annotated
    department: str = Field(..., max_length=50)
    location: str = Field(..., max_length=50)

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


@app.post("/")
async def dummyfunc():
    return {"message": "Hello dummy"}

#login/register methods
@app.post("/register", response_model=UserOut)
async def register(user: UserCreate, db: AsyncSession = Depends(get_db)):
    # Check if user exists
    result = await db.execute(select(User).where(User.username == user.username))
    existing_user = result.scalar_one_or_none()
    if existing_user:
        raise HTTPException(status_code=400, detail="Username already taken")

    valid_status = validate_password(user.password)
    if valid_status:
        return HTTPException(status_code=400, detail=valid_status)

    # Create new user
    new_user = User(
        username=user.username,
        password=user.password,
        email = user.email
    )
    db.add(new_user)
    await db.commit()
    await db.refresh(new_user)
    return new_user

from fastapi.responses import JSONResponse

from fastapi.responses import Response

@app.post("/login")
async def login(user: UserLogin, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(User).where(User.username == user.username))
    db_user = result.scalar_one_or_none()
    
    if not db_user or user.password != db_user.password:
        raise HTTPException(status_code=401, detail="Invalid credentials")

    access_token = create_access_token(data={"sub": db_user.username})
    
    response = JSONResponse(content={"message": "Login successful"})
    response.set_cookie(
        key="inventory-access-token",
        value=access_token,
        httponly=True,
        max_age=1800,  # 30 minutes
        secure=False,  # Set to True in production with HTTPS
        samesite="lax"
    )
    return response

@app.post("/logout")
async def logout():
    response = JSONResponse(content={"message": "Logged out"})
    response.delete_cookie("inventory-access-token")
    return response

@app.post("/PromoteAdmin")
async def promote(user: PromoteAdmin, db : AsyncSession = Depends(get_db)):
    
    result = await db.execute(select(User).where(User.username == user.username))
    db_user = result.scalar_one_or_none()
    
    if not db_user:
        raise HTTPException(status_code=401, detail="No user found")
    
    if user.adminPassword != secret_keys.admin_password:
        return HTTPException(status_code=401, detail="Invalid credentials")
    



# CRUD operations
@app.post("/additem", response_model=ItemOut)
async def create_item(
    item: ItemCreate,
    db: AsyncSession = Depends(get_db),
    _: None = Depends(require_token)  # This line enforces login
):
    new_item = Item(**item.dict())
    db.add(new_item)
    await db.commit()
    await db.refresh(new_item)
    return new_item

@app.get("/items", response_model=List[ItemOut])
async def read_items(
    db: AsyncSession = Depends(get_db),
    _: None = Depends(require_token)  # Enforce login
):
    result = await db.execute(select(Item))
    items = result.scalars().all()
    return items