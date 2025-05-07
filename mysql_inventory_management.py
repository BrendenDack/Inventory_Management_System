# Most of initialization from professor's async example
from contextlib import asynccontextmanager # Managing async context lifecycle
from fastapi import FastAPI, HTTPException, Depends, Request  # FastAPI core components
from fastapi.responses import JSONResponse, Response # Custom JSON and response handling
from pydantic import BaseModel, EmailStr, Field  # For data validation and parsing
from typing import List, Optional # Type hints to improve code clarity
import jwt as jwt # Handling JWT authentication
from datetime import datetime, timedelta, timezone # Managing token expiration and timestamps
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine  # Async engine and session from SQLAlchemy
from sqlalchemy.ext.declarative import declarative_base  # Base class for SQLAlchemy models
from sqlalchemy.orm import sessionmaker, declarative_base  # ORM tools
from sqlalchemy import Column, Integer, String, Float, Boolean, LargeBinary, select, text  # Column types and SQL expressions
import re  # Regular expressions module
import bcrypt # Password hashing

import secret_keys # Custom module for storing sensitive key


# ------------------- Database Configuration -------------------

# Database URL for async MySQL connection using credentials from secret_keys
DATABASE_URL = "mysql+aiomysql://"+secret_keys.db_username+":"+secret_keys.db_password+"@localhost/inventory_management" # Async MySQL DB URL

# Create an async SQLAlchemy engine for database interactions
# echo=True enables SQL query logging for debugging
engine = create_async_engine(DATABASE_URL, echo=True)

# Create an async session class
AsyncSessionLocal = sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)

# Base class for ORM models
Base = declarative_base()

# Dependency to get async DB session
async def get_db():  # Dependency function to yield a DB session
    async with AsyncSessionLocal() as session:  # Context manager to open and close session
        yield session

# ------------------- FastAPI Initialization -------------------

# Function to initialize database models (create tables if they don't exist)
async def init_models():
    async with engine.begin() as conn:
        print("Creating tables if they don't exist...")
        await conn.run_sync(Base.metadata.create_all)

# Define the application lifespan context manager
# Ensures database models are initialized when the app starts
@asynccontextmanager
async def lifespan(app: FastAPI):
    await init_models()     
    yield                   

app = FastAPI(lifespan=lifespan)  # Initialize FastAPI app instance


# ------------------- JWT -------------------

# Dependency function to validate JWT tokens from cookies
# Ensures the user is authenticated before accessing protected routes
async def require_token(request: Request):
    token = request.cookies.get("inventory-access-token")

    # Raise an error if no token is found
    if not token:
        raise HTTPException(status_code=401, detail="Missing token")

    try:
        # Decode the JWT token using the secret key and HS256 algorithm
        payload = jwt.decode(token, secret_keys.encrypt_key, algorithms=["HS256"])

        # Check if the token has an expiration field
        exp = payload.get("exp")
        if not exp :
            raise HTTPException(status_code=401, detail="Invalid token")
    except jwt.ExpiredSignatureError:
        # Handle expired tokens
        raise HTTPException(status_code=401, detail="Token expired")
    except jwt.JWTError:
        # Handle other JWT-related errors (e.g., invalid token)
        raise HTTPException(status_code=401, detail="Invalid token")
    
    return payload

# Protected route that requires a valid JWT token
# Demonstrates access to payload data for personalized responses
@app.get("/protected")
async def protected_route(request: Request, jwt_payload = Depends(require_token)):
    print(jwt_payload)
    # Return a personalized message using payload data
    return {"message": f"Welcome {jwt_payload.get("username")}, You are a admin: {jwt_payload.get("isAdmin")}!"}

# Function to create a JWT access token
# Encodes user data (e.g., username, isAdmin) with an expiration time
def create_access_token(data: dict, expires_delta: timedelta = None):
    # Create a copy of the input data
    to_encode = data.copy()
    # Set expiration time for 30 minutes
    expire = datetime.now(timezone.utc) + (expires_delta or timedelta(minutes=30))
    to_encode.update({"exp": expire}) # Add expiration to the payload
    # Encode the payload into a JWT token
    return jwt.encode(to_encode, secret_keys.encrypt_key, algorithm="HS256")

# Function to validate password strength
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

    # Define columns with their data types and constraints
    id = Column(Integer, primary_key=True, index=True) # Primary key with indexing
    name = Column(String(100), unique=True, nullable=False) # Unique item name
    description = Column(String(250), nullable=False) # Item description
    quantity = Column(Integer, nullable=False) # Item quantity
    price = Column(Float, nullable=False) # Item price
    department = Column(String(50), nullable=False) # Department name
    location = Column(String(50), nullable=False)  # Storage location

# User model
class User(Base):
    __tablename__ = "users"

    # Define columns with their data types and constraints
    id = Column(Integer, primary_key=True, index=True) # Primary key with indexing
    username = Column(String(50), unique=True, nullable=False) # Unique username
    passwordsalt = Column(String(256), nullable=False) # Salt for password hashing
    hashedpassword = Column(String(512), nullable=False) # Hashed password
    email = Column(String(255), nullable=False) # User email
    isAdmin = Column(Boolean, nullable=False) # Admin status

# ------------------- Pydantic Schemas -------------------

# Pydantic schema for user registration
class UserCreate(BaseModel):
    username: str = Field(..., min_length=3, max_length=50)
    password: str = Field(..., min_length=8, max_length=255) # Should be hashed
    email: str = Field(..., max_length=255)
    # Enable ORM mode for SQLAlchemy compatibility
    class Config:
        orm_mode = True

# Pydantic schema for user login
class UserLogin(BaseModel):
    username: str = Field(..., min_length=3, max_length=50)
    password: str = Field(..., min_length=8, max_length=255) # Should be hashed

    class Config:
        orm_mode = True

# Pydantic schema for promoting a user to admin
class PromoteAdmin(BaseModel):
    username: str = Field(..., min_length=3, max_length=50)  # Username to promote
    adminPassword: str = Field(..., min_length=8, max_length=255) # Admin password for authorization

# Pydantic schema for user output
class UserOut(BaseModel):
    id: int
    username: str

    class Config:
        orm_mode = True

# Pydantic schema for creating a new item
class ItemCreate(BaseModel):
    name: str = Field(..., min_length=3, max_length=100)
    description: str = Field(..., max_length=250) 
    quantity: int = Field(ge=0)
    price: float = Field(ge = 0)
    department: str = Field(..., max_length=50)
    location: str = Field(..., max_length=50)

    class Config:
        orm_mode = True

# Pydantic schema for updating an existing item
class ItemUpdate(BaseModel):
    name: Optional[str] = Field(default=None, min_length=3, max_length=100)
    description: Optional[str] = Field(default=None, max_length=250)
    quantity: Optional[int] = Field(ge=0, default=None)
    price: Optional[float] = Field(ge=0, default=None)
    department: Optional[str] = Field(default=None, max_length=50)
    location: Optional[str] = Field(default=None, max_length=50)

    class Config:
        orm_mode = True
        
# Pydantic schema for item output
class ItemOut(BaseModel):
    id: int
    name: str
    description: str
    quantity: int
    price: float
    department: str
    location: str

    class Config:
        orm_mode = True


@app.post("/")
async def index():
    return {"message": "There is no index page"}

#login/register methods
@app.post("/register", response_model=UserOut)
async def register(user: UserCreate, db: AsyncSession = Depends(get_db)):
    # Check if user exists
    result = await db.execute(select(User).where(User.username == user.username))
    existing_user = result.scalar_one_or_none()
    if existing_user:
        raise HTTPException(status_code=400, detail="Username already taken")
    
    # Validate the password strength
    valid_status = validate_password(user.password)
    if valid_status:
        raise HTTPException(status_code=400, detail=valid_status)
    
    # Generate a salt and hash the password
    salt = bcrypt.gensalt()
    hashed = bcrypt.hashpw(bytes(user.password, 'utf-8'), salt)

    # Create new user
    new_user = User(
        username=user.username,
        passwordsalt=salt,
        hashedpassword=hashed,
        email = user.email,
        isAdmin = False
    )
    # Add the user to the database and commit
    db.add(new_user)
    await db.commit()
    await db.refresh(new_user)
    return new_user

# User login
@app.post("/login")
async def login(user: UserLogin, db: AsyncSession = Depends(get_db)):
    # Retrieve the user from the database
    result = await db.execute(select(User).where(User.username == user.username))
    db_user = result.scalar_one_or_none()
    
    # Hash the provided password with the stored salt
    hashedpass = bcrypt.hashpw(bytes(user.password, 'utf-8'),bytes(db_user.passwordsalt, 'utf-8'))
    
    # Verify the user exists and the password is correct
    if not db_user or hashedpass != bytes(db_user.hashedpassword, 'utf-8'):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    # Create a JWT access token
    access_token = create_access_token(data={"username": db_user.username, "isAdmin": db_user.isAdmin})
    # Set the token in a cookie and return a success message
    response = JSONResponse(content={"message": "Login successful"})
    response.set_cookie(
        key="inventory-access-token",
        value=access_token,
        httponly=True,
        max_age=1800,  # Cookie expires in 30 minutes
        secure=False,  # Set to True in production with HTTPS
        samesite="lax"
    )
    return response
# User logout
@app.post("/logout")
async def logout():
    response = JSONResponse(content={"message": "Logged out"})
    response.delete_cookie("inventory-access-token")
    return response

# User to admin
@app.post("/promoteAdmin")
async def promote(user: PromoteAdmin, db : AsyncSession = Depends(get_db)):
    # Retrieve the user from the database
    result = await db.execute(select(User).where(User.username == user.username))
    db_user = result.scalar_one_or_none()
    # Check if the user exists
    if not db_user:
        raise HTTPException(status_code=401, detail="No user found")
    # Verify the admin password
    if user.adminPassword != secret_keys.admin_password:
        raise HTTPException(status_code=401, detail="Invalid credentials")
    # Set the user as admin and update the database
    db_user.isAdmin = True
    await db.commit()
    await db.refresh(db_user)
    # Return a message indicating the user needs to log in again
    return {"message": "Promoted User, please have the promoted user log in to refresh the token."}

# Admin CRUD operations
# Create a new item
@app.post("/items")
async def create_item(
    item: ItemCreate,
    db: AsyncSession = Depends(get_db),
    jwt_payload = Depends(require_token)  # This line enforces login
):
    # Check if the user is an admin
    if not jwt_payload.get("isAdmin") == True:
        raise HTTPException(status_code=401, detail="Unauthorized Action")

    # Check if an item with the same name already exists
    check_name = await db.execute(select(Item).where(Item.name == item.name))
    db_item = check_name.scalar_one_or_none()
    if db_item:
        raise HTTPException(status_code=401, detail="Item of that name already exists")
    # Create a new item instance and save it to the database
    new_item = Item(**item.dict())
    db.add(new_item)
    await db.commit()
    await db.refresh(new_item)
    return new_item

# Delete an item by the ID
@app.delete("/items/{item_id}")
async def delete_item(
    item_id: int,
    db: AsyncSession = Depends(get_db),
    jwt_payload = Depends(require_token)  # This line enforces login
):
    # Check if the user is an admin
    if not jwt_payload.get("isAdmin") == True:
        raise HTTPException(status_code=401, detail="Unauthorized Action")

    # Retrieve the item from the database
    result = await db.execute(select(Item).where(Item.id == item_id))
    db_item = result.scalar_one_or_none()

    # Delete the item and commit the change
    await db.delete(db_item)
    await db.commit()
    return {"message":"Item deleted"}

# Default CRUD operations
# Update an existing item
@app.put("/items/{item_id}")
async def update_item(
    item_id: int,
    item: ItemUpdate,
    db: AsyncSession = Depends(get_db),
    jwt_payload = Depends(require_token)  # This line enforces login
):
    # Retrieve the item from the database
    result = await db.execute(select(Item).where(Item.id == item_id))
    db_item = result.scalar_one_or_none()
    # Check if the new name is already taken by another item
    if item.name != None:
        check_name = await db.execute(select(Item).where(Item.name == item.name))
        db_name_item = check_name.scalar_one_or_none()
        if (db_name_item != db_item) and db_name_item:
            raise HTTPException(status_code=401, detail="Item of that name already exists")
    # Check if the item exists
    if not db_item:
        raise HTTPException(status_code=401, detail="No item found")
    # Update only the provided fields
    if item.name != None:
        db_item.name = item.name
    if item.description != None:
        db_item.description = item.description
    if item.quantity != None:
        db_item.quantity = item.quantity
    if item.price != None:
        db_item.price = item.price
    if item.department != None:
        db_item.department = item.department
    if item.location != None:
        db_item.location = item.location
        
    # Commit the changes and refresh the item
    await db.commit()
    await db.refresh(db_item)
    return db_item

# Retrieve all items
@app.get("/items", response_model=List[ItemOut])
async def read_items(
    db: AsyncSession = Depends(get_db),
    jwt_payload = Depends(require_token)  # Enforce login
):
    # Retrieve all items from the database
    result = await db.execute(select(Item))
    items = result.scalars().all()
    return items