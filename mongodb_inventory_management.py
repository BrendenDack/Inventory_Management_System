# Most of initialization from professor's async example
from fastapi import FastAPI, HTTPException, Depends, Request, Body, status  # FastAPI core components
from fastapi.responses import JSONResponse, Response
from fastapi.encoders import jsonable_encoder
from pydantic import BaseModel, EmailStr, Field, ConfigDict, GetJsonSchemaHandler  # For data validation and parsing
from pydantic.functional_validators import BeforeValidator
from pydantic.json_schema import JsonSchemaValue
from typing import List, Optional, Any
from typing_extensions import Annotated
import jwt as jwt
from datetime import datetime, timedelta, timezone
import re  # Regular expressions module
import bcrypt

import secret_keys

from bson.objectid import ObjectId
import motor.motor_asyncio
from pymongo import ReturnDocument

# ------------------- Database Configuration -------------------
DATABASE_URL = "mongodb://localhost:27017/inventory_management" # Async Mongo DB URL

client = motor.motor_asyncio.AsyncIOMotorClient(DATABASE_URL)
db = client.get_database("inventory_management")
users = db.get_collection("users")
items = db.get_collection("items")

PyObjectId = Annotated[str, BeforeValidator(str)]

# ------------------- FastAPI Initialization -------------------     

app = FastAPI()  # Initialize FastAPI app instance

# ------------------- JWT -------------------
async def require_token(request: Request):
    token = request.cookies.get("inventory-access-token")

    if not token:
        raise HTTPException(status_code=401, detail="Missing token")

    try:
        payload = jwt.decode(token, secret_keys.encrypt_key, algorithms=["HS256"])

        exp = payload.get("exp")
        if not exp :
            raise HTTPException(status_code=401, detail="Invalid token")
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except jwt.JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")
    
    return payload

@app.get("/protected")
async def protected_route(request: Request, jwt_payload = Depends(require_token)):
    print(jwt_payload)
    return {"message": f"Welcome {jwt_payload.get("username")}, You are a admin: {jwt_payload.get("isAdmin")}!"}

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

class PyObjectId(ObjectId):
    @classmethod
    def __get_validators__(cls):
        yield cls.validate
    
    @classmethod
    def validate(cls, v, field=None):
        if not ObjectId.is_valid(v):
            raise ValueError('Invalid ObjectId')
        return ObjectId(v)

    @classmethod
    def __get_pydantic_json_schema__(cls, core_schema: Any, handler: GetJsonSchemaHandler) -> JsonSchemaValue:
        json_schema = handler(core_schema)
        json_schema.update(
            {
                "type": "string",
                "examples": ["507f1f77bcf86cd799439011"],
                "title": "ObjectId"
            }
        )
        return json_schema

# Item model
class Item(BaseModel):
    __tablename__ = "items"  # Name of the table

    id: Optional[PyObjectId] = Field(default_factory=PyObjectId, alias="_id",)
    name: str = Field(...)
    description: str = Field(...)
    quantity: int = Field(...)
    price: float = Field(...)
    department: str = Field(...)
    location: str = Field(...)

    class Config:
        populate_by_name = True
        arbitrary_types_allowed = True
        json_encoders = {ObjectId: str}

# User model
class User(BaseModel):
    __tablename__ = "users"

    id: Optional[PyObjectId] = Field(alias="_id", default=None)
    username: str = Field(...)
    passwordsalt: str = Field(...)
    hashedpassword: str = Field(...) # Should be hashed
    email: EmailStr = Field(...)
    isAdmin: bool = Field(...)
    
    class Config:
        populate_by_name = True
        arbitrary_types_allowed = True
        json_encoders = {ObjectId: str}

# ------------------- Pydantic Schemas -------------------

class UserCreate(BaseModel):
    username: str = Field(..., min_length=3, max_length=50)
    password: str = Field(..., min_length=8, max_length=255) # Should be hashed
    email: EmailStr = Field(..., max_length=255)

    class Config:
        from_attributes = True

class UserLogin(BaseModel):
    username: str = Field(..., min_length=3, max_length=50)
    password: str = Field(..., min_length=8, max_length=255) # Should be hashed

    class Config:
        from_attributes = True

class PromoteAdmin(BaseModel):
    username: str = Field(..., min_length=3, max_length=50)
    adminPassword: str = Field(...) # Should be hashed

class UserOut(BaseModel):
    id: PyObjectId
    username: str

    class Config:
        from_attributes = True

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
        from_attributes = True

class ItemUpdate(BaseModel):
    name: Optional[str] = Field(default=None, min_length=3, max_length=100)
    description: Optional[str] = Field(default=None, max_length=250)
    quantity: Optional[int] = Field(default=None)
    price: Optional[float] = Field(default=None)
    # We want this to be a List[str] that is constrained, but im not sure how to do that, most I could get is this site
    # https://docs.python.org/3/library/typing.html#typing.Annotated
    department: Optional[str] = Field(default=None, max_length=50)
    location: Optional[str] = Field(default=None, max_length=50)

    class Config:
        from_attributes = True

class ItemOut(BaseModel):
    id: PyObjectId
    name: str
    description: str
    quantity: int
    price: float
    # We want this to be a List[str] that is constrained, but im not sure how to do that, most I could get is this site
    # https://docs.python.org/3/library/typing.html#typing.Annotated
    department: str
    location: str

    class Config:
        from_attributes = True

# Helper function to convert MongoDB ObjectId to string
def mongo_to_dict(item):
    """Recursively convert ObjectId to string in the dictionary"""
    if isinstance(item, dict):
        return {k: mongo_to_dict(v) for k, v in item.items()}
    elif isinstance(item, ObjectId):
        return str(item)
    return item


@app.post("/")
async def index():
    return {"message": "There is no index page"}

#login/register methods
@app.post("/register")
async def register(user: UserCreate = Body(...)):
    # Check if user exists
    existing_user = await users.find_one({"username":user.username})
    if existing_user:
        raise HTTPException(status_code=400, detail="Username already taken")

    valid_status = validate_password(user.password)
    if valid_status:
        raise HTTPException(status_code=400, detail=valid_status)
    
    salt = bcrypt.gensalt()
    hashed = bcrypt.hashpw(bytes(user.password, 'utf-8'), salt)

    # Create new user
    new_user = User(
        username=user.username,
        passwordsalt=salt.decode('utf-8'),
        hashedpassword=hashed.decode('utf-8'),
        email = user.email,
        isAdmin = False
    )
    await users.insert_one(new_user.model_dump(by_alias=True, exclude=["id"]))

    return {"message":"User registered"}

@app.post("/login")
async def login(user: UserLogin = Body(...)):
    result = await users.find_one({"username" : user.username})
    
    if not result or not bcrypt.checkpw(user.password.encode('utf-8'), bytes(result['hashedpassword'], 'utf-8')):
        raise HTTPException(status_code=401, detail="Invalid credentials")

    access_token = create_access_token(data={"username": result["username"], "isAdmin": result["isAdmin"]})
    
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

@app.post("/promoteAdmin")
async def promote(user: PromoteAdmin = Body(...)):
    
    result = await users.find_one({"username" : user.username})
    
    if not result:
        raise HTTPException(status_code=401, detail="No user found")
    
    if user.adminPassword != secret_keys.admin_password:
        raise HTTPException(status_code=401, detail="Invalid credentials")
    
    await users.find_one_and_update(
        {"username" : user.username},
        {"$set": {"isAdmin":True}},
        return_document=ReturnDocument.AFTER
    )

    return {"message": "Promoted User, please have the promoted user log in to refresh the token."}



# Admin CRUD operations
@app.post("/items")
async def create_item(
    item: ItemCreate = Body(...),
    jwt_payload = Depends(require_token)  # This line enforces login
):
    if not jwt_payload.get("isAdmin") == True:
        raise HTTPException(status_code=401, detail="Unauthorized Action")

    check_name = await items.find_one({"name" : item.name})
    if check_name:
        raise HTTPException(status_code=401, detail="Item of that name already exists")

    new_item = Item(**item.dict())
    await items.insert_one(new_item.dict(by_alias=True))
    return new_item

@app.delete("/items/{item_id}")
async def delete_item(
    item_id: str,
    jwt_payload = Depends(require_token)  # This line enforces login
):
    if not jwt_payload.get("isAdmin") == True:
        raise HTTPException(status_code=401, detail="Unauthorized Action")

    result = await items.find_one({"_id" : ObjectId(item_id)})

    delete_result = await items.delete_one({"_id":ObjectId(item_id)})

    return {"message":"Item deleted"}

# Default CRUD operations
@app.put("/items/{item_id}")
async def update_item(
    item_id: str,
    item: ItemUpdate = Body(...),
    jwt_payload = Depends(require_token)  # This line enforces login
):
    result = await items.find_one({"_id" : ObjectId(item_id)})
    
    if not result:
        raise HTTPException(status_code=404, detail="No item found")

    update_data = {}
    if item.name != None:
        update_data["name"] = item.name
    if item.description != None:
        update_data["description"] = item.description
    if item.quantity != None:
        update_data["quantity"] = item.quantity
    if item.price != None:
        update_data["price"] = item.price
    if item.department != None:
        update_data["department"] = item.department
    if item.location != None:
        update_data["location"] = item.location
    
    if update_data.get("name"):
        name_check = await items.find_one({"name": update_data['name']})

        if name_check and (name_check['_id'] != result['_id']):
            raise HTTPException(status_code=400, detail="Item with that name already exists")

    updated = await items.find_one_and_update(
        {"_id": ObjectId(item_id)},
        {"$set": update_data},
        return_document=ReturnDocument.AFTER
    )
    
    return mongo_to_dict(updated)


@app.get("/items")
async def read_items(
    jwt_payload = Depends(require_token)  # Enforce login
):
    items_list = await items.find().to_list(length=200)
    for item in items_list:
        item["_id"] = str(item["_id"])
    return items_list