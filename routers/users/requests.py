from pydantic import BaseModel, Field
from typing import Self
from models.users import User as UserModel
from util import hash

class CreateUserRequest(BaseModel):
    user_name:str = Field(max_length=50)
    email:str = Field(max_length=100)
    password:str = Field(max_length=50)
    
class DeleteUserRequest(BaseModel):
    uid: int