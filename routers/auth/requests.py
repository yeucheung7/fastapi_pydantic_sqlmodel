from pydantic import BaseModel, Field

class LoginRequest(BaseModel):
    user_name:str = Field(max_length=50)
    password:str = Field(max_length=50)

class TokenRefreshRequest(BaseModel):
    refresh:str

class TokenCheckRequest(BaseModel):
    token:str