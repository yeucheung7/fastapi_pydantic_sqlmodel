from pydantic import BaseModel, Field

class FullTokenResponse(BaseModel):
    access:str
    refresh:str