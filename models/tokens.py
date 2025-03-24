from sqlmodel import Field, SQLModel

class RefreshTokenRegister(SQLModel, table=True):
    token_id: int | None = Field(default = None, primary_key = True, index = True)
    uid: int ## Not using foreign key since expecting user deletion from DB
    iat: int
    exp: int

class RefreshTokenBlackList(SQLModel, table=True):
    token_id: int = Field(default=None, primary_key = True, index = True)
    reg_time: int ## Unix time stamp when the token is registered
    exp: int