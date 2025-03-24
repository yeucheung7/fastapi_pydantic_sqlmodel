from sqlmodel import Field, SQLModel

class User(SQLModel, table=True):
    id: int | None = Field(default=None, primary_key=True)
    user_name: str = Field(unique = True, nullable = False)
    password_hash: str
    min_token_verison: int = 0
    is_admin: bool = False
    is_active: bool = False