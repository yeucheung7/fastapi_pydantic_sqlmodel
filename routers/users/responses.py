from pydantic import BaseModel
from typing import Self
from models.users import User as UserModel

class SingleUserResponse(BaseModel):
    id: int
    user_name: str
    is_admin: bool
    is_active: bool

    @classmethod
    def from_db_model(cls, db_models: UserModel | list[UserModel]) -> Self | list[Self]:
        def _from_single_instance(db_model: UserModel) -> Self:
            return cls(
                id = db_model.id,
                user_name = db_model.user_name,
                is_admin = db_model.is_admin,
                is_active = db_model.is_active
            )

        if isinstance(db_models, list):
            return [
                _from_single_instance(db_model) for db_model in db_models
            ]
        elif isinstance(db_models, UserModel):
            return _from_single_instance(db_models)
        else:
            raise TypeError(f"from_db_model only accepts User or list of User, {type(db_models)} is provided.")
