from fastapi import APIRouter, Depends, HTTPException
from models.users import User as UserModel
from sqlmodel import select
from dependencies.dbsession import SessionDep
from dependencies.auth import require_auth, user_must_be_admin
from util import user as UserUtil
from .requests import *
from .responses import *
from sqlalchemy.exc import IntegrityError, MultipleResultsFound, NoResultFound

user_router = APIRouter(
    dependencies=[Depends(require_auth)]
)

## Auth-ed APIs ##
@user_router.get("/all")
async def read_users(session: SessionDep) -> list[SingleUserResponse]:
    users = session.exec(select(UserModel).where(UserModel.is_active == True)).all()
    return SingleUserResponse.from_db_model(users)

@user_router.get("/uid/{uid}")
async def read_users(uid: int, session: SessionDep) -> SingleUserResponse:
    try:
        user = session.exec(select(UserModel).where(UserModel.id == uid).where(UserModel.is_active == True)).one()
        return SingleUserResponse.from_db_model(user)
    except NoResultFound:
        raise HTTPException(404, detail = "User not found")
    except MultipleResultsFound:
        raise HTTPException(500, detail = "User duplication found")

## Admin only APIs ##
@user_router.post("/", dependencies=[Depends(user_must_be_admin)])
async def create_user(new_user_req: CreateUserRequest, session: SessionDep) -> SingleUserResponse:
    input_user = new_user_req

    ## Adding the user
    new_user, err = UserUtil.create_new_user(input_user.user_name, email = input_user.email, clear_text_pw = input_user.password, session = session)

    ## Handling the result
    if err is None:
        if new_user:
            return SingleUserResponse.from_db_model(new_user)
        else:
            ## Unknown error
            raise HTTPException(500, detail = "Unknown error while creating user")
    else:
        ## Error cases
        if isinstance(err, IntegrityError):
            raise HTTPException(409, detail = "User exists")
        else:
            ## Unknown error
            raise HTTPException(500, detail = "Unknown error while creating user")

@user_router.delete("/", dependencies=[Depends(user_must_be_admin)])
async def delete_user(delete_user_req: DeleteUserRequest, session: SessionDep) -> dict:
    uid = delete_user_req.uid

    ## Find and delete the user
    result: int = UserUtil.delete_user_by_id(uid, session = session)
    if result == 404:
        raise HTTPException(404, detail = "User not found")
    else:
        return {}