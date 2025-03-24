from fastapi import APIRouter, HTTPException
from models.users import User as UserModel
from sqlmodel import select
from dependencies.dbsession import SessionDep
from .requests import *
from .responses import *
from sqlalchemy.exc import MultipleResultsFound, NoResultFound
from util import hash, token

auth_router = APIRouter()

@auth_router.post("/login")
async def login(login_req: LoginRequest, session: SessionDep) -> FullTokenResponse:
    user_name = login_req.user_name
    password = login_req.password
    
    ## Find the requested user
    try:
        target_user = session.exec(select(UserModel).where(UserModel.user_name == user_name)).one()
        password_hash = target_user.password_hash
        pass_okay: bool = hash.verify(password, password_hash)
        if pass_okay:
            access_token, refresh_token = token.issue_access_refresh_tokens(target_user, session = session)
            return FullTokenResponse(
                access = access_token,
                refresh = refresh_token
            )
    except NoResultFound:
        pass
    except MultipleResultsFound:
        raise HTTPException(500, detail = "User duplication found")

    ## Catch-all failure
    raise HTTPException(404, detail = "incorrect user name or password")

@auth_router.post("/token/refresh")
async def check_refresh_token(refresh_req: TokenRefreshRequest, session: SessionDep) -> FullTokenResponse:
    '''
    Check the validity of the token without leeway
    '''
    token_str = refresh_req.refresh
    try:
        new_ac_token, new_rf_token = token.process_refresh(token_str, session = session)
        return FullTokenResponse(
            access = new_ac_token,
            refresh = new_rf_token
        )
    except token.TokenInvalid:
        raise HTTPException(406, detail = "bad token")
    except Exception:
        raise HTTPException(500, detail = "Unknown server error")
    
@auth_router.post("/token/check")
async def check_token(token_check_req: TokenCheckRequest, session: SessionDep) -> dict:
    '''
    Check the validity of the token without leeway
    '''
    token_str = token_check_req.token
    validity = token.check_token(token_str, session, auto_scope = True, with_leeway = False)
    if validity:
        return {}
    else:
        raise HTTPException(406, detail = "bad token")