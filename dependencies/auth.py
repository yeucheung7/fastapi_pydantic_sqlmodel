from typing import Annotated
from fastapi import Header, HTTPException
from models.users import User as UserModel
from util import token
from util import user as UserUtil
from dependencies.dbsession import SessionDep

async def require_auth(session: SessionDep, authorization: Annotated[str | None, Header()] = None):
    if authorization is None:
        raise HTTPException(401, detail = "Authentication required")

    if authorization.startswith("Bearer "):
        ## Try to get the access token
        authorization = str(authorization)
        ac_token = authorization[7:]
        if len(ac_token) < 10:
            raise HTTPException(400, detail = "Bad token")
        else:
            valid = token.check_token(ac_token, session = session, check_access = True) ## Check access with leeway
            if not valid:
                raise HTTPException(400, detail = "Bad token")
    else:
        raise HTTPException(401, detail = "Authentication required")

async def user_must_be_admin(session: SessionDep, authorization: Annotated[str | None, Header()] = None):
    if authorization is None:
        raise HTTPException(401, detail = "Authentication required")
    
    if authorization.startswith("Bearer "):
        ## Try to get the access token
        authorization = str(authorization)
        ac_token = authorization[7:]
        if len(ac_token) < 10:
            raise HTTPException(400, detail = "Bad token")
        else:
            valid = token.check_token(ac_token, session = session, check_access = True) ## Check access with leeway
            if not valid:
                raise HTTPException(400, detail = "Bad token")
            
            ## Admin check
            token_body = token.decode_jwt_no_verification(ac_token)
            uid = token_body["uid"]
            user: UserModel = UserUtil.select_user_by_id(uid, session)
            if user is None:
                raise HTTPException(404, detail = "User not found")
            if user.is_admin == False:
                raise HTTPException(403, detail = "Admin right required")
    else:
        raise HTTPException(401, detail = "Authentication required")