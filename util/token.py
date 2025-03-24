from jwt.exceptions import InvalidTokenError, InvalidSignatureError, ExpiredSignatureError
from sqlalchemy.exc import MultipleResultsFound, NoResultFound
from sqlalchemy import delete as sa_delete
from models.users import User as UserModel
from models.tokens import RefreshTokenRegister, RefreshTokenBlackList
from dependencies.dbsession import SessionDep
from sqlmodel import select
from util import user as UserUtil
import os
import json
import time
import jwt

## JWT released parameters ##
with open(os.path.join("config", "settings.json"), "r") as setting_file:
    setting_dict = json.load(setting_file)
    jwt_dict = setting_dict["jwt"]
__secret__: str = jwt_dict["sign_key"]
__access_lifetime_s__ = jwt_dict["access_lifetime_s"]
__refresh_lifetime_s__ = jwt_dict["refresh_lifetime_s"]
__leeway_s__ = jwt_dict["leeway_s"]

## Exceptions ##
class TokenInvalid(ValueError):
    "Bad refresh token, or on blacklist"
    def __init__(self, msg="Bad refresh token"):
        super().__init__(msg)

## Simple JWT option ##
def sign_jwt(payload: dict) -> str:
    return jwt.encode(payload, __secret__, algorithm="HS256")

def decode_jwt_no_verification(jwt_str: str) -> dict:
    return jwt.decode(jwt_str, options={"verify_signature": False})

def decode_jwt(jwt_str: str, with_leeway: bool = True, overide_leeway: int = None) -> dict:
    if with_leeway:
        leeway = __leeway_s__ if overide_leeway is None else overide_leeway
        return jwt.decode(jwt_str, __secret__, algorithms=["HS256"], leeway = leeway)
    else:
        return jwt.decode(jwt_str, __secret__, algorithms=["HS256"])
        
def create_token(user: UserModel, session: SessionDep, is_access: bool = True, lifetime_s : int = None):
    ## Basic token creation
    token_version = user.min_token_verison
    uid = user.id
    iat = int(time.time())
    scope = "access" if is_access else "refresh"
    if lifetime_s is None:
        ## Using default lifetime if life time setting is not overidden in the function call
        lifetime_s = __access_lifetime_s__ if is_access else __refresh_lifetime_s__
    exp =  int(iat + lifetime_s)
    payload = {
        "uid": uid,
        "version": token_version,
        "iat": iat,
        "exp": exp,
        "scope": scope
    }

    ## Refresh token registration
    if is_access == False:
        new_token_registry: RefreshTokenRegister = RefreshTokenRegister(
            uid = uid,
            iat = iat,
            exp = exp,
        )

        ## Add to DB and get an ID
        session.add(new_token_registry)
        session.commit()
        session.refresh(new_token_registry)

        ## token ID
        token_id = new_token_registry.token_id
        payload = payload | {"token_id": token_id}

    ## Token signing
    jwt_token = sign_jwt(payload)
    return jwt_token

def check_token(token: str, session: SessionDep, auto_scope: bool = True, check_access: bool = False, check_refresh: bool = False, test_exp: bool = True, check_active: bool = True, check_admin: bool = False, with_leeway: bool = True, overide_leeway: int = None) -> bool:
    ## Check token validity and expiration
    try:
        token_payload = decode_jwt(token)
    except Exception:
        return False
    
    ## Check for token version -> Reject version nolonger accepted
    token_keys = list(token_payload.keys())
    if not (("uid" in token_keys) and ("version" in token_keys)):
        return False
    
    uid = token_payload["uid"]
    token_version = token_payload["version"]
    user_model: UserModel = UserUtil.select_user_by_id(uid, session = session)
    if user_model.min_token_verison > token_version:
        return False ## Old token

    ## User is active check
    if check_active:
        if user_model.is_active == False:
            return False

    ## User is admin check
    if check_admin:
        if user_model.is_admin == False:
            return False

    ## Auto scope checking
    if auto_scope == True and (check_access == False and check_refresh == False):
        if not "scope" in token_payload.keys():
            return False
        token_scope = token_payload["scope"]
        if token_scope == "access":
            check_access = True
        elif token_scope == "refresh":
            check_refresh = True
        else:
            return False ## Bad token: Unknown scope

    ## Checking expiration again
    if test_exp:
        if not "exp" in token_payload.keys():
            return False
        exp: int = token_payload["exp"]

        if with_leeway:
            leeway = __leeway_s__ if overide_leeway is None else overide_leeway
            if exp + leeway < int(time.time()):
                return False
        else:
            if exp < int(time.time()):
                return False
    
    ## Specific check for token scope
    if not "scope" in token_payload.keys():
        return False
    scope = token_payload["scope"]
    if (check_access == False) and (check_refresh == False):
        return True
    elif check_access:
        if scope == "access":
            return True
        else:
            return False
    elif check_refresh:
        if scope != "refresh": ## Still need to confirm token is not on blacklist
            return False
    
    ### Only refresh tokens are remaining beyond this line ###

    ## Refresh token blacklist lookup
    if scope == "refresh":
        token_id = token_payload["token_id"]
        result = blacklisted_token_lookup(token_id, session)

        if result:
            ## Refresh token is on blacklist
            return False
        else:
            ## Refresh token not on blacklist
            return True

    ## Catch all False
    return False

## Authentication-side operations ##
def issue_access_refresh_tokens(user: UserModel, session: SessionDep, access_lifetime_s: int = None, refresh_lifetime_s: int = None) -> tuple[str, str]:
    access_token = create_token(user, session = session, is_access = True, lifetime_s = access_lifetime_s)
    refresh_token = create_token(user, session = session, is_access = False, lifetime_s = refresh_lifetime_s)
    return access_token, refresh_token

def issue_access_tokens(user: UserModel, session: SessionDep, lifetime_s: int = None) -> str:
    access_token = create_token(user, session = session, is_access = True, lifetime_s = lifetime_s)
    return access_token

def process_refresh(refresh_token: str, session: SessionDep) -> tuple[str, str]:
    error_invalid_token = TokenInvalid("bad refresh token")

    ## Validate the refresh token
    validity = check_token(refresh_token, session = session, check_refresh = True) ## Black list lookup included
    if not validity:
        raise error_invalid_token
    
    ## Get user from token (to confirm the user is still existing and active)
    old_token: dict = decode_jwt(refresh_token)
    uid = int(old_token["uid"])
    token_id = int(old_token["token_id"])
    exp = int(old_token["exp"])
    target_user: UserModel = None
    try:
        target_user = session.exec(select(UserModel).where(UserModel.id == uid)).one()
    except (NoResultFound, MultipleResultsFound):
        raise error_invalid_token

    ## Add used refresh token to the black list
    refresh_token_blacklisting(token_id, exp, session)

    ## Make the access and refresh tokens
    return issue_access_refresh_tokens(target_user, session = session)

## Refresh token blacklisting ##
def refresh_token_blacklisting(token_id: int, exp: int, session: SessionDep):
    ## Add used refresh token to the black list
    new_black_listing: RefreshTokenBlackList = RefreshTokenBlackList(
        token_id = token_id,
        reg_time = int(time.time()),
        exp = exp,
    )
    session.add(new_black_listing)
    session.commit()
    session.refresh(new_black_listing)

def blacklisted_token_lookup(token_id: int, session: SessionDep) -> bool:
    result = session.exec(select(RefreshTokenBlackList).where(RefreshTokenBlackList.token_id == token_id)).first()
    if result:
        return True
    else:
        return False

def removed_expired_blacklist(session: SessionDep):
    time_now = int(time.time())
    statement = sa_delete(RefreshTokenBlackList).where(RefreshTokenBlackList.exp < time_now)
    session.exec(statement)
    session.commit()