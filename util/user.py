from models.users import User as UserModel
from dependencies.dbsession import SessionDep
from util import hash as HashUtil
from sqlmodel import select

def select_user_by_id(uid: int, session: SessionDep, require_active: bool = None) -> UserModel:
    '''
    Selecte user by ID. By default, the selection is regardless if the user is active or not. Only return one user. If no such user is found, return none.

    optional boolean argument `require_active` is none by default, which makes the function no checking is_active status. If it is true / false, return only the user that is active / inactive instead.

    Note: If 
    '''
    if isinstance(uid, int) == False:
        raise TypeError(f"Provided UID must be an integer, but type {type(uid)} is given.")

    if require_active is None:
        results = session.exec(select(UserModel).where(UserModel.id == uid)).first()
    else:
        results = session.exec(select(UserModel).where(UserModel.is_active == require_active).where(UserModel.id == uid)).first()
    
    return results

def create_new_user(user_name: str, clear_text_pw: str, session: SessionDep, super_user:bool = False, activiate:bool = True) -> tuple[UserModel, Exception]:
    '''
    Given a user name and clear text password, add the new user onto the database.
    Return UserModel and Exception. If success, exception will be None, while the UserModel will be fully filled and active. Else, the exception will be returned, while the user model will be none.

    New user will be active by default. To alter this behaviour, set `activiate` to False.
    '''
    ## Create new user model
    hashed = HashUtil.hashing(clear_text_pw)
    new_user: UserModel = UserModel(
        user_name = user_name,
        password_hash = hashed,
        is_admin = super_user,
        is_active = activiate
    )

    ## Try adding the user to DB
    try:
        session.add(new_user)
        session.commit()
        session.refresh(new_user)
        return new_user, None
    except Exception as e:
        session.rollback()
        return None, e

def check_password_correct(user: UserModel, clear_password:str, session: SessionDep) -> bool:
    '''
    Provide an user and clear password, return bool if the clear password matches the password of the user.
    '''
    hashed_password: str = user.password_hash
    return HashUtil.verify(clear_password, hashed_password)

def update_user_info(user: UserModel, session: SessionDep, user_name: str = None, is_admin: bool = None, is_active: bool = None) -> tuple[UserModel, Exception]:
    user_name: str = user.user_name if user_name is None else user_name
    is_admin: str = user.is_admin if is_admin is None else is_admin
    is_active: str = user.is_active if is_active is None else is_active
    user.user_name = user_name
    user.is_admin = is_admin
    user.is_active = is_active

    try:
        session.add(user)
        session.commit()
        session.refresh(user)
        return user, None
    except Exception as e:
        session.rollback()
        return None, e

def change_user_password(uid: int, new_clear_password: str, session: SessionDep, adv_token_version: bool = True) -> Exception:
    try:
        hashed_pw: str = HashUtil.hashing(new_clear_password)
        target_user: UserModel = select_user_by_id(uid, session = session)
        if target_user is None:
            raise KeyError("The user not found")
        target_user.password_hash = hashed_pw
        if adv_token_version:
            ## Advance the minimum token version to nullifly all issued tokens
            target_user.min_token_verison += 1
        session.add(target_user)
        session.commit()
        return None
    except Exception as e:
        return e

def delete_user_by_id(uid: int, session: SessionDep) -> int:
    '''
    Delete a user from DB by UID. Generally deleting an user is only during testing to delete test case.
    Under normal operation, please opt for deactivating the user over deleting from DB outweight due to foreign key issues.
    '''
    target_user: UserModel = session.exec(select(UserModel).where(UserModel.id == uid)).first()
    if target_user is None:
        return 404
    else:
        session.delete(target_user)
        session.commit()
        return 200