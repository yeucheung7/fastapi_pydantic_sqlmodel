import pytest
from util import token as TokenUtil
from util import user as UserUtil
from models.users import User as UserModel
from models.tokens import RefreshTokenBlackList
from jwt.exceptions import ExpiredSignatureError
from dependencies.dbsession import SessionDep
from sqlmodel import Session, select
from sqlalchemy.exc import IntegrityError
import db
import time
import random
import string

def random_email() -> str:
    return random_string(6, no_pun = False) + "@" + random_string(5, no_pun = False) + ".com"

def random_string(length: int = 20, no_pun: bool = False) -> str:
    return ''.join(random.choices(string.ascii_letters + string.digits + string.punctuation, k = length))

## Test case setup ##
test_user = UserModel(
    id = 1,
    user_name = random_string(10),
    email = random_email(),
    password_hash = random_string(10),
    min_token_verison = 0,
    is_admin = False,
)

token_life_time_s = 10
token_leeway_s = 6
half_token_life_time_s = token_life_time_s / 2
test_wait_time = token_life_time_s * 1.1
#######################

class Test_User_Selection:
    def test_good_select_by_id(self):
        target_uid: int = 1
        with Session(db.engine) as session:
            selected_user: UserModel = UserUtil.select_user_by_id(uid = target_uid, session = session)
            assert (selected_user is None) == False
            assert selected_user.id == target_uid

            ## Specify search with activity requirement
            target_user_is_active: bool = selected_user.is_active
            
            ## Search for active user only
            selected_user: UserModel = UserUtil.select_user_by_id(uid = target_uid, session = session, require_active = True)
            assert (selected_user is None) == (not target_user_is_active)
            
            ## Search for inactive user only
            selected_user: UserModel = UserUtil.select_user_by_id(uid = target_uid, session = session, require_active = False)
            assert (selected_user is None) == target_user_is_active

    def test_missing_select_by_id(self):
        target_uid: int = -1
        with Session(db.engine) as session:
            selected_user: UserModel = UserUtil.select_user_by_id(uid = target_uid, session = session)
            assert (selected_user is None) == True

    def test_bad_select_by_id(self):
        target_uid_str = "1"
        target_uid_float = 1.0
        with Session(db.engine) as session:
            with pytest.raises(TypeError):
                selected_user: UserModel = UserUtil.select_user_by_id(uid = target_uid_str, session = session)
            with pytest.raises(TypeError):
                selected_user: UserModel = UserUtil.select_user_by_id(uid = target_uid_float, session = session)

class Test_User_Creation_and_Delete:
    def test_user_creation_and_delete(self):
        with Session(db.engine) as session:
            new_user_name: str = random_string()
            new_email: str = random_email()
            new_clear_password: str = random_string()

            ## Creation
            new_user_model, err = UserUtil.create_new_user(new_user_name, new_email, new_clear_password, session = session, super_user = False)
            assert (new_user_model is None) == False
            assert (err is None) == True
            new_uid: int = new_user_model.id
            new_user_active: bool = new_user_model.is_active
            new_user_admin: bool = new_user_model.is_admin
            assert new_user_admin == False
            assert new_user_active == True
            
            ## Deletion
            status_code: int = UserUtil.delete_user_by_id(uid = new_uid, session = session)
            assert status_code == 200

            ## Make sure the user is actually deleted
            found_user: UserModel = UserUtil.select_user_by_id(uid = new_uid, session = session)
            assert (found_user is None) == True

    def test_user_creation_with_repeated_user_name(self):
        with Session(db.engine) as session:
            ## Basic information
            new_user_name: str = random_string(15)
            new_email: str = random_email()
            clear_pw_1: str = random_string(10)
            clear_pw_2: str = random_string(5) + clear_pw_1

            ## Creating the first user
            new_user_1, err = UserUtil.create_new_user(new_user_name, new_email, clear_pw_1, session = session, super_user = False)

            ## Confirm first user created okay
            assert (new_user_1 is None) == False
            assert (err is None) == True
            user_1_uid: int = new_user_1.id

            ## Create the second user that has the exact same name of first user
            new_user_2, err = UserUtil.create_new_user(new_user_name, new_email, clear_pw_2, session = session, super_user = False)

            ## Confirm second user was not created due to repeated name
            assert (new_user_2 is None) == True
            assert (err is None) == False
            assert isinstance(err, IntegrityError) == True

            ## Delete the created user
            status_code: int = UserUtil.delete_user_by_id(uid = user_1_uid, session = session)
            assert status_code == 200
            
            ## Make sure the user is actually deleted
            found_user: UserModel = UserUtil.select_user_by_id(uid = user_1_uid, session = session)
            assert (found_user is None) == True

    def test_deleting_non_exist_user(self):
        target_uid: int = -1

        with Session(db.engine) as session:
            status_code: int = UserUtil.delete_user_by_id(uid = target_uid, session = session)
            assert status_code == 404

class Test_User_Update:
    def test_user_update_name(self):
        ## Basic user info
        user_name_1: str = random_string(10)
        user_name_2: str = random_string(5) + user_name_1
        new_email: str  = random_email()
        clear_pw_1: str = random_string(10)

        ## DB session
        with Session(db.engine) as session:
            ## Create the test user account
            new_user, err = UserUtil.create_new_user(user_name = user_name_1, email = new_email, clear_text_pw = clear_pw_1, session = session)

            ## Make sure the new user account is okay
            assert (new_user is None) == False
            assert (err is None) == True
            assert new_user.user_name == user_name_1
            assert new_user.user_name != user_name_2

            ## Apply the user name change
            new_user, err = UserUtil.update_user_info(new_user, session = session, user_name = user_name_2)

            ## Make sure the new user account is okay
            assert (new_user is None) == False
            assert (err is None) == True

            ## Confirm name is updated
            assert new_user.user_name != user_name_1
            assert new_user.user_name == user_name_2

            ## Delete the created test user
            user_id: int = new_user.id
            status_code: int = UserUtil.delete_user_by_id(uid = user_id, session = session)
            assert status_code == 200

            ## Make sure the user is actually deleted
            found_user: UserModel = UserUtil.select_user_by_id(uid = user_id, session = session)
            assert (found_user is None) == True

    def test_user_update_name_to_existing_user(self):
        ## Basic user info
        user_name_1: str = random_string(10)
        new_email: str = random_email()
        clear_pw_1: str = random_string(10)

        ## DB session
        with Session(db.engine) as session:
            ## Get information of an existing user
            exising_user_model: UserModel = UserUtil.select_user_by_id(uid = 1, session = session)
            assert (exising_user_model is None) == False
            exising_user_name: str = exising_user_model.user_name
            user_name_2: str = exising_user_name

            ## Create the test user account
            new_user, err = UserUtil.create_new_user(user_name = user_name_1, email = new_email, clear_text_pw = clear_pw_1, session = session)

            ## Make sure the new user account is okay
            assert (new_user is None) == False
            assert (err is None) == True
            assert new_user.user_name == user_name_1
            user_uid: int = new_user.id

            ## Apply the user name change
            new_user, err = UserUtil.update_user_info(new_user, session = session, user_name = user_name_2)

            ## Make sure the new user account is okay
            assert (new_user is None) == True
            assert (err is None) == False
            assert isinstance(err, IntegrityError) == True

            
            ## Delete test user
            status_code: int = UserUtil.delete_user_by_id(uid = user_uid, session = session)
            assert status_code == 200

            ## Make sure the user is actually deleted
            found_user: UserModel = UserUtil.select_user_by_id(uid = user_uid, session = session)
            assert (found_user is None) == True

class Test_User_Password_Change:
    user_name: str = random_string(10)
    new_email: str = random_email()
    clear_pw_1: str = random_string(10)
    clear_pw_2: str = clear_pw_1 + random_string(10)

    def test_password_change(self):
        with Session(db.engine) as session:
            ## Create test user
            new_user, err = UserUtil.create_new_user(user_name = self.user_name, email = self.new_email, clear_text_pw = self.clear_pw_1, session = session)
            
            ## Verify new user okay
            assert (new_user is None) == False
            assert (err is None) == True
            assert UserUtil.check_password_correct(new_user, self.clear_pw_1, session = session) == True
            assert UserUtil.check_password_correct(new_user, self.clear_pw_2, session = session) == False

            ## Change the password
            user_uid: int = new_user.id
            initial_token_version: int = new_user.min_token_verison
            err = UserUtil.change_user_password(user_uid, self.clear_pw_2, session = session)
            assert (err is None) == True
            assert UserUtil.check_password_correct(new_user, self.clear_pw_1, session = session) == False
            assert UserUtil.check_password_correct(new_user, self.clear_pw_2, session = session) == True
            session.refresh(new_user)
            second_token_version: int = new_user.min_token_verison
            assert second_token_version == initial_token_version + 1

            ## Delete test user
            status_code: int = UserUtil.delete_user_by_id(uid = user_uid, session = session)
            assert status_code == 200
            
            ## Make sure the user is actually deleted
            found_user: UserModel = UserUtil.select_user_by_id(uid = user_uid, session = session)
            assert (found_user is None) == True