from fastapi.testclient import TestClient
from main import app
from util import token as TokenUtil
from models.users import User as UserModel
from tests.api.auth import general as AuthTest 
from util import user as UserUtil
from util import hash as HashUtil
from sqlmodel import Session, select
import db
import time
import random
import string

def random_email() -> str:
    return random_string(6, no_pun = False) + "@" + random_string(5, no_pun = False) + ".com"

def random_string(length: int = 20, no_pun: bool = False) -> str:
    return ''.join(random.choices(string.ascii_letters + string.digits + string.punctuation, k = length))

def two_list_total_match(list_1: list, list_2: list) -> bool:
    set_1 = set(list_1)
    set_2 = set(list_2)
    return set_1 == set_2

## Test case setup ##
client = TestClient(app)

test_user = UserModel(
    id = 1,
    user_name = random_string(10),
    email = random_email(),
    password_hash = random_string(10),
    min_token_verison = 0,
    is_admin = False,
)

test_admin = UserModel(
    id = 5,
    user_name = random_string(10),
    email = random_email(),
    password_hash = random_string(10),
    min_token_verison = 10,
    is_admin = True,
)

token_life_time_s: int = 10
token_leeway_s: int = 6
half_token_life_time_s: float = token_life_time_s / 2
test_wait_time: float = token_life_time_s * 1.1
#######################

class Test_User_Get_All:
    url = "/users/all"
    method = "get"
    expected_fields = ["id", "user_name", "is_admin", "is_active"]
    
    def test_api_auth_requirement(self):
        with Session(db.engine) as session:
            ## Create dummy access token
            ac_token: str = TokenUtil.issue_access_tokens(test_user, session = session, lifetime_s = token_life_time_s)

            ## Make sure the token is good
            assert TokenUtil.check_token(ac_token, session = session, check_access = True, with_leeway = False) == True

            ## Test access right
            assert AuthTest.test_site_auth_requirement(client, url = self.url, token = ac_token, method = self.method) == True

    def test_api_return(self):
        with Session(db.engine) as session:
            ## Create dummy access token
            ac_token: str = TokenUtil.issue_access_tokens(test_user, session = session, lifetime_s = token_life_time_s)

            ## Make sure the token is good
            assert TokenUtil.check_token(ac_token, session = session, check_access = True, with_leeway = False) == True

            ## Making the request
            response = client.request(method = self.method, url = self.url, headers = {"Authorization": f"Bearer {ac_token}"})
            response_json: dict = response.json()
            assert response.status_code == 200

            ## Checking the output dictionary are all well formed
            for user_dict in response_json:
                fields_in_dict = list(user_dict.keys())
                assert two_list_total_match(fields_in_dict, self.expected_fields) == True
                    
class Test_Read_Single_User:
    target_uid = 1
    url = f"/users/uid/{target_uid}"
    method = "get"
    expected_fields = ["id", "user_name", "is_admin", "is_active"]
    
    def test_api_auth_requirement(self):
        with Session(db.engine) as session:
            ## Create dummy access token
            ac_token: str = TokenUtil.issue_access_tokens(test_user, session = session, lifetime_s = token_life_time_s)

            ## Make sure the token is good
            assert TokenUtil.check_token(ac_token, session = session, check_access = True, with_leeway = False) == True

            ## Test access right
            assert AuthTest.test_site_auth_requirement(client, url = self.url, token = ac_token, method = self.method) == True

    def test_reading_single_user_api(self):
        with Session(db.engine) as session:
            ## Create dummy access token
            ac_token: str = TokenUtil.issue_access_tokens(test_user, session = session, lifetime_s = token_life_time_s)

            ## Make sure the token is good
            assert TokenUtil.check_token(ac_token, session = session, check_access = True, with_leeway = False) == True

            ## Making the request - check form
            response = client.request(method = self.method, url = self.url, headers = {"Authorization": f"Bearer {ac_token}"})
            response_json: dict = response.json()
            assert response.status_code == 200
            fields_in_dict = list(response_json.keys())
            assert two_list_total_match(fields_in_dict, self.expected_fields) == True

class Test_User_Creation_and_Deletion:
    url = "/users/"
    method = "post"
    method_del = "delete"
    expected_fields = ["id", "user_name", "is_admin", "is_active"]

    def test_creation_api_admin_requirement(self):
        with Session(db.engine) as session:
            ## Create dummy access token
            non_admin_ac_token: str = TokenUtil.issue_access_tokens(test_user, session = session, lifetime_s = token_life_time_s*5)
            admin_ac_token: str = TokenUtil.issue_access_tokens(test_admin, session = session, lifetime_s = token_life_time_s*5)

            ## Confirming the tokens are good
            assert TokenUtil.check_token(non_admin_ac_token, session = session, check_access = True, with_leeway = False) == True
            assert TokenUtil.check_token(admin_ac_token, session = session, check_access = True, with_leeway = False) == True

            ## Test admin token requirements
            assert AuthTest.test_site_admin_requirement(client, url = self.url, non_admin_token = non_admin_ac_token, admin_token = admin_ac_token, method = self.method) == True
    
    def test_deletion_api_admin_requirement(self):
        with Session(db.engine) as session:
            ## Create dummy access token
            non_admin_ac_token: str = TokenUtil.issue_access_tokens(test_user, session = session, lifetime_s = token_life_time_s*5)
            admin_ac_token: str = TokenUtil.issue_access_tokens(test_admin, session = session, lifetime_s = token_life_time_s*5)

            ## Confirming the tokens are good
            assert TokenUtil.check_token(non_admin_ac_token, session = session, check_access = True, with_leeway = False) == True
            assert TokenUtil.check_token(admin_ac_token, session = session, check_access = True, with_leeway = False) == True

            ## Test admin token requirements
            assert AuthTest.test_site_admin_requirement(client, url = self.url, non_admin_token = non_admin_ac_token, admin_token = admin_ac_token, method = self.method_del) == True

    def test_creation_api_return(self):
        with Session(db.engine) as session:
            ## Create dummy access token
            admin_ac_token: str = TokenUtil.issue_access_tokens(test_admin, session = session, lifetime_s = token_life_time_s*5)

            ## Confirming the tokens are good
            assert TokenUtil.check_token(admin_ac_token, session = session, check_access = True, with_leeway = False) == True

            ## Creating new users
            user_name = random_string(15)
            email = random_email()
            clear_password = random_string(15)
            response = client.request(method = self.method, url = self.url, headers = {"Authorization": f"Bearer {admin_ac_token}"}, json = {
                "user_name": user_name,
                "email": email,
                "password": clear_password
            })
            response_json: dict = response.json()

            ## Checking the return: Should be all in good form
            assert response.status_code == 200
            fields_in_dict = list(response_json.keys())
            assert two_list_total_match(fields_in_dict, self.expected_fields) == True

            ## Make sure a new user is created on the DB
            uid: int = response_json["id"]
            user_model: UserModel = UserUtil.select_user_by_id(uid, session = session)
            assert (user_model is None) == False
            assert user_model.user_name == user_name
            assert HashUtil.verify(clear_password, user_model.password_hash) == True
            
            ## Getting UID from the return and delete the user
            response = client.request(method = self.method_del, url = self.url, headers = {"Authorization": f"Bearer {admin_ac_token}"}, json = {
                "uid": uid
            })
            assert response.status_code == 200

            ## Confirm that the user is actually deleted
            user_model: UserModel = UserUtil.select_user_by_id(uid, session = session)
            assert (user_model is None) == True