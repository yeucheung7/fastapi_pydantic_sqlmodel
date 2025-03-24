from fastapi.testclient import TestClient
from main import app
from util import token
from models.users import User as UserModel
from jwt.exceptions import ExpiredSignatureError
from sqlmodel import Session, select
import db
import time
import random
import string

def random_string(length: int = 20):
    return ''.join(random.choices(string.ascii_letters + string.digits + string.punctuation, k = length))

## Test case setup ##
client = TestClient(app)

test_user = UserModel(
    id = 1,
    user_name = random_string(10),
    password_hash = random_string(10),
    min_token_verison = 10,
    is_admin = False,
)

token_life_time_s: int = 10
token_leeway_s: int = 6
half_token_life_time_s: float = token_life_time_s / 2
test_wait_time: float = token_life_time_s * 1.1
#######################

## Routes ##
auth_url: str = "/auth"
token_url: str = f"{auth_url}/token"
login_url: str = f"{auth_url}/login"
token_check_url: str = f"{token_url}/check"
token_refresh_url: str = f"{token_url}/refresh"
############

class Test_login_Api:
    def test_login_token_creation(self):
        with Session(db.engine) as session:
            ## Good login ##
            response = client.post(login_url, json = {"user_name":"vannesa", "password":"123456"})
            response_dict: dict = response.json()
            response_code: int = response.status_code
            assert response_code == 200
            assert ("access" in response_dict) == True
            ac_token = response_dict["access"]
            assert token.check_token(ac_token, session = session, check_access=True) == True
            assert token.check_token(ac_token, session = session, check_refresh=True) == False

            ## Bad login: user name ##
            response = client.post(login_url, json = {"user_name":"vasdsaannesa", "password":"123456"})
            response_dict: dict = response.json()
            response_code: int = response.status_code
            assert response_code == 404
            
            ## Bad login: password ##
            response = client.post(login_url, json = {"user_name":"vannesa", "password":"123vannesa456"})
            response_dict: dict = response.json()
            response_code: int = response.status_code
            assert response_code == 404
            
            ## Bad login: user name and password ##
            response = client.post(login_url, json = {"user_name":"vanasdasnesa", "password":"123vannesa456"})
            response_dict: dict = response.json()
            response_code: int = response.status_code
            assert response_code == 404

class Test_Check_Token_Api:
    def test_check_access_token(self):
        with Session(db.engine) as session:
            ## Creation of token ##
            ac_token = token.create_token(test_user, session = session, lifetime_s = token_life_time_s, is_access = True)

            ## Good case: token still valid ##
            response = client.post(token_check_url, json = {"token":ac_token})
            response_code: int = response.status_code
            assert response_code == 200

            ## Bad case: Malformed token ##
            response = client.post(token_check_url, json = {"token":ac_token[:-5]})
            response_code: int = response.status_code
            assert response_code == 406

            ## Bad case: Expired token ##
            time.sleep(test_wait_time)
            response = client.post(token_check_url, json = {"token":ac_token})
            response_code: int = response.status_code
            assert response_code == 406

    def test_check_refresh_token(self):
        with Session(db.engine) as session:
            ## Creation of token ##
            rf_token = token.create_token(test_user, session = session, lifetime_s = token_life_time_s, is_access = False)

            ## Good case: token still valid ##
            response = client.post(token_check_url, json = {"token":rf_token})
            response_code: int = response.status_code
            assert response_code == 200

            ## Bad case: Malformed token ##
            response = client.post(token_check_url, json = {"token":rf_token[:-5]})
            response_code: int = response.status_code
            assert response_code == 406

            ## Bad case: Expired token ##
            time.sleep(test_wait_time)
            response = client.post(token_check_url, json = {"token":rf_token})
            response_code: int = response.status_code
            assert response_code == 406

class Test_Refresh_Api:
    def test_good_refresh(self):
        with Session(db.engine) as session:
            ## Creation of token ##
            rf_token = token.create_token(test_user, session = session, lifetime_s = token_life_time_s * 10, is_access = False)

            ## Make sure the token is good
            assert token.check_token(rf_token, session = session, auto_scope = True) == True

            ## Request for refresh
            response = client.post(token_refresh_url, json = {"refresh": rf_token})
            response_body: dict = response.json()
            response_code: int = response.status_code
            assert response_code == 200
            new_ac_token = response_body["access"]
            new_rf_token = response_body["refresh"]

            ## Check token validity
            assert token.check_token(rf_token, session = session, auto_scope = True) == False
            assert token.check_token(new_ac_token, session = session, auto_scope = True) == True
            assert token.check_token(new_rf_token, session = session, auto_scope = True) == True

    def test_expired_refresh(self):
        with Session(db.engine) as session:
            ## Creation of token ##
            rf_token = token.create_token(test_user, session = session, lifetime_s = token_life_time_s, is_access = False)

            ## Make sure the token is good
            assert token.check_token(rf_token, session = session, auto_scope = True) == True

            ## Modify the token so that it is expired
            rf_token_decoded = token.decode_jwt(rf_token)
            rf_token_decoded["iat"] -= 10000
            rf_token_decoded["exp"] -= 10000
            rf_token = token.sign_jwt(rf_token_decoded)
            assert token.check_token(rf_token, session = session, auto_scope = True) == False

            ## Request for refresh: should failed due to expiration
            response = client.post(token_refresh_url, json = {"refresh": rf_token})
            response_code: int = response.status_code
            assert response_code == 406
            