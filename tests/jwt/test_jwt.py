import pytest
from util import token
from models.users import User as UserModel
from models.tokens import RefreshTokenBlackList
from jwt.exceptions import ExpiredSignatureError
from dependencies.dbsession import SessionDep
from sqlmodel import Session, select
import db
import time
import random
import string

def random_string(length: int = 20):
    return ''.join(random.choices(string.ascii_letters + string.digits + string.punctuation, k = length))

## Test case setup ##
test_user = UserModel(
    id = 1,
    user_name = random_string(10),
    password_hash = random_string(10),
    min_token_verison = 0,
    is_admin = False,
)

token_life_time_s = 10
token_leeway_s = 6
half_token_life_time_s = token_life_time_s / 2
test_wait_time = token_life_time_s * 1.1
#######################

class Test_Basic_Jwt_Operation:
    def test_signing_and_decoding_jwt(self):
        '''
        Test JWT signing, providing decoder is always correct
        '''

        test_dict = {
            "asdsad": random_string(15), 
            "asdfg": random_string(15), 
            "sdf": random_string(15), 
            "fgj": random_string(15), 
            "drt": random_string(15), 
            "dfg": random_string(15), 
        }

        ## Good case: normal operation with normal dictionary ##
        token_str = token.sign_jwt(test_dict)
        assert token.decode_jwt(token_str) == test_dict

        ## Bad case: pure string as input ##
        test_data = random_string(30)
        with pytest.raises(TypeError):
            token_str = token.sign_jwt(test_data)

        ## Bad case: Non-string or dictionary output:
        test_data = 34643523525
        with pytest.raises(TypeError):
            token_str = token.sign_jwt(test_data)
        test_data = 9834734.958756
        with pytest.raises(TypeError):
            token_str = token.sign_jwt(test_data)

    def test_token_creation_function(self):
        '''
        Test JWT token creation, providing decoder and signer are always correct
        '''
        with Session(db.engine) as session:
            ## Token creations ##
            ac_token = token.create_token(test_user, session = session, lifetime_s = token_life_time_s, is_access = True)
            rf_token = token.create_token(test_user, session = session, lifetime_s = token_life_time_s, is_access = False)

            ## Good case: Decode and confirm token body: Access token ##
            decoded_token = token.decode_jwt(ac_token)
            print(decoded_token)
            in_token_uid = decoded_token["uid"]
            in_token_iat = decoded_token["iat"]
            in_token_exp = decoded_token["exp"]
            in_token_scope = decoded_token["scope"]
            in_token_life_time = in_token_exp - in_token_iat
            assert in_token_life_time == pytest.approx(token_life_time_s, 2)
            assert in_token_uid == test_user.id
            assert in_token_scope == "access"

            ## Decode and confirm token body: Refresh token ##
            decoded_token = token.decode_jwt(rf_token)
            in_token_uid = decoded_token["uid"]
            in_token_iat = decoded_token["iat"]
            in_token_exp = decoded_token["exp"]
            in_token_scope = decoded_token["scope"]
            in_token_life_time = in_token_exp - in_token_iat
            assert in_token_life_time == pytest.approx(token_life_time_s, 2)
            assert in_token_uid == test_user.id
            assert in_token_scope == "refresh"

            ## Sleep a bit to test validity with decoder (with test exp)
            time.sleep(half_token_life_time_s)
            try:
                token.decode_jwt(ac_token)
            except Exception as e:
                print(e)
                pytest.fail("Unexpected error in decoding the access token")
            try:
                token.decode_jwt(rf_token)
            except Exception as e:
                print(e)
                pytest.fail("Unexpected error in decoding the refresh token")

            ## Sleep beyond expiration, verify WITHOUT leeway, test validity with decoder (with test exp)
            time.sleep(half_token_life_time_s)
            with pytest.raises(ExpiredSignatureError):
                token.decode_jwt(ac_token, with_leeway = False)
            with pytest.raises(ExpiredSignatureError):
                token.decode_jwt(rf_token, with_leeway = False)

            ## Sleep beyond expiration, verify WITH leeway, test validity with decoder (with test exp)
            try:
                token.decode_jwt(ac_token, with_leeway = True, overide_leeway = token_leeway_s)
            except Exception as e:
                print(e)
                pytest.fail("Unexpected error in decoding the access token, should be in leeway")
            
            try:
                token.decode_jwt(rf_token, with_leeway = True, overide_leeway = token_leeway_s)
            except Exception as e:
                print(e)
                pytest.fail("Unexpected error in decoding the access token, should be in leeway")

            ## Sleep beyond expiration and leeway, should also yield failure
            time.sleep(token_leeway_s)
            with pytest.raises(ExpiredSignatureError):
                token.decode_jwt(ac_token, with_leeway = False)
            with pytest.raises(ExpiredSignatureError):
                token.decode_jwt(rf_token, with_leeway = False)
            with pytest.raises(ExpiredSignatureError):
                token.decode_jwt(ac_token, with_leeway = True, overide_leeway = token_leeway_s)
            with pytest.raises(ExpiredSignatureError):
                token.decode_jwt(rf_token, with_leeway = True, overide_leeway = token_leeway_s)

    def test_check_function(self):
        '''
        Testing the token validity check function, providing that the signing, decoding and creation functions are always correct.
        '''
        
        with Session(db.engine) as session:

            ## Token creations ##
            ac_token = token.create_token(test_user, session = session, lifetime_s = token_life_time_s, is_access = True)
            rf_token = token.create_token(test_user, session = session, lifetime_s = token_life_time_s, is_access = False)

            ## Good: Using the check fucntion before expiration ##
            assert token.check_token(ac_token, session = session) == True
            assert token.check_token(ac_token, session = session, check_access = True) == True
            assert token.check_token(ac_token, session = session, check_refresh = True) == False

            assert token.check_token(rf_token, session = session) == True
            assert token.check_token(rf_token, session = session, check_access = True) == False
            assert token.check_token(rf_token, session = session, check_refresh = True) == True

            ## Bad: Token expiration, without leeway ##
            time.sleep(test_wait_time)
            assert token.check_token(ac_token, session = session, with_leeway = False) == False
            assert token.check_token(rf_token, session = session, with_leeway = False) == False

            ## Good: Token expiration, with leeway, within leeway
            assert token.check_token(ac_token, session = session, with_leeway = True, overide_leeway = token_leeway_s) == True
            assert token.check_token(rf_token, session = session, with_leeway = True, overide_leeway = token_leeway_s) == True

            ## Bad: Token expiration and beyond leeway ##
            time.sleep(token_leeway_s)
            assert token.check_token(ac_token, session = session, with_leeway = False) == False
            assert token.check_token(rf_token, session = session, with_leeway = False) == False
            assert token.check_token(ac_token, session = session, with_leeway = True, overide_leeway = token_leeway_s) == False
            assert token.check_token(rf_token, session = session, with_leeway = True, overide_leeway = token_leeway_s) == False

class Test_Auth_Operations:
    def test_token_issuing(self):
        
        with Session(db.engine) as session:

            ## Creating tokens ##
            ac1_token, rf_token = token.issue_access_refresh_tokens(test_user, session = session, access_lifetime_s  = token_life_time_s, refresh_lifetime_s  = token_life_time_s)
            ac2_token = token.issue_access_tokens(test_user, session = session,lifetime_s  = token_life_time_s)

            #### Good cases: Before expiration ####

            ## Token checkings: AC1 ##
            assert token.check_token(ac1_token, session = session) == True
            assert token.check_token(ac1_token, session = session, check_access = True) == True
            assert token.check_token(ac1_token, session = session, check_refresh = True) == False
            
            ## Token checkings: AC2 ##
            assert token.check_token(ac2_token, session = session) == True
            assert token.check_token(ac2_token, session = session, check_access = True) == True
            assert token.check_token(ac2_token, session = session, check_refresh = True) == False
            
            ## Token checkings: Ref ##
            assert token.check_token(rf_token, session = session) == True
            assert token.check_token(rf_token, session = session, check_access = True) == False
            assert token.check_token(rf_token, session = session, check_refresh = True) == True

            #### Base cases: Expiration, without leeway ####
            time.sleep(test_wait_time)
            assert token.check_token(ac1_token, session = session, with_leeway = False) == False
            assert token.check_token(ac2_token, session = session, with_leeway = False) == False
            assert token.check_token(rf_token, session = session, with_leeway = False) == False

            #### Good cases: Expiration but without leeway, WITH leeway test ####
            assert token.check_token(ac1_token, session = session, with_leeway = True, overide_leeway = token_leeway_s) == True
            assert token.check_token(ac2_token, session = session, with_leeway = True, overide_leeway = token_leeway_s) == True
            assert token.check_token(rf_token, session = session, with_leeway = True, overide_leeway = token_leeway_s) == True

            #### Bad cases: Expiration and beyond leeway ####
            time.sleep(token_leeway_s)
            assert token.check_token(ac1_token, session = session, with_leeway = False) == False
            assert token.check_token(ac2_token, session = session, with_leeway = False) == False
            assert token.check_token(rf_token, session = session, with_leeway = False) == False
            assert token.check_token(ac1_token, session = session, with_leeway = True, overide_leeway = token_leeway_s) == False
            assert token.check_token(ac2_token, session = session, with_leeway = True, overide_leeway = token_leeway_s) == False
            assert token.check_token(rf_token, session = session, with_leeway = True, overide_leeway = token_leeway_s) == False

    def test_refreshing_and_blacklisting_tokens(self):
        with Session(db.engine) as session:
            ## Creating tokens ##
            ac_token, rf_token = token.issue_access_refresh_tokens(test_user, session = session, access_lifetime_s = token_life_time_s, refresh_lifetime_s = None)
            
            ## Good case: Reference token is still valid
            assert token.check_token(ac_token, session = session, check_access = True, with_leeway = False) == True
            assert token.check_token(rf_token, session = session, check_refresh = True, with_leeway = False) == True

            ## Bad case: Access token already expired, no leeway check ##
            time.sleep(test_wait_time)
            assert token.check_token(ac_token, session = session, check_access = True, with_leeway = False) == False # Confirm access token is dead
            assert token.check_token(rf_token, session = session, check_refresh = True, with_leeway = False) == True # Confirm refresh token is still good
            
            ## Refreshing the access token and refresh token, and check
            new_ac_token, new_rf_token = token.process_refresh(rf_token, session = session)
            assert token.check_token(new_ac_token, session = session, check_access = True, with_leeway = False) == True
            assert token.check_token(new_rf_token, session = session, check_refresh = True, with_leeway = False) == True

            ## Black-listing:: Confirming old refresh token cannot be used to refresh again. Old access token is still not usable
            assert token.check_token(ac_token, session = session, check_access = True, with_leeway = False) == False
            assert token.check_token(rf_token, session = session, check_refresh = True, with_leeway = False) == False

    def reject_token_by_version(self):
        with Session(db.engine) as session:
            acc_token = token.issue_access_tokens(test_user, session = session)
            token_body = token.decode_jwt(acc_token)
            assert token.check_token(acc_token, session = session, check_access = True) == True
            token_body["token_version"] = token_body["token_version"] - 10
            mod_acc_token = token.sign_jwt(token_body)
            assert token.check_token(mod_acc_token, session = session, check_access = True) == False

    def delete_expired_blacklisted_tokens(self):
        with Session(db.engine) as session:
            ## Create initial tokens
            ac_token, rf_token = token.issue_access_refresh_tokens(test_user, session = session, access_lifetime_s = token_life_time_s, refresh_lifetime_s = None)

            ## Verify the tokens are good
            assert token.check_token(ac_token, session = session, check_access = True, with_leeway = False) == True
            assert token.check_token(rf_token, session = session, check_refresh = True, with_leeway = False) == True

            ## Refresh the tokens
            new_ac_token, new_rf_token = token.process_refresh(rf_token, session = session)

            ## Verify the old refresh token is not usable, and the new tokens are good
            assert token.check_token(rf_token, session = session, check_refresh = True, with_leeway = False) == False
            assert token.check_token(new_ac_token, session = session, check_access = True, with_leeway = False) == True
            assert token.check_token(new_rf_token, session = session, check_refresh = True, with_leeway = False) == True

            ## Confirm the old refresh token is on the blacklist
            rf_token_dict = token.decode_jwt(rf_token)
            old_token_id = rf_token_dict["token_id"]
            assert token.blacklisted_token_lookup(old_token_id, session) == True

            ## Wait for the token to expire
            time.sleep(test_wait_time)

            ## Call expired token removal function
            token.removed_expired_blacklist(session)

            ## Confirm the old refresh token is removed from the blacklist
            assert token.blacklisted_token_lookup(old_token_id, session) == False