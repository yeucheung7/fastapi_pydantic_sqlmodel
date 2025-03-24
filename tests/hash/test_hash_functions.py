import pytest
import bcrypt
import random
import string
from util import hash

class Test_Hashing:
    def test_verifier(self):
        """
        Test the functionality of the verifier, by creating test string with Bcrypt and then making sure the verifier is working properly
        """

        test_string = ''.join(random.choices(string.ascii_letters + string.digits + string.punctuation, k=20))

        ## Create hash by bcrypt directly
        code = test_string.encode('utf-8')
        salt = bcrypt.gensalt()
        hashed_str_dir = bcrypt.hashpw(code, salt)

        ## Check verifier: Create clear string ##
        assert hash.verify(test_string, hashed_str_dir) == True
        
        ## Check verifier: Incorrect clear string ##
        assert hash.verify(test_string[2:], hashed_str_dir) == False
        assert hash.verify(test_string[:-2], hashed_str_dir) == False
        added_string = ''.join(random.choices(string.ascii_letters + string.digits + string.punctuation, k=5))
        assert hash.verify(added_string + test_string, hashed_str_dir) == False
        assert hash.verify(test_string + test_string, hashed_str_dir) == False

        ## Check verifier: Incorrect hash string ##
        assert hash.verify(test_string, hashed_str_dir[3:]) == False
        assert hash.verify(test_string, hashed_str_dir[:-3]) == False
        assert hash.verify(test_string, added_string.encode('utf-8') + hashed_str_dir) == False
        assert hash.verify(test_string, hashed_str_dir + added_string.encode('utf-8')) == False

        ## Check verifier: Bad clear string or hash string ##
        assert hash.verify(123, hashed_str_dir) == False
        assert hash.verify(None, hashed_str_dir) == False
        assert hash.verify("", hashed_str_dir) == False
        assert hash.verify(test_string, 456) == False
        assert hash.verify(test_string, None) == False
        assert hash.verify(test_string, "") == False
        assert hash.verify(hashed_str_dir, test_string) == False ## Swapped hash and clear text

    def test_hasher(self):
        """
        Test the functionality of the hasher function. Providing that the verifier is always working well, the generated function should always be positively verified by the verifier
        """
        
        ## Good case: Normal operation ##
        test_string = ''.join(random.choices(string.ascii_letters + string.digits + string.punctuation, k=20))

        ## Create hash with hashing function
        hashed_string = hash.hashing(test_string)

        ## Verify with verifier
        assert hash.verify(test_string, hashed_string) == True
        
        ## Bad case: Non-string data into hashing version ##
        with pytest.raises(AttributeError):
            hashed_string = hash.hashing(3513584)
        with pytest.raises(AttributeError):
            hashed_string = hash.hashing(3513584.1351)
        with pytest.raises(AttributeError):
            hashed_string = hash.hashing('csdfsadf'.encode("utf-8")) ## Binary
        with pytest.raises(AttributeError):
            hashed_string = hash.hashing(None)
        
            
