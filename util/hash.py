import bcrypt

def hashing(in_str: str) -> str:
    code = in_str.encode('utf-8')
    salt = bcrypt.gensalt()
    hashed = bcrypt.hashpw(code, salt)
    return hashed

def verify(test_str: str, target_hash: str) -> bool:
    ## Encoding source
    try:
        in_code = test_str.encode('utf-8')
    except AttributeError:
        ## Bad input data type
        return False
    
    ## Checking
    try:
        result: bool = bcrypt.checkpw(in_code, target_hash)
        return result
    except ValueError:
        ## Incorrect hash
        return False
    except TypeError:
        ## Bad hash data type
        return False