from fastapi.testclient import TestClient

def test_site_auth_requirement(client: TestClient, url:str, token:str, method:str = "get") -> bool:
    '''
    Given a url and method, try to access the URL and see if access token is required.

    Test programme is:
        1. Access without access token. Expect 400
        2. Access with a valid access token. Expect less than 400 or 422 (422 for data mismatch)

    If all responses are as expected, return True. Otherwise, return False.

    Accepted methods (string) are get, post, put, delete and option. This is case insensitive. If other method is provided, raise KeyError
    '''
    ## Screening for HTTP method
    accepted_methods = ["get", "post", "put", "delete", "option"]
    method = method.lower()
    if not method in accepted_methods:
        raise KeyError(f"Unaccepted method {method} is provided to the test function.")
    
    ## Test without access token
    response = client.request(method = method, url = url)
    no_ac_code = response.status_code
    print(f"Response code without access token: {no_ac_code}")
    if no_ac_code != 401:
        return False
    
    ## Test with access token
    response = client.request(method = method, url = url, headers = {"Authorization": f"Bearer {token}"})
    with_ac_code = response.status_code
    print(f"Response code with access token: {with_ac_code}")
    if with_ac_code == 422 or (with_ac_code < 400):
        return True

    ## Catch all return false
    return False

def test_site_admin_requirement(client: TestClient, url:str, admin_token:str, non_admin_token:str, method:str = "get") -> bool:
    '''
    Given a url and method, try to access the URL and see if admin's access token is required.

    Test programme is:
        1. Access without access token. Expect 400
        2. Access with a valid non-admin access token. Expect less 403
        3. Access with a valid admin access token. Expect less than 400 or 422 (422 for data mismatch)

    If all responses are as expected, return True. Otherwise, return False.

    Accepted methods (string) are get, post, put, delete and option. This is case insensitive. If other method is provided, raise KeyError
    '''
    ## Screening for HTTP method
    accepted_methods = ["get", "post", "put", "delete", "option"]
    method = method.lower()
    if not method in accepted_methods:
        raise KeyError(f"Unaccepted method {method} is provided to the test function.")
    
    ## Test without access token
    response = client.request(method = method, url = url)
    no_ac_code = response.status_code
    print(f"Response code without access token: {no_ac_code}")
    if no_ac_code != 401:
        return False
    
    ## Test with non-admin access token ##
    response = client.request(method = method, url = url, headers = {"Authorization": f"Bearer {non_admin_token}"})
    with_user_ac_code = response.status_code
    print(f"Response code with access token: {with_user_ac_code}")
    if with_user_ac_code != 403:
        return False

    ## Test with admin access token ##
    response = client.request(method = method, url = url, headers = {"Authorization": f"Bearer {admin_token}"})
    with_admin_ac_code = response.status_code
    print(f"Response code with access token: {with_admin_ac_code}")
    if with_admin_ac_code == 422 or (with_admin_ac_code < 400):
        return True

    ## Catch all return false
    return False
    