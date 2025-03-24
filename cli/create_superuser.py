from models.users import User as UserModel
from util import user as UserUtil
from sqlmodel import Session, select
from sqlalchemy.exc import IntegrityError
import pwinput
import db

description = "Create a new super user with use name and password"

def get_username_password() -> tuple[str, str] | None:
    '''
    Interactive with the user on CLI for user name and password pair.
    '''
    try:
        answer_accepted: bool = False
        
        ## Main loop
        while answer_accepted == False:
            input_user_name: str = None
            input_clear_pw: str = None

            ## User name
            entered_text:str = input("Please enter the user name of the new user: ")
            if entered_text:
                input_user_name = entered_text

            ## Clear password
            entered_text:str = pwinput.pwinput("Please enter the password of the new user (not shown): ")
            if entered_text:
                input_clear_pw = entered_text

            ## Check answer ##
            if (input_user_name is None) or (input_clear_pw is None):
                ## One of them is not input
                print("Please provide both information.\n")
            else:
                ## Other critera to be provided... ##

                ## Ask user again
                entered_text:str = input("Confirm the entered informaiton is correct? Type (y) to proceed, any other character(s) to restart. ")
                if entered_text == "y":
                    answer_accepted = True

        ## Return the main function
        return input_user_name, input_clear_pw
    except KeyboardInterrupt:
        exit(0)

def command():
    user_name, clear_password = get_username_password()

    ## Attempt to create user
    with Session(db.engine) as session:
        new_user_model: UserModel
        err: Exception
        new_user_model, err = UserUtil.create_new_user(user_name, clear_password, session, super_user = True)
        if new_user_model:
            print(f"New user created. UID {new_user_model.id}")
            exit(0)
        elif err:
            if isinstance(err, IntegrityError):
                print("Error encountered. The user name has been used.")
                exit(1)
            else:
                print("Error encountered")
                print(err)
                exit(1)
        else:
            print("Encountered unknown error while creating the new user.")
            exit(1)
