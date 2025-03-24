from models.users import User as UserModel
from util import user as UserUtil
from sqlmodel import Session
import pwinput
import db

description = "Change the password of a user"

def get_password() -> str | None:
    '''
    Interactive with the user on CLI for a new password.
    '''
    try:
        answer_accepted: bool = False
        
        ## Main loop
        while answer_accepted == False:
            input_clear_pw: str = None

            ## Clear password
            entered_text:str = pwinput.pwinput("Please enter the new password of the user (not shown): ")
            if entered_text:
                input_clear_pw = entered_text

            ## Check answer ##
            if input_clear_pw is None:
                ## One of them is not input
                print("Please provide the new password.\n")
            else:
                ## Other critera to be provided... ##

                ## Ask user again
                entered_text:str = input("Confirm the entered password is correct? Type (y) to proceed, any other character(s) to restart. ")
                if entered_text == "y":
                    answer_accepted = True

        ## Return the main function
        return input_clear_pw
    except KeyboardInterrupt:
        exit(0)

def get_int_from_user(prompt:str = "Please enter an integer: ") -> int:
    try:
        answer_accepted: bool = False
        while answer_accepted == False:
                uid: int = None
                entered_text:str = input(prompt)

                if entered_text:
                    try:
                        uid = int(entered_text)
                        break
                    except Exception:
                        print("Please enter an integer.")
        return uid
    except Exception:
        exit(0)

def get_user_say_yes(prompt:str = "Please enter 'y' to confirm proceed"):
    try:
        answer_accepted: bool = False
        while answer_accepted == False:
            entered_text:str = input(prompt)
            
            if entered_text == "y":
                return
            else:
                print("Breaking")
                exit(0)
    except KeyboardInterrupt:
            exit(0)

def command():
    with Session(db.engine) as session:
        ## Find the user model
        target_uid: int = get_int_from_user(prompt = "Please enter the UID of the target user: ")
        user_model: UserModel = UserUtil.select_user_by_id(target_uid, session = session)
        if user_model is None:
            print(f"Requested user of UID {target_uid} does not exist.")
            exit(1)
        else:
            print(f"Selected {user_model.user_name}.")

        ## Getthing the new password
        clear_password: int = get_password()

        ## Confirm user understand log out everywhere
        get_user_say_yes(f"This act will log out all logins of the target user ({user_model.user_name}). Confirm by enter 'y': ")

        ## Change the password and update the minimum token version
        err: Exception = UserUtil.change_user_password(target_uid, clear_password, session = session, adv_token_version = True)
        if err:
            print(f"Encounted error while updating the password")
            print(err)
            exit(1)

    ## Successful update
    print("Updated")
    exit(0)