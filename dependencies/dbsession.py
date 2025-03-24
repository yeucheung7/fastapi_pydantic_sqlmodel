from typing import Annotated
from sqlmodel import Session
from fastapi import Depends
from db import get_session

SessionDep = Annotated[Session, Depends(get_session)]


