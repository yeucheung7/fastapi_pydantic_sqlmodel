from sqlmodel import create_engine, SQLModel, Session
import json
import os

## Models :: Models must be registered here for init_db to "pick up" the tables
from models.users import *
from models.tokens import *

## Basic ##
with open(os.path.join("config", "settings.json"), "r") as setting_file:
    setting_dict = json.load(setting_file)
    sql_dict = setting_dict["db"]
sql_file_name = sql_dict["sqlite_file"]
DATABASE_URL = f"sqlite:///{sql_file_name}"
engine = create_engine(DATABASE_URL, echo=sql_dict["echo"])

def init_db():
    SQLModel.metadata.create_all(engine)

def get_session():
    with Session(engine) as session:
        yield session
