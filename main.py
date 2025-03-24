from fastapi import FastAPI, Depends
from contextlib import asynccontextmanager
from db import init_db

@asynccontextmanager
async def lifespan(app: FastAPI):
    ## On startup
    print("From lifespan function: On startup")
    init_db() ## including create all tables

    ## On start up: Pass and await for shutdown
    yield

    ## On shutdown
    print("From lifespan function: On shutdown")

    ## Never give "yield"

## Creating the APP
app = FastAPI(lifespan=lifespan)

#### Routers ####

## Import the routers here
from routers.users.apis import user_router
from routers.auth.apis import auth_router

## Register the routers here
app.include_router(
    auth_router,
    prefix="/auth",
    tags=["Authentication"],
)
app.include_router(
    user_router,
    prefix="/users",
    tags=["Users"],
)