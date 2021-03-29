from fastapi import FastAPI

from .api import router

app = FastAPI(
    app="test worlshop",
    description="Csfsdfsdfdfs",
    version='1.0.0',
    debug=True,
)
app.include_router(router)
