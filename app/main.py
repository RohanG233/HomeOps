from fastapi import FastAPI

from app.routers.auth import router

app = FastAPI(title="HomeOps API")

app.include_router(router, prefix="/auth", tags=["Authentication"])

@app.get("/health")
def health_check():
    return {"status": "healthy"}