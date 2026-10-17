from fastapi import FastAPI

app = FastAPI(title="HomeOps API")

@app.get("/health")
def health_check():
    return {"status": "healthy"}