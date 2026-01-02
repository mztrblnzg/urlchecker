from fastapi import FastAPI
from pydantic import BaseModel
from typing import Literal

app = FastAPI()

# Белый список — строгое совпадение строки
WHITELIST = {
    "https://example.com",
    "https://urlchecker-n49c.onrender.com",
    "http://127.0.0.1:10000",
}

class URLCheckRequest(BaseModel):
    url: str

class URLCheckResponse(BaseModel):
    status: Literal["ok", "blocked"]

@app.post("/check", response_model=URLCheckResponse)
def check_url(data: URLCheckRequest):
    return {"status": "ok" if data.url in WHITELIST else "blocked"}

@app.get("/health")
def health():
    return {"status": "ok"}
