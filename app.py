from fastapi import FastAPI, Response
from fastapi.responses import HTMLResponse, FileResponse
from pydantic import BaseModel
from typing import Literal
import os

print("LOADED app.py VERSION=2026-01-02")

app = FastAPI()

WHITELIST = {
    "https://urlchecker-n49c.onrender.com",
}

class URLCheckRequest(BaseModel):
    url: str

@app.get("/", response_class=HTMLResponse)
def root():
    with open("index.html") as f:
        return HTMLResponse(content=f.read(), status_code=200)

@app.get("/health")
def health():
    return {"status": "ok"}

@app.post("/check")
def check_url(data: URLCheckRequest):
    status: Literal["ok", "blocked"] = "ok" if data.url in WHITELIST else "blocked"
    return {"status": status}
