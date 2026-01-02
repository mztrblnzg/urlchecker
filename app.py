   from fastapi import FastAPI
   from fastapi.responses import FileResponse
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

   @app.get("/")
   def root():
       return FileResponse("index.html")

   @app.get("/health")
   def health():
       return {"status": "ok"}

   @app.post("/check")
   def check_url(data: URLCheckRequest):
       status: Literal["ok", "blocked"] = "ok" if data.url in WHITELIST else "blocked"
       return {"status": status}
