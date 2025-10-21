from fastapi import FastAPI, Request
from fastapi.responses import RedirectResponse
import os
import asyncio
from db import engine, Base
from fastapi.middleware.cors import CORSMiddleware
from routes.upload_routes import router as upload_router
from routes.auth_routes import router as auth_router
from routes.health_routes import router as health_router
from routes.misc_routes import router as misc_router
from routes.user_routes import router as user_router

app = FastAPI(title="SecureShare API")

# CORS configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Update with your frontend URL in production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include routers
app.include_router(upload_router, prefix="/api/uploads", tags=["uploads"])
app.include_router(auth_router, prefix="/api/auth", tags=["auth"])
app.include_router(health_router, prefix="/api/health", tags=["health"])
app.include_router(misc_router, prefix="/api/misc", tags=["misc"])
app.include_router(user_router, prefix="/api/admin", tags=["admin"])

@app.get("/")
def read_root():
    return {"message": "Welcome to SecureShare API!"}

@app.get("/receive")
def redirect_receive(request: Request):
    """Redirect legacy backend /receive links to the frontend /receive page preserving query params.
    This lets old links that pointed at the API port still function after changing link generation.
    """
    frontend_base = os.getenv("FRONTEND_BASE_URL", "http://localhost:5173").rstrip("/")
    query = request.url.query
    target = f"{frontend_base}/receive"
    if query:
        target = f"{target}?{query}"
    return RedirectResponse(target, status_code=307)

@app.on_event("startup")
async def on_startup():
    # Migrations should manage schema; avoid create_all to prevent drift.
    # If needed in dev, run `python -m backend.scripts.migrate_and_seed`.
    pass