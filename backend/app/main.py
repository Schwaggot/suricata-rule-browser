"""
Suricata Rule Browser - FastAPI Backend
"""
from fastapi import FastAPI, Request
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pathlib import Path

from app.api import rules

# Initialize FastAPI app
app = FastAPI(
    title="Suricata Rule Browser",
    description="Browse and search Suricata IDS rules",
    version="1.0.0"
)

# Set up templates and static files
BASE_DIR = Path(__file__).resolve().parent
templates = Jinja2Templates(directory=str(BASE_DIR / "templates"))
app.mount("/static", StaticFiles(directory=str(BASE_DIR / "static")), name="static")

# Include API routers
app.include_router(rules.router, prefix="/api/v1", tags=["rules"])

# Root endpoint - serves the main page
@app.get("/")
async def read_root(request: Request):
    """Render the main rule browser page"""
    return templates.TemplateResponse("index.html", {"request": request})

@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {"status": "healthy"}
