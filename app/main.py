"""
Suricata Rule Browser - FastAPI Backend
"""
from contextlib import asynccontextmanager
from fastapi import FastAPI, Request
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pathlib import Path

from app.api import rules, transforms


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Lifespan event handler for startup and shutdown"""
    # Startup: Load rules
    rules.load_rules()
    yield
    # Shutdown: Add cleanup code here if needed


# Initialize FastAPI app
app = FastAPI(
    title="Suricata Rule Browser",
    description="Browse and search Suricata IDS rules",
    version="1.0.0",
    lifespan=lifespan
)

# Set up templates and static files
BASE_DIR = Path(__file__).resolve().parent
templates = Jinja2Templates(directory=str(BASE_DIR / "templates"))
app.mount("/static", StaticFiles(directory=str(BASE_DIR / "static")), name="static")

# Include API routers
app.include_router(rules.router, prefix="/api/v1", tags=["rules"])
app.include_router(transforms.router, prefix="/api/v1", tags=["transforms"])


# Page endpoints
@app.get("/")
async def browser_page(request: Request):
    """Render the rules browser page"""
    return templates.TemplateResponse("browser.html", {"request": request, "active_page": "browser"})


@app.get("/transforms")
async def transforms_page(request: Request):
    """Render the transforms page"""
    return templates.TemplateResponse("transforms.html", {"request": request, "active_page": "transforms"})


@app.get("/about")
async def about_page(request: Request):
    """Render the about page"""
    return templates.TemplateResponse("about.html", {"request": request, "active_page": "about"})


@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {"status": "healthy"}
