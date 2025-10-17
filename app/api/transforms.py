"""
API endpoints for transform management
"""
from typing import List
from fastapi import APIRouter, HTTPException
from app.models.transform import TransformRule, DryRunResult
from app.repositories.transform_repository import TransformRepository
from app.engines.transform_engine import TransformEngine

# Initialize repository and router
repository = TransformRepository()
router = APIRouter()


def get_rules_cache():
    """Get rules cache from rules API (import at runtime to avoid circular import issues)"""
    from app.api import rules
    return rules._rules_cache


@router.get("/transforms", response_model=List[TransformRule])
async def list_transforms():
    """List all transform rules"""
    return repository.list_all()


@router.get("/transforms/{transform_id}", response_model=TransformRule)
async def get_transform(transform_id: str):
    """Get a specific transform rule"""
    transform = repository.read(transform_id)
    if not transform:
        raise HTTPException(status_code=404, detail="Transform not found")
    return transform


@router.post("/transforms", response_model=TransformRule)
async def create_transform(transform: TransformRule):
    """Create a new transform rule"""
    transform_id = repository.create(transform)
    created = repository.read(transform_id)
    if not created:
        raise HTTPException(status_code=500, detail="Failed to create transform")
    return created


@router.put("/transforms/{transform_id}", response_model=TransformRule)
async def update_transform(transform_id: str, transform: TransformRule):
    """Update an existing transform rule"""
    success = repository.update(transform_id, transform)
    if not success:
        raise HTTPException(status_code=404, detail="Transform not found")

    updated = repository.read(transform_id)
    if not updated:
        raise HTTPException(status_code=500, detail="Failed to retrieve updated transform")
    return updated


@router.delete("/transforms/{transform_id}")
async def delete_transform(transform_id: str):
    """Delete a transform rule"""
    success = repository.delete(transform_id)
    if not success:
        raise HTTPException(status_code=404, detail="Transform not found")
    return {"message": "Transform deleted successfully"}


@router.post("/transforms/{transform_id}/enable")
async def enable_transform(transform_id: str):
    """Enable a transform rule"""
    transform = repository.read(transform_id)
    if not transform:
        raise HTTPException(status_code=404, detail="Transform not found")

    transform.enabled = True
    repository.update(transform_id, transform)
    return {"message": "Transform enabled successfully"}


@router.post("/transforms/{transform_id}/disable")
async def disable_transform(transform_id: str):
    """Disable a transform rule"""
    transform = repository.read(transform_id)
    if not transform:
        raise HTTPException(status_code=404, detail="Transform not found")

    transform.enabled = False
    repository.update(transform_id, transform)
    return {"message": "Transform disabled successfully"}


@router.post("/transforms/{transform_id}/dry-run", response_model=DryRunResult)
async def dry_run_transform(transform_id: str):
    """
    Preview which rules would be affected by this transform
    This is the dry-run mode that shows statistics without modifying rules
    """
    # Load the transform
    transform = repository.read(transform_id)
    if not transform:
        raise HTTPException(status_code=404, detail="Transform not found")

    # Run dry-run preview
    rules_cache = get_rules_cache()
    result = TransformEngine.preview_transform(rules_cache, transform)
    return result


@router.post("/transforms/test", response_model=DryRunResult)
async def test_transform(transform: TransformRule):
    """
    Test a transform rule without saving it
    Useful for testing criteria before creating the transform
    """
    # Assign temporary ID for the test
    if not transform.id:
        transform.id = "test"

    # Get rules cache and run dry-run preview
    rules_cache = get_rules_cache()
    result = TransformEngine.preview_transform(rules_cache, transform)

    return result
