"""
Repository for managing transform rules storage
"""
import json
import uuid
from pathlib import Path
from typing import List, Optional
from datetime import datetime
from app.models.transform import TransformRule


class TransformRepository:
    """Manages transform rules storage using JSON files"""

    def __init__(self, storage_dir: Optional[Path] = None):
        """
        Initialize repository

        Args:
            storage_dir: Directory to store transform files. Defaults to data/transforms/
        """
        if storage_dir is None:
            # Default to data/transforms/ relative to project root
            self.storage_dir = Path(__file__).resolve().parent.parent.parent.parent / "data" / "transforms"
        else:
            self.storage_dir = storage_dir

        # Create directory if it doesn't exist
        self.storage_dir.mkdir(parents=True, exist_ok=True)

    def _get_file_path(self, transform_id: str) -> Path:
        """Get file path for a transform"""
        return self.storage_dir / f"{transform_id}.json"

    def create(self, transform: TransformRule) -> str:
        """
        Save a new transform rule

        Args:
            transform: The transform rule to save

        Returns:
            Transform ID
        """
        # Generate ID if not provided
        if not transform.id:
            transform.id = f"transform-{uuid.uuid4().hex[:8]}"

        # Set timestamps
        now = datetime.now()
        transform.created_at = now
        transform.updated_at = now

        # Save to file
        file_path = self._get_file_path(transform.id)
        with open(file_path, 'w', encoding='utf-8') as f:
            json.dump(transform.dict(), f, indent=2, default=str)

        return transform.id

    def read(self, transform_id: str) -> Optional[TransformRule]:
        """
        Load a transform rule by ID

        Args:
            transform_id: ID of the transform to load

        Returns:
            TransformRule if found, None otherwise
        """
        file_path = self._get_file_path(transform_id)
        if not file_path.exists():
            return None

        with open(file_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
            return TransformRule(**data)

    def update(self, transform_id: str, transform: TransformRule) -> bool:
        """
        Update an existing transform rule

        Args:
            transform_id: ID of the transform to update
            transform: Updated transform data

        Returns:
            True if successful, False if not found
        """
        file_path = self._get_file_path(transform_id)
        if not file_path.exists():
            return False

        # Preserve ID and created_at
        existing = self.read(transform_id)
        if existing:
            transform.id = transform_id
            transform.created_at = existing.created_at
            transform.updated_at = datetime.now()

        # Save to file
        with open(file_path, 'w', encoding='utf-8') as f:
            json.dump(transform.dict(), f, indent=2, default=str)

        return True

    def delete(self, transform_id: str) -> bool:
        """
        Delete a transform rule

        Args:
            transform_id: ID of the transform to delete

        Returns:
            True if successful, False if not found
        """
        file_path = self._get_file_path(transform_id)
        if not file_path.exists():
            return False

        file_path.unlink()
        return True

    def list_all(self) -> List[TransformRule]:
        """
        Get all transform rules

        Returns:
            List of all transform rules
        """
        transforms = []
        for file_path in self.storage_dir.glob("*.json"):
            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    transforms.append(TransformRule(**data))
            except Exception:
                # Skip invalid files
                continue

        return transforms

    def list_enabled(self) -> List[TransformRule]:
        """
        Get only enabled transform rules

        Returns:
            List of enabled transform rules
        """
        return [e for e in self.list_all() if e.enabled]
