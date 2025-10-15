"""
Transform models for rule transform system
"""
from datetime import datetime
from enum import Enum
from typing import Optional, Union, List, Dict, Any
from pydantic import BaseModel, Field


class CriteriaOperator(str, Enum):
    """Operators for matching criteria"""
    EXACT_MATCH = "exact_match"
    CONTAINS = "contains"
    REGEX = "regex"
    IN_LIST = "in_list"
    NOT_IN_LIST = "not_in_list"
    GREATER_THAN = "greater_than"
    LESS_THAN = "less_than"
    EXISTS = "exists"
    NOT_EXISTS = "not_exists"


class TransformActionType(str, Enum):
    """Types of transform actions"""
    ADD_METADATA = "add_metadata"
    MODIFY_METADATA = "modify_metadata"
    UPDATE_PRIORITY = "update_priority"
    ADD_REFERENCE = "add_reference"
    ADD_TAG = "add_tag"


class TransformCriteria(BaseModel):
    """Defines matching criteria for rules"""
    field: str = Field(..., description="Rule field to match (msg, action, protocol, category, etc.)")
    operator: CriteriaOperator = Field(..., description="Matching operator")
    value: Union[str, int, List[str], None] = Field(..., description="Value to match against")
    case_sensitive: bool = Field(default=False, description="Whether matching should be case sensitive")

    class Config:
        use_enum_values = True


class TransformAction(BaseModel):
    """Describes what modification to apply"""
    action_type: TransformActionType = Field(..., description="Type of action to perform")
    key: Optional[str] = Field(None, description="Metadata key or field name")
    value: Union[str, int, None] = Field(..., description="Value to set")

    class Config:
        use_enum_values = True


class TransformRule(BaseModel):
    """Complete transform rule with criteria and actions"""
    id: Optional[str] = Field(None, description="Unique identifier")
    name: str = Field(..., description="Human-readable name")
    description: Optional[str] = Field(None, description="Description of what this transform does")
    enabled: bool = Field(default=True, description="Whether this transform is active")
    criteria: Union[TransformCriteria, List[TransformCriteria]] = Field(..., description="Matching criteria (single or list, combined with AND)")
    actions: List[TransformAction] = Field(..., description="Actions to apply to matched rules")
    created_at: Optional[datetime] = Field(default_factory=datetime.now)
    updated_at: Optional[datetime] = Field(default_factory=datetime.now)


class RuleMatch(BaseModel):
    """Information about a matched rule"""
    sid: int
    msg: str
    source: Optional[str]
    category: Optional[str]
    actions_to_apply: List[TransformAction]


class DryRunResult(BaseModel):
    """Result of a dry-run transform preview"""
    transform_id: str
    transform_name: str
    total_matched: int = Field(..., description="Total number of rules matched")
    total_rules: int = Field(..., description="Total number of rules in the dataset")
    breakdown_by_source: Dict[str, int] = Field(default_factory=dict, description="Count by rule source")
    breakdown_by_category: Dict[str, int] = Field(default_factory=dict, description="Count by category")
    breakdown_by_action: Dict[str, int] = Field(default_factory=dict, description="Count by rule action")
    example_matches: List[RuleMatch] = Field(default_factory=list, description="Sample matched rules")
