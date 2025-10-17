"""
Data models for Suricata rules
"""
from pydantic import BaseModel, Field
from typing import Optional, Dict, List, Union, Any
from enum import Enum


class RuleAction(str, Enum):
    """Suricata rule actions"""
    ALERT = "alert"
    DROP = "drop"
    REJECT = "reject"
    PASS = "pass"


class SuricataRule(BaseModel):
    """Model representing a parsed Suricata rule"""
    id: Optional[int] = Field(None, description="Rule SID (Signature ID)")
    action: RuleAction = Field(..., description="Rule action (alert, drop, etc.)")
    protocol: str = Field(..., description="Protocol (tcp, udp, icmp, etc.)")
    src_ip: str = Field(..., description="Source IP address or network")
    src_port: str = Field(..., description="Source port")
    direction: str = Field(..., description="Direction operator (-> or <>)")
    dst_ip: str = Field(..., description="Destination IP address or network")
    dst_port: str = Field(..., description="Destination port")

    # Rule options
    msg: Optional[str] = Field(None, description="Rule message")
    classtype: Optional[str] = Field(None, description="Classification type")
    priority: Optional[int] = Field(None, description="Priority level")
    reference: Optional[List[str]] = Field(default_factory=list, description="External references")
    rev: Optional[int] = Field(None, description="Revision number")
    metadata: Optional[Dict[str, str]] = Field(default_factory=dict, description="Metadata fields")

    # Additional parsed options (values can be strings or lists of strings)
    options: Dict[str, Union[str, List[str]]] = Field(default_factory=dict, description="All rule options")

    # Original rule text
    raw_rule: str = Field(..., description="Original rule text")

    # Searchable fields
    tags: List[str] = Field(default_factory=list, description="Tags extracted from rule")

    # Source tracking
    source: Optional[str] = Field(None, description="Rule source (e.g., 'et-open', 'stamus', 'local')")
    source_file: Optional[str] = Field(None, description="Original filename")

    # Rule state
    enabled: bool = Field(True, description="Whether the rule is enabled (False if commented out)")

    # Category tracking (extracted from message prefix like "ET MALWARE", "ET INFO")
    category: Optional[str] = Field(None, description="Rule category (e.g., 'MALWARE', 'INFO', 'EXPLOIT')")

    # Metadata-based fields for additional filtering
    signature_severity: Optional[str] = Field(None, description="Signature severity from metadata (Critical, Major, Minor, Informational)")
    attack_target: Optional[str] = Field(None, description="Attack target from metadata (e.g., Client_Endpoint, Server, Web_Server)")
    deployment: Optional[str] = Field(None, description="Deployment type from metadata (e.g., Perimeter, Internal, Datacenter)")
    affected_product: Optional[str] = Field(None, description="Affected product from metadata")
    confidence: Optional[str] = Field(None, description="Detection confidence from metadata (High, Medium, Low)")
    performance_impact: Optional[str] = Field(None, description="Performance impact from metadata (Low, Medium, High)")
    created_at: Optional[str] = Field(None, description="Creation date from metadata")
    updated_at: Optional[str] = Field(None, description="Last update date from metadata")

    class Config:
        json_schema_extra = {
            "example": {
                "id": 2000001,
                "action": "alert",
                "protocol": "tcp",
                "src_ip": "any",
                "src_port": "any",
                "direction": "->",
                "dst_ip": "any",
                "dst_port": "80",
                "msg": "Potential SQL Injection Attack",
                "classtype": "web-application-attack",
                "priority": 1,
                "reference": ["url,example.com/ref"],
                "rev": 1,
                "raw_rule": 'alert tcp any any -> any 80 (msg:"Potential SQL Injection Attack"; sid:2000001; rev:1;)',
                "tags": ["sql", "injection", "web"]
            }
        }


class RuleFilter(BaseModel):
    """Filter parameters for searching rules"""
    search: Optional[str] = Field(None, description="Search text (searches msg, sid, and content)")
    action: Optional[RuleAction] = Field(None, description="Filter by action")
    protocol: Optional[str] = Field(None, description="Filter by protocol")
    classtype: Optional[str] = Field(None, description="Filter by classification type")
    priority: Optional[int] = Field(None, description="Filter by priority")
    sid: Optional[int] = Field(None, description="Filter by specific SID")
    source: Optional[str] = Field(None, description="Filter by rule source")
    category: Optional[str] = Field(None, description="Filter by rule category")

    class Config:
        json_schema_extra = {
            "example": {
                "search": "sql injection",
                "action": "alert",
                "protocol": "tcp"
            }
        }


class RuleResponse(BaseModel):
    """Response model for rule queries"""
    total: int = Field(..., description="Total number of rules matching the filter")
    rules: List[SuricataRule] = Field(..., description="List of rules")
    page: int = Field(1, description="Current page number")
    page_size: int = Field(50, description="Number of rules per page")
