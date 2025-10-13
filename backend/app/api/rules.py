"""
API endpoints for Suricata rules
"""
from fastapi import APIRouter, Query, HTTPException
from typing import Optional, List
from pathlib import Path

from app.models.rule import SuricataRule, RuleFilter, RuleResponse, RuleAction
from app.parsers.suricata_parser import SuricataRuleParser
from app.downloaders.suricata_rule_downloader import SuricataRuleDownloader

router = APIRouter()

# In-memory cache for rules (loaded at startup)
_rules_cache: List[SuricataRule] = []
_rules_loaded = False


def load_rules():
    """Load rules from configured sources (downloads and parses)"""
    global _rules_cache, _rules_loaded

    if _rules_loaded:
        return

    print("\n" + "="*60)
    print("Initializing Suricata Rule Browser")
    print("="*60)

    # Initialize downloader (reads rules.yaml)
    downloader = SuricataRuleDownloader()

    # Process all enabled sources (download URL sources, verify local sources)
    print("\nProcessing rule sources...")
    downloader.download_all(force=False)

    # Now parse rules from all sources
    print("\n" + "="*60)
    print("Parsing rules from all sources")
    print("="*60)

    all_rules = []
    base_dir = Path(__file__).resolve().parent.parent.parent.parent

    for source in downloader.sources:
        if not source.enabled:
            continue

        print(f"\nLoading rules from source: {source.name}")

        try:
            if source.type == 'url':
                # URL sources are downloaded to data/rules/{source_name}/
                source_dir = base_dir / "data" / "rules" / source.name
                if source_dir.exists():
                    rules = SuricataRuleParser.parse_directory(source_dir, source=source.name)
                    all_rules.extend(rules)
                else:
                    print(f"  Warning: Directory not found: {source_dir}")

            elif source.type == 'directory':
                # Local directory source
                rules = SuricataRuleParser.parse_directory(
                    source.path,
                    source=source.name,
                    exclude_subdirs=source.exclude_subdirs
                )
                all_rules.extend(rules)

            elif source.type == 'file':
                # Local file source
                rules = SuricataRuleParser.parse_file(source.path, source=source.name)
                all_rules.extend(rules)

        except Exception as e:
            print(f"  Error loading rules from {source.name}: {e}")

    _rules_cache = all_rules
    _rules_loaded = True

    print("\n" + "="*60)
    print(f"Successfully loaded {len(_rules_cache)} rules from {len([s for s in downloader.sources if s.enabled])} sources")
    print("="*60 + "\n")


@router.on_event("startup")
async def startup_event():
    """Load rules when the API starts"""
    load_rules()


@router.get("/rules", response_model=RuleResponse)
async def get_rules(
    page: int = Query(1, ge=1, description="Page number"),
    page_size: int = Query(50, ge=1, le=1000, description="Number of rules per page"),
    search: Optional[str] = Query(None, description="Search in message, SID, and content"),
    action: Optional[RuleAction] = Query(None, description="Filter by action"),
    protocol: Optional[str] = Query(None, description="Filter by protocol"),
    classtype: Optional[str] = Query(None, description="Filter by classification type"),
    priority: Optional[int] = Query(None, description="Filter by priority"),
    sid: Optional[int] = Query(None, description="Filter by specific SID"),
    source: Optional[str] = Query(None, description="Filter by rule source"),
    category: Optional[str] = Query(None, description="Filter by rule category"),
    sort_by: Optional[str] = Query("sid", description="Sort by field (sid, priority, msg)"),
    sort_order: Optional[str] = Query("asc", description="Sort order (asc or desc)")
):
    """
    Get rules with optional filtering, sorting, and pagination

    - **page**: Page number (1-indexed)
    - **page_size**: Number of rules per page
    - **search**: Search text (searches message, SID, and tags)
    - **action**: Filter by action (alert, drop, reject, pass)
    - **protocol**: Filter by protocol
    - **classtype**: Filter by classification type
    - **priority**: Filter by priority level
    - **sid**: Filter by specific SID
    - **source**: Filter by rule source (e.g., 'et-open', 'stamus', 'local')
    - **category**: Filter by rule category (e.g., 'MALWARE', 'INFO', 'EXPLOIT')
    - **sort_by**: Field to sort by
    - **sort_order**: Sort order (asc or desc)
    """
    # Ensure rules are loaded
    if not _rules_loaded:
        load_rules()

    # Start with all rules
    filtered_rules = _rules_cache.copy()

    # Apply filters
    if search:
        search_lower = search.lower()
        filtered_rules = [
            rule for rule in filtered_rules
            if (rule.msg and search_lower in rule.msg.lower()) or
               (rule.id and search_lower in str(rule.id)) or
               any(search_lower in tag for tag in rule.tags)
        ]

    if action:
        filtered_rules = [rule for rule in filtered_rules if rule.action == action]

    if protocol:
        filtered_rules = [rule for rule in filtered_rules if rule.protocol == protocol.lower()]

    if classtype:
        filtered_rules = [
            rule for rule in filtered_rules
            if rule.classtype and rule.classtype.lower() == classtype.lower()
        ]

    if priority is not None:
        filtered_rules = [rule for rule in filtered_rules if rule.priority == priority]

    if sid is not None:
        filtered_rules = [rule for rule in filtered_rules if rule.id == sid]

    if source:
        filtered_rules = [rule for rule in filtered_rules if rule.source == source]

    if category:
        filtered_rules = [rule for rule in filtered_rules if rule.category == category.upper()]

    # Sort rules
    reverse = sort_order.lower() == "desc"

    if sort_by == "sid":
        filtered_rules.sort(key=lambda r: r.id if r.id is not None else 0, reverse=reverse)
    elif sort_by == "priority":
        filtered_rules.sort(key=lambda r: r.priority if r.priority is not None else 999, reverse=reverse)
    elif sort_by == "msg":
        filtered_rules.sort(key=lambda r: r.msg if r.msg else "", reverse=reverse)

    # Calculate pagination
    total = len(filtered_rules)
    start_idx = (page - 1) * page_size
    end_idx = start_idx + page_size
    paginated_rules = filtered_rules[start_idx:end_idx]

    return RuleResponse(
        total=total,
        rules=paginated_rules,
        page=page,
        page_size=page_size
    )


@router.get("/rules/{sid}", response_model=SuricataRule)
async def get_rule_by_sid(sid: int):
    """Get a specific rule by its SID"""
    if not _rules_loaded:
        load_rules()

    for rule in _rules_cache:
        if rule.id == sid:
            return rule

    raise HTTPException(status_code=404, detail=f"Rule with SID {sid} not found")


@router.get("/stats")
async def get_stats():
    """Get statistics about the rules database"""
    if not _rules_loaded:
        load_rules()

    # Calculate statistics
    total_rules = len(_rules_cache)

    actions = {}
    protocols = {}
    classtypes = {}
    priorities = {}
    sources = {}
    categories = {}

    for rule in _rules_cache:
        # Count actions
        actions[rule.action.value] = actions.get(rule.action.value, 0) + 1

        # Count protocols
        protocols[rule.protocol] = protocols.get(rule.protocol, 0) + 1

        # Count classtypes
        if rule.classtype:
            classtypes[rule.classtype] = classtypes.get(rule.classtype, 0) + 1

        # Count priorities
        if rule.priority is not None:
            priorities[rule.priority] = priorities.get(rule.priority, 0) + 1

        # Count sources
        if rule.source:
            sources[rule.source] = sources.get(rule.source, 0) + 1

        # Count categories
        if rule.category:
            categories[rule.category] = categories.get(rule.category, 0) + 1

    return {
        "total_rules": total_rules,
        "actions": actions,
        "protocols": protocols,
        "classtypes": classtypes,
        "priorities": priorities,
        "sources": sources,
        "categories": categories
    }


@router.post("/reload")
async def reload_rules():
    """Reload rules from disk (useful after adding new rule files)"""
    global _rules_cache, _rules_loaded

    _rules_cache = []
    _rules_loaded = False
    load_rules()

    return {
        "status": "success",
        "message": f"Reloaded {len(_rules_cache)} rules"
    }
