"""
API endpoints for Suricata rules
"""
from fastapi import APIRouter, Query, HTTPException, Request
from typing import Optional, List
from pathlib import Path
from collections import defaultdict

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

    print("\n" + "=" * 60)
    print("Initializing Suricata Rule Browser")
    print("=" * 60)

    # Initialize downloader (reads rules.yaml)
    downloader = SuricataRuleDownloader()

    # Process all enabled sources (download URL sources, verify local sources)
    print("\nProcessing rule sources...")
    downloader.download_all(force=False)

    # Now parse rules from all sources
    print("\n" + "=" * 60)
    print("Parsing rules from all sources")
    print("=" * 60)

    all_rules = []
    base_dir = Path(__file__).resolve().parent.parent.parent

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

    # Count enabled and disabled rules
    enabled_count = sum(1 for rule in _rules_cache if rule.enabled)
    disabled_count = sum(1 for rule in _rules_cache if not rule.enabled)

    print("\n" + "=" * 60)
    print(
        f"Successfully loaded {len(_rules_cache)} rules from {len([s for s in downloader.sources if s.enabled])} sources")
    print(f"  - {enabled_count} enabled")
    print(f"  - {disabled_count} disabled")
    print("=" * 60 + "\n")


@router.get("/rules", response_model=RuleResponse)
async def get_rules(
        request: Request,
        page: int = Query(1, ge=1, description="Page number"),
        page_size: int = Query(50, ge=1, le=1000, description="Number of rules per page"),
        search: Optional[str] = Query(None, description="Search in message, SID, and content"),
        action: Optional[List[str]] = Query(None, description="Filter by action (can specify multiple)"),
        protocol: Optional[List[str]] = Query(None, description="Filter by protocol (can specify multiple)"),
        classtype: Optional[List[str]] = Query(None,
                                               description="Filter by classification type (can specify multiple)"),
        sid: Optional[int] = Query(None, description="Filter by specific SID"),
        source: Optional[List[str]] = Query(None, description="Filter by rule source (can specify multiple)"),
        category: Optional[List[str]] = Query(None, description="Filter by rule category (can specify multiple)"),
        enabled: Optional[List[str]] = Query(None,
                                             description="Filter by enabled status (true/false, can specify multiple)"),
        sort_by: Optional[str] = Query("msg", description="Sort by field (sid, msg)"),
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
    - **sid**: Filter by specific SID
    - **source**: Filter by rule source (e.g., 'et-open', 'stamus', 'local')
    - **category**: Filter by rule category (e.g., 'MALWARE', 'INFO', 'EXPLOIT')
    - **sort_by**: Field to sort by
    - **sort_order**: Sort order (asc or desc)
    """
    # Ensure rules are loaded
    if not _rules_loaded:
        load_rules()

    # Extract all query params
    query_params = dict(request.query_params)

    # Define known filters (the ones already handled explicitly above)
    known_fields = {
        "page", "page_size", "search", "action", "protocol", "classtype",
        "sid", "source", "category", "enabled", "sort_by", "sort_order"
    }

    # Separate dynamic metadata filters (everything not explicitly declared)
    metadata_filters = {
        key: value for key, value in query_params.items() if key not in known_fields
    }

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
        filtered_rules = [rule for rule in filtered_rules if rule.action.value in action]

    if protocol:
        protocol_lower = [p.lower() for p in protocol]
        filtered_rules = [rule for rule in filtered_rules if rule.protocol in protocol_lower]

    if classtype:
        classtype_lower = [c.lower() for c in classtype]
        filtered_rules = [
            rule for rule in filtered_rules
            if (rule.classtype and rule.classtype.lower() in classtype_lower) or
               (not rule.classtype and "(unset)" in classtype)
        ]

    if sid is not None:
        filtered_rules = [rule for rule in filtered_rules if rule.id == sid]

    if source:
        filtered_rules = [
            rule for rule in filtered_rules
            if rule.source in source or
               (not rule.source and "(unset)" in source)
        ]

    if category:
        category_upper = [c.upper() for c in category]
        filtered_rules = [
            rule for rule in filtered_rules
            if rule.category in category_upper or
               (not rule.category and "(unset)" in category)
        ]

    if enabled:
        # Convert string values to boolean
        enabled_bool = [e.lower() == 'true' for e in enabled]
        filtered_rules = [
            rule for rule in filtered_rules
            if rule.enabled in enabled_bool
        ]

    if metadata_filters:
        # Convert query params to support multiple values for the same key
        metadata_multi = defaultdict(list)
        for key in metadata_filters.keys():
            # Get all values for this metadata key (handles multiple selections)
            all_values = request.query_params.getlist(key)
            metadata_multi[key] = [v.lower() for v in all_values]

        # Filter rules: a rule matches if for each metadata key, its value is in the selected values
        filtered_rules = [
            rule for rule in filtered_rules
            if all(
                str(rule.metadata.get(k, "")).lower() in values
                for k, values in metadata_multi.items()
            )
        ]

    # Sort rules
    reverse = sort_order.lower() == "desc"

    # Define sort keys for different fields
    sort_keys = {
        "sid": lambda r: r.id if r.id is not None else 0,
        "msg": lambda r: (r.msg or "").lower(),
        "action": lambda r: r.action.value,
        "enabled": lambda r: r.enabled,
        "protocol": lambda r: r.protocol.lower(),
        "source": lambda r: (r.source or "").lower(),
        "category": lambda r: (r.category or "").lower(),
        "classtype": lambda r: (r.classtype or "").lower(),
        "severity": lambda r: (r.signature_severity or "").lower(),        
        "rev": lambda r: r.rev if r.rev is not None else 0,
    }

    # Apply sorting if the field is valid
    if sort_by in sort_keys:
        filtered_rules.sort(key=sort_keys[sort_by], reverse=reverse)
    else:
        # Default to sorting by message
        filtered_rules.sort(key=sort_keys["msg"], reverse=reverse)

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
    sources = {}
    categories = {}    
    enabled_status = {}
    metadata = defaultdict(lambda: defaultdict(int))

    for rule in _rules_cache:
        # Count actions
        actions[rule.action.value] = actions.get(rule.action.value, 0) + 1

        # Count protocols
        protocols[rule.protocol] = protocols.get(rule.protocol, 0) + 1

        # Count classtypes
        classtype_key = rule.classtype if rule.classtype else "(unset)"
        classtypes[classtype_key] = classtypes.get(classtype_key, 0) + 1

        # Count sources
        source_key = rule.source if rule.source else "(unset)"
        sources[source_key] = sources.get(source_key, 0) + 1

        # Count categories
        category_key = rule.category if rule.category else "(unset)"
        categories[category_key] = categories.get(category_key, 0) + 1

        # Count enabled status
        enabled_key = "true" if rule.enabled else "false"
        enabled_status[enabled_key] = enabled_status.get(enabled_key, 0) + 1

        # Dynamically count all occuring metadata fields
        for key, value in rule.metadata.items():
            if isinstance(value, list):
                for item in value:
                    metadata[key][item] += 1
            else:
                metadata[key][value] += 1

    return {
        "total_rules": total_rules,
        "actions": actions,
        "protocols": protocols,
        "classtypes": classtypes,
        "sources": sources,
        "categories": categories,
        "enabled_status": enabled_status,
        "metadata": metadata
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
