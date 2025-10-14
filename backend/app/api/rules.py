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
    action: Optional[List[str]] = Query(None, description="Filter by action (can specify multiple)"),
    protocol: Optional[List[str]] = Query(None, description="Filter by protocol (can specify multiple)"),
    classtype: Optional[List[str]] = Query(None, description="Filter by classification type (can specify multiple)"),
    priority: Optional[List[int]] = Query(None, description="Filter by priority (can specify multiple)"),
    sid: Optional[int] = Query(None, description="Filter by specific SID"),
    source: Optional[List[str]] = Query(None, description="Filter by rule source (can specify multiple)"),
    category: Optional[List[str]] = Query(None, description="Filter by rule category (can specify multiple)"),
    signature_severity: Optional[List[str]] = Query(None, description="Filter by signature severity (can specify multiple)"),
    attack_target: Optional[List[str]] = Query(None, description="Filter by attack target (can specify multiple)"),
    deployment: Optional[List[str]] = Query(None, description="Filter by deployment type (can specify multiple)"),
    affected_product: Optional[List[str]] = Query(None, description="Filter by affected product (can specify multiple)"),
    confidence: Optional[List[str]] = Query(None, description="Filter by confidence level (can specify multiple)"),
    performance_impact: Optional[List[str]] = Query(None, description="Filter by performance impact (can specify multiple)"),
    sort_by: Optional[str] = Query("msg", description="Sort by field (sid, priority, msg)"),
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
        filtered_rules = [rule for rule in filtered_rules if rule.action.value in action]

    if protocol:
        protocol_lower = [p.lower() for p in protocol]
        filtered_rules = [rule for rule in filtered_rules if rule.protocol in protocol_lower]

    if classtype:
        classtype_lower = [c.lower() for c in classtype]
        filtered_rules = [
            rule for rule in filtered_rules
            if rule.classtype and rule.classtype.lower() in classtype_lower
        ]

    if priority is not None:
        filtered_rules = [rule for rule in filtered_rules if rule.priority in priority]

    if sid is not None:
        filtered_rules = [rule for rule in filtered_rules if rule.id == sid]

    if source:
        filtered_rules = [rule for rule in filtered_rules if rule.source in source]

    if category:
        category_upper = [c.upper() for c in category]
        filtered_rules = [rule for rule in filtered_rules if rule.category in category_upper]

    if signature_severity:
        filtered_rules = [rule for rule in filtered_rules if rule.signature_severity in signature_severity]

    if attack_target:
        filtered_rules = [rule for rule in filtered_rules if rule.attack_target in attack_target]

    if deployment:
        filtered_rules = [rule for rule in filtered_rules if rule.deployment in deployment]

    if affected_product:
        filtered_rules = [rule for rule in filtered_rules if rule.affected_product in affected_product]

    if confidence:
        filtered_rules = [rule for rule in filtered_rules if rule.confidence in confidence]

    if performance_impact:
        filtered_rules = [rule for rule in filtered_rules if rule.performance_impact in performance_impact]

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
    signature_severities = {}
    attack_targets = {}
    deployments = {}
    affected_products = {}
    confidences = {}
    performance_impacts = {}

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

        # Count metadata-based filters
        if rule.signature_severity:
            signature_severities[rule.signature_severity] = signature_severities.get(rule.signature_severity, 0) + 1

        if rule.attack_target:
            attack_targets[rule.attack_target] = attack_targets.get(rule.attack_target, 0) + 1

        if rule.deployment:
            deployments[rule.deployment] = deployments.get(rule.deployment, 0) + 1

        if rule.affected_product:
            affected_products[rule.affected_product] = affected_products.get(rule.affected_product, 0) + 1

        if rule.confidence:
            confidences[rule.confidence] = confidences.get(rule.confidence, 0) + 1

        if rule.performance_impact:
            performance_impacts[rule.performance_impact] = performance_impacts.get(rule.performance_impact, 0) + 1

    return {
        "total_rules": total_rules,
        "actions": actions,
        "protocols": protocols,
        "classtypes": classtypes,
        "priorities": priorities,
        "sources": sources,
        "categories": categories,
        "signature_severities": signature_severities,
        "attack_targets": attack_targets,
        "deployments": deployments,
        "affected_products": affected_products,
        "confidences": confidences,
        "performance_impacts": performance_impacts
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
