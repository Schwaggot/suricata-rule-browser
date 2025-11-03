"""
API endpoints for Suricata rules
"""
from fastapi import APIRouter, Query, HTTPException, Request
from typing import Optional, List, Dict
from pathlib import Path
from collections import defaultdict
import re
import json

from app.models.rule import SuricataRule, RuleFilter, RuleResponse, RuleAction
from app.parsers.suricata_parser import SuricataRuleParser
from app.downloaders.suricata_rule_downloader import SuricataRuleDownloader

router = APIRouter()

# In-memory cache for rules (loaded at startup)
_rules_cache: List[SuricataRule] = []
_rules_loaded = False
_stats_cache = None
_llm_summaries: Dict[int, Dict[str, any]] = {}  # SID -> {markdown, name, doc_rev}


def parse_search_query(query: str) -> tuple[List[str], List[str]]:
    """
    Parse a search query to extract quoted phrases and unquoted terms,
    separating positive and negative (prefixed with !) terms.

    Unquoted terms are split by spaces (OR logic - any term matches).
    Quoted phrases are kept as exact strings.
    Terms prefixed with ! are negated (must NOT match).
    Use \\! to search for a literal ! character.

    Examples:
        'malware' -> (['malware'], [])
        'class function' -> (['class', 'function'], [])
        '"class function"' -> (['class function'], [])
        '!malware' -> ([], ['malware'])
        'alert !malware' -> (['alert'], ['malware'])
        '!malware !trojan' -> ([], ['malware', 'trojan'])
        '!"ET MALWARE"' -> ([], ['ET MALWARE'])
        'alert drop !malware !"pcre:"' -> (['alert', 'drop'], ['malware', 'pcre:'])
        '\\!important' -> (['!important'], [])

    Returns:
        Tuple of (positive_terms, negative_terms)
    """
    if not query:
        return ([], [])

    # Replace escaped exclamation marks with placeholder
    ESCAPED_EXCLAMATION = '\x00ESCAPED_EXCLAMATION\x00'
    query = query.replace('\\!', ESCAPED_EXCLAMATION)

    positive_terms = []
    negative_terms = []

    # Find all quoted strings (including those with ! prefix)
    # Pattern: optional !, then quoted string
    quoted_pattern = r'(!?)"([^"]*)"'
    quoted_matches = re.findall(quoted_pattern, query)

    for prefix, content in quoted_matches:
        # Restore escaped exclamation marks
        content = content.replace(ESCAPED_EXCLAMATION, '!')
        if prefix == '!':
            negative_terms.append(content)
        else:
            positive_terms.append(content)

    # Remove quoted strings from query to find unquoted terms
    remaining = re.sub(quoted_pattern, '', query)

    # Split remaining text by whitespace and filter out empty strings
    unquoted_terms = [term.strip() for term in remaining.split() if term.strip()]

    for term in unquoted_terms:
        # Check for negation BEFORE restoring escaped exclamation marks
        if term.startswith(ESCAPED_EXCLAMATION):
            # Escaped exclamation mark - restore and treat as positive
            term = term.replace(ESCAPED_EXCLAMATION, '!')
            positive_terms.append(term)
        elif term.startswith('!'):
            # Negation - remove ! and add to negative terms
            term = term[1:].replace(ESCAPED_EXCLAMATION, '!')
            negative_terms.append(term)
        else:
            # Regular positive term
            term = term.replace(ESCAPED_EXCLAMATION, '!')
            positive_terms.append(term)

    return (positive_terms, negative_terms)


def format_search_logic(positive_terms: List[str], negative_terms: List[str]) -> str:
    """
    Format search terms into a human-readable logic expression.

    Examples:
        (['apple', 'orange'], []) -> '"apple" OR "orange"'
        (['pcre'], ['malware', 'control']) -> '"pcre" AND NOT "malware" AND NOT "control"'
        ([], ['malware', 'trojan']) -> 'NOT "malware" AND NOT "trojan"'
        (['alert', 'drop'], ['malware']) -> '("alert" OR "drop") AND NOT "malware"'
    """
    if not positive_terms and not negative_terms:
        return ""

    parts = []

    # Format positive terms (OR logic)
    if positive_terms:
        positive_str = " OR ".join(f'"{term}"' for term in positive_terms)
        # Add parentheses if there are multiple positive terms AND negative terms
        if len(positive_terms) > 1 and negative_terms:
            positive_str = f"({positive_str})"
        parts.append(positive_str)

    # Format negative terms (AND NOT logic)
    if negative_terms:
        negative_strs = [f'NOT "{term}"' for term in negative_terms]
        if parts:
            # Already have positive terms, join with AND
            parts.extend(negative_strs)
            return " AND ".join(parts)
        else:
            # Only negative terms
            return " AND ".join(negative_strs)

    return parts[0] if parts else ""


def load_llm_summaries():
    """Load LLM summaries from ids-docs.json"""
    global _llm_summaries

    docs_path = Path("ids-docs.json")
    if not docs_path.exists():
        print("⚠️  ids-docs.json not found, LLM summaries will not be available")
        return

    try:
        with open(docs_path, 'r', encoding='utf-8') as f:
            docs_data = json.load(f)

        # Parse the reference array and index by SID
        for ref in docs_data.get("reference", []):
            ref_id = ref.get("id", "")
            # Extract SID from format "sid-rev" (e.g., "2008719-5")
            if "-" in ref_id:
                sid_str, rev_str = ref_id.split("-", 1)
                try:
                    sid = int(sid_str)
                    doc_rev = int(rev_str)

                    # Get the English markdown content
                    i18n = ref.get("i18n", {})
                    en = i18n.get("en", {})
                    markdown = en.get("markdown", "")
                    name = en.get("name", "")

                    if markdown:
                        _llm_summaries[sid] = {
                            "markdown": markdown,
                            "name": name,
                            "doc_rev": doc_rev
                        }
                except (ValueError, IndexError):
                    continue

        print(f"✓ Loaded {len(_llm_summaries)} LLM summaries from ids-docs.json")
    except Exception as e:
        print(f"⚠️  Error loading ids-docs.json: {e}")
        _llm_summaries = {}


def load_rules():
    """Load rules from configured sources (downloads and parses)"""
    global _rules_cache, _rules_loaded, _stats_cache

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

    # Load LLM summaries
    load_llm_summaries()
    total_summaries_loaded = len(_llm_summaries)

    # Enrich rules with LLM summaries
    enriched_count = 0
    for rule in _rules_cache:
        if rule.id and rule.id in _llm_summaries:
            summary_data = _llm_summaries[rule.id]
            rule.llm_summary = summary_data["markdown"]
            rule.llm_summary_available = True
            rule.llm_summary_rev = summary_data["doc_rev"]
            # Check if revision matches
            rule.llm_summary_rev_mismatch = (rule.rev is not None and
                                             rule.rev != summary_data["doc_rev"])
            enriched_count += 1

    # Count enabled and disabled rules
    enabled_count = sum(1 for rule in _rules_cache if rule.enabled)
    disabled_count = sum(1 for rule in _rules_cache if not rule.enabled)

    print("\n" + "=" * 60)
    print(
        f"Successfully loaded {len(_rules_cache)} rules from {len([s for s in downloader.sources if s.enabled])} sources")
    print(f"  - {enabled_count} enabled")
    print(f"  - {disabled_count} disabled")
    if total_summaries_loaded > 0:
        print(f"  - {enriched_count:,} rules matched with LLM summaries")
        print(f"    ({total_summaries_loaded:,} total summaries loaded, {total_summaries_loaded - enriched_count:,} for rules not in current database)")
    print("=" * 60 + "\n")

    # Compute and cache statistics
    print("Computing statistics...")
    _compute_stats()
    print("Statistics cached.")


@router.get("/rules", response_model=RuleResponse)
async def get_rules(
        request: Request,
        page: int = Query(1, ge=1, description="Page number"),
        page_size: int = Query(50, ge=1, le=1000, description="Number of rules per page"),
        search: Optional[str] = Query(None, description="Search in message, SID, and content"),
        raw_search: Optional[str] = Query(None, description="Search in raw rule text"),
        action: Optional[List[str]] = Query(None, description="Filter by action (can specify multiple)"),
        protocol: Optional[List[str]] = Query(None, description="Filter by protocol (can specify multiple)"),
        classtype: Optional[List[str]] = Query(None,
                                               description="Filter by classification type (can specify multiple)"),
        sid: Optional[int] = Query(None, description="Filter by specific SID"),
        source: Optional[List[str]] = Query(None, description="Filter by rule source (can specify multiple)"),
        category: Optional[List[str]] = Query(None, description="Filter by rule category (can specify multiple)"),
        enabled: Optional[List[str]] = Query(None,
                                             description="Filter by enabled status (true/false, can specify multiple)"),
        llm_summary: Optional[List[str]] = Query(None,
                                                 description="Filter by LLM summary availability (true/false, can specify multiple)"),
        sort_by: Optional[str] = Query("msg", description="Sort by field (sid, msg)"),
        sort_order: Optional[str] = Query("asc", description="Sort order (asc or desc)")
):
    """
    Get rules with optional filtering, sorting, and pagination

    - **page**: Page number (1-indexed)
    - **page_size**: Number of rules per page
    - **search**: Search text (searches message, SID, and tags)
    - **raw_search**: Search text (searches raw rule text)
    - **action**: Filter by action (alert, drop, reject, pass)
    - **protocol**: Filter by protocol
    - **classtype**: Filter by classification type
    - **sid**: Filter by specific SID
    - **source**: Filter by rule source (e.g., 'et-open', 'stamus', 'local')
    - **category**: Filter by rule category (e.g., 'MALWARE', 'INFO', 'EXPLOIT')
    - **llm_summary**: Filter by LLM summary availability (true/false)
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
        "page", "page_size", "search", "raw_search", "action", "protocol", "classtype",
        "sid", "source", "category", "enabled", "llm_summary", "sort_by", "sort_order"
    }

    # Separate dynamic metadata filters (everything not explicitly declared)
    metadata_filters = {
        key: value for key, value in query_params.items() if key not in known_fields
    }

    # Start with all rules
    filtered_rules = _rules_cache.copy()

    # Apply filters
    if search or raw_search:
        def term_matches_in_standard_fields(rule, term):
            """Check if a single term matches in msg, SID, or tags"""
            term_lower = term.lower()
            return ((rule.msg and term_lower in rule.msg.lower()) or
                    (rule.id and term_lower in str(rule.id)) or
                    any(term_lower in tag for tag in rule.tags))

        def term_matches_in_raw(rule, term):
            """Check if a single term matches in raw rule text"""
            term_lower = term.lower()
            return rule.raw_rule and term_lower in rule.raw_rule.lower()

        def matches_standard_search(rule, positive_terms, negative_terms):
            """
            Check if rule matches standard search criteria.
            Positive terms: OR logic (match ANY)
            Negative terms: AND logic (match NONE)
            """
            # Check positive terms (if any, at least one must match)
            if positive_terms:
                has_positive_match = any(term_matches_in_standard_fields(rule, term)
                                        for term in positive_terms)
                if not has_positive_match:
                    return False

            # Check negative terms (none should match)
            if negative_terms:
                has_negative_match = any(term_matches_in_standard_fields(rule, term)
                                        for term in negative_terms)
                if has_negative_match:
                    return False

            return True

        def matches_raw_search(rule, positive_terms, negative_terms):
            """
            Check if rule matches raw text search criteria.
            Positive terms: OR logic (match ANY)
            Negative terms: AND logic (match NONE)
            """
            # Check positive terms (if any, at least one must match)
            if positive_terms:
                has_positive_match = any(term_matches_in_raw(rule, term)
                                        for term in positive_terms)
                if not has_positive_match:
                    return False

            # Check negative terms (none should match)
            if negative_terms:
                has_negative_match = any(term_matches_in_raw(rule, term)
                                        for term in negative_terms)
                if has_negative_match:
                    return False

            return True

        def matches_search_criteria(rule):
            # Both search bars must match if provided (AND logic)

            # Standard search in msg, SID, and tags
            if search:
                positive_terms, negative_terms = parse_search_query(search)
                if not matches_standard_search(rule, positive_terms, negative_terms):
                    return False

            # Raw rule text search
            if raw_search:
                positive_terms, negative_terms = parse_search_query(raw_search)
                if not matches_raw_search(rule, positive_terms, negative_terms):
                    return False

            return True

        filtered_rules = [rule for rule in filtered_rules if matches_search_criteria(rule)]

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

    if llm_summary:
        # Convert string values to boolean
        llm_summary_bool = [s.lower() == 'true' for s in llm_summary]
        filtered_rules = [
            rule for rule in filtered_rules
            if rule.llm_summary_available in llm_summary_bool
        ]

    if metadata_filters:
        # Convert query params to support multiple values for the same key
        metadata_multi = defaultdict(list)
        for key in metadata_filters.keys():
            # Get all values for this metadata key (handles multiple selections)
            all_values = request.query_params.getlist(key)
            metadata_multi[key] = [v.lower() for v in all_values]

        # Filter rules: a rule matches if for each metadata key, its value is in the selected values
        def matches_metadata_filter(rule):
            for key, values in metadata_multi.items():
                rule_value = str(rule.metadata.get(key, "")).lower()

                # Check if rule has the metadata field
                has_field = key in rule.metadata and rule.metadata.get(key)

                # Check if "(unset)" is in the selected values
                unset_selected = "(unset)" in values

                if unset_selected and not has_field:
                    # Rule doesn't have this field and "(unset)" is selected - matches
                    continue
                elif has_field and rule_value in values:
                    # Rule has this field and value matches - matches
                    continue
                else:
                    # No match for this metadata key
                    return False
            return True

        filtered_rules = [rule for rule in filtered_rules if matches_metadata_filter(rule)]

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
    # Build search logic display
    search_logic_parts = []

    if search:
        positive_terms, negative_terms = parse_search_query(search)
        if positive_terms or negative_terms:
            logic_str = format_search_logic(positive_terms, negative_terms)
            search_logic_parts.append(f"Standard: {logic_str}")

    if raw_search:
        positive_terms, negative_terms = parse_search_query(raw_search)
        if positive_terms or negative_terms:
            logic_str = format_search_logic(positive_terms, negative_terms)
            search_logic_parts.append(f"Raw Text: {logic_str}")

    # Combine search logic parts with AND
    search_logic = None
    if search_logic_parts:
        if len(search_logic_parts) == 1:
            search_logic = search_logic_parts[0]
        else:
            search_logic = " AND ".join(f"({part})" for part in search_logic_parts)

    total = len(filtered_rules)
    start_idx = (page - 1) * page_size
    end_idx = start_idx + page_size
    paginated_rules = filtered_rules[start_idx:end_idx]

    return RuleResponse(
        total=total,
        rules=paginated_rules,
        page=page,
        page_size=page_size,
        search_logic=search_logic
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


def _compute_stats():
    """Compute and cache statistics about the rules database"""
    global _stats_cache

    # Calculate statistics
    total_rules = len(_rules_cache)

    actions = {}
    protocols = {}
    classtypes = {}
    sources = {}
    categories = {}
    enabled_status = {}
    llm_status = {}
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

        # Count LLM summary availability
        llm_key = "true" if rule.llm_summary_available else "false"
        llm_status[llm_key] = llm_status.get(llm_key, 0) + 1

        # Dynamically count all occuring metadata fields
        for key, value in rule.metadata.items():
            if isinstance(value, list):
                for item in value:
                    metadata[key][item] += 1
            else:
                metadata[key][value] += 1

    # Count rules without each metadata field
    for key in metadata.keys():
        unset_count = sum(1 for rule in _rules_cache if key not in rule.metadata or not rule.metadata.get(key))
        if unset_count > 0:
            metadata[key]["(unset)"] = unset_count

    _stats_cache = {
        "total_rules": total_rules,
        "actions": actions,
        "protocols": protocols,
        "classtypes": classtypes,
        "sources": sources,
        "categories": categories,
        "enabled_status": enabled_status,
        "llm_status": llm_status,
        "metadata": metadata
    }


@router.get("/stats")
async def get_stats():
    """Get statistics about the rules database"""
    if not _rules_loaded:
        load_rules()

    # Return cached statistics
    return _stats_cache


@router.post("/reload")
async def reload_rules():
    """Reload rules from disk (useful after adding new rule files)"""
    global _rules_cache, _rules_loaded, _stats_cache

    _rules_cache = []
    _rules_loaded = False
    _stats_cache = None
    load_rules()

    return {
        "status": "success",
        "message": f"Reloaded {len(_rules_cache)} rules"
    }
