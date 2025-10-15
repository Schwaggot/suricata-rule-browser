"""
Transform engine for applying transforms to rules and generating dry-run results
"""
from typing import List
from collections import defaultdict
from app.models.rule import SuricataRule
from app.models.transform import TransformRule, DryRunResult, RuleMatch
from app.engines.criteria_engine import CriteriaEvaluator


class TransformEngine:
    """Applies transforms to rules and generates dry-run previews"""

    @staticmethod
    def preview_transform(
        rules: List[SuricataRule],
        transform: TransformRule
    ) -> DryRunResult:
        """
        Preview what rules would be affected by a transform without modifying them

        Args:
            rules: List of all Suricata rules
            transform: The transform rule to preview

        Returns:
            DryRunResult with statistics and example matches
        """
        matched_rules = []
        breakdown_by_source = defaultdict(int)
        breakdown_by_category = defaultdict(int)
        breakdown_by_action = defaultdict(int)

        # Evaluate each rule against criteria (support single or multiple criteria with AND logic)
        criteria_list = transform.criteria if isinstance(transform.criteria, list) else [transform.criteria]

        for rule in rules:
            # All criteria must match (AND logic)
            if all(CriteriaEvaluator.evaluate_criteria(rule, criteria) for criteria in criteria_list):
                matched_rules.append(rule)

                # Update breakdowns
                source = rule.source or "(unknown)"
                breakdown_by_source[source] += 1

                category = rule.category or "(unset)"
                breakdown_by_category[category] += 1

                action = rule.action.value if rule.action else "(unknown)"
                breakdown_by_action[action] += 1

        # Create example matches (first 10)
        example_matches = []
        for rule in matched_rules[:10]:
            example_matches.append(RuleMatch(
                sid=rule.id or 0,
                msg=rule.msg or "(no message)",
                source=rule.source,
                category=rule.category,
                actions_to_apply=transform.actions
            ))

        return DryRunResult(
            transform_id=transform.id or "",
            transform_name=transform.name,
            total_matched=len(matched_rules),
            total_rules=len(rules),
            breakdown_by_source=dict(breakdown_by_source),
            breakdown_by_category=dict(breakdown_by_category),
            breakdown_by_action=dict(breakdown_by_action),
            example_matches=example_matches
        )

    @staticmethod
    def apply_transform(
        rule: SuricataRule,
        transform: TransformRule
    ) -> SuricataRule:
        """
        Apply transform actions to a rule (for future implementation)
        Currently not used in dry-run mode

        Args:
            rule: The rule to transform
            transform: The transform to apply

        Returns:
            Modified rule (in future, for now returns original)
        """
        # TODO: Implement actual rule modification
        # This will be used when we move beyond dry-run mode
        return rule
