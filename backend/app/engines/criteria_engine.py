"""
Criteria matching engine for evaluating rules against transform criteria
"""
import re
from typing import Any, Optional
from app.models.rule import SuricataRule
from app.models.transform import TransformCriteria, CriteriaOperator


class CriteriaEvaluator:
    """Evaluates rules against transform criteria"""

    @staticmethod
    def get_field_value(rule: SuricataRule, field: str) -> Optional[Any]:
        """
        Extract field value from rule, supporting nested metadata access

        Args:
            rule: The Suricata rule to extract from
            field: Field name, supports dot notation (e.g., 'metadata.signature_severity')

        Returns:
            Field value or None if not found
        """
        # Handle nested field access (e.g., metadata.key)
        if '.' in field:
            parts = field.split('.', 1)
            if parts[0] == 'metadata' and rule.metadata:
                return rule.metadata.get(parts[1])
            return None

        # Direct field access
        return getattr(rule, field, None)

    @staticmethod
    def evaluate_criteria(rule: SuricataRule, criteria: TransformCriteria) -> bool:
        """
        Check if a rule matches the given criteria

        Args:
            rule: The Suricata rule to evaluate
            criteria: The criteria to match against

        Returns:
            True if rule matches criteria, False otherwise
        """
        field_value = CriteriaEvaluator.get_field_value(rule, criteria.field)

        # Handle EXISTS and NOT_EXISTS operators
        if criteria.operator == CriteriaOperator.EXISTS:
            return field_value is not None

        if criteria.operator == CriteriaOperator.NOT_EXISTS:
            return field_value is None

        # If field doesn't exist and we're not checking for existence, no match
        if field_value is None:
            return False

        # Convert to string for text-based operations
        field_str = str(field_value)

        # Apply case sensitivity
        if not criteria.case_sensitive and isinstance(field_value, str):
            field_str = field_str.lower()
            if isinstance(criteria.value, str):
                compare_value = criteria.value.lower()
            elif isinstance(criteria.value, list):
                compare_value = [str(v).lower() for v in criteria.value]
            else:
                compare_value = criteria.value
        else:
            compare_value = criteria.value

        # Evaluate based on operator
        if criteria.operator == CriteriaOperator.EXACT_MATCH:
            return field_str == str(compare_value)

        elif criteria.operator == CriteriaOperator.CONTAINS:
            if not isinstance(compare_value, str):
                return False
            return compare_value in field_str

        elif criteria.operator == CriteriaOperator.REGEX:
            if not isinstance(compare_value, str):
                return False
            try:
                flags = 0 if criteria.case_sensitive else re.IGNORECASE
                return bool(re.search(compare_value, field_str, flags))
            except re.error:
                # Invalid regex, return False
                return False

        elif criteria.operator == CriteriaOperator.IN_LIST:
            if not isinstance(compare_value, list):
                return False
            return field_str in [str(v) for v in compare_value]

        elif criteria.operator == CriteriaOperator.NOT_IN_LIST:
            if not isinstance(compare_value, list):
                return False
            return field_str not in [str(v) for v in compare_value]

        elif criteria.operator == CriteriaOperator.GREATER_THAN:
            try:
                return float(field_value) > float(compare_value)
            except (ValueError, TypeError):
                return False

        elif criteria.operator == CriteriaOperator.LESS_THAN:
            try:
                return float(field_value) < float(compare_value)
            except (ValueError, TypeError):
                return False

        return False
