"""
Suricata rule parser using suricataparser library
Parses Suricata IDS rule files and extracts rule information
"""
import re
from typing import List, Optional, Dict
from pathlib import Path

from suricataparser import parse_rule as suricata_parse_rule
from app.models.rule import SuricataRule, RuleAction


class SuricataRuleParser:
    """Parser for Suricata IDS rules using suricataparser library"""

    @staticmethod
    def extract_category(msg: str) -> Optional[str]:
        """
        Extract category from rule message
        Categories are typically prefixed like "ET MALWARE", "ET INFO", "ETPRO EXPLOIT"

        Args:
            msg: Rule message string

        Returns:
            Category name (uppercase) or None
        """
        if not msg:
            return None

        # Match patterns like "ET CATEGORY", "ETPRO CATEGORY", or just "CATEGORY"
        import re
        match = re.match(r'^(?:ET(?:PRO)?\s+)?([A-Z][A-Z_\s]+?)(?:\s|:)', msg, re.IGNORECASE)
        if match:
            category = match.group(1).strip().upper()
            # Replace spaces with underscores and return
            return category.replace(' ', '_')
        return None

    @staticmethod
    def parse_metadata(metadata_str: str) -> Dict[str, str]:
        """
        Parse metadata field into key-value pairs

        Args:
            metadata_str: The metadata string

        Returns:
            Dictionary of metadata
        """
        metadata = {}
        if not metadata_str:
            return metadata

        # Split by comma
        pairs = metadata_str.split(',')
        for pair in pairs:
            pair = pair.strip()
            if ' ' in pair:
                key, value = pair.split(' ', 1)
                metadata[key.strip()] = value.strip()
            else:
                metadata[pair] = ""

        return metadata

    @classmethod
    def parse_rule(cls, rule_text: str, source: Optional[str] = None, source_file: Optional[str] = None) -> Optional[SuricataRule]:
        """
        Parse a single Suricata rule using suricataparser library

        Args:
            rule_text: The raw rule text
            source: Rule source identifier (e.g., 'et-open', 'stamus', 'local')
            source_file: Original filename

        Returns:
            SuricataRule object or None if parsing fails
        """
        rule_text = rule_text.strip()

        # Skip comments and empty lines
        if not rule_text or rule_text.startswith('#'):
            return None

        try:
            # Use suricataparser library to parse the rule
            parsed = suricata_parse_rule(rule_text)

            # Extract action
            action = parsed.action.lower()
            if action not in ['alert', 'drop', 'reject', 'pass']:
                action = 'alert'  # default fallback

            # Parse header to extract network information
            # Header format: "protocol src_ip src_port direction dst_ip dst_port"
            # The suricataparser might return header as string or list
            if isinstance(parsed.header, list):
                header_parts = parsed.header
            else:
                header_parts = parsed.header.split()

            if len(header_parts) < 6:
                print(f"Invalid header format: {parsed.header}")
                return None

            protocol = header_parts[0].lower()
            src_ip = header_parts[1]
            src_port = header_parts[2]
            direction = header_parts[3]
            dst_ip = header_parts[4]
            dst_port = header_parts[5]

            # Extract options
            options = {}
            for opt in parsed.options:
                # Each option has a 'name' and 'value' attribute
                opt_name = opt.name

                # Handle value based on type
                if opt.value is None:
                    opt_value = ''
                elif isinstance(opt.value, str):
                    opt_value = opt.value.strip('"')
                else:
                    # For objects like Metadata, convert to string
                    opt_value = str(opt.value)

                # Handle multiple values for same key (like reference, content)
                if opt_name in options:
                    if not isinstance(options[opt_name], list):
                        options[opt_name] = [options[opt_name]]
                    options[opt_name].append(opt_value)
                else:
                    options[opt_name] = opt_value

            # Extract commonly used fields (use built-in attributes when available)
            sid = parsed.sid if hasattr(parsed, 'sid') and parsed.sid else None
            msg = parsed.msg if hasattr(parsed, 'msg') and parsed.msg else options.get('msg', '')
            classtype = parsed.classtype if hasattr(parsed, 'classtype') and parsed.classtype else options.get('classtype', None)
            rev = parsed.rev if hasattr(parsed, 'rev') and parsed.rev else None

            # Priority needs to be extracted from options
            priority = None
            if 'priority' in options:
                try:
                    priority = int(options['priority'])
                except (ValueError, TypeError):
                    priority = None

            # Handle references (can be multiple)
            references = []
            if 'reference' in options:
                if isinstance(options['reference'], list):
                    references = options['reference']
                else:
                    references = [options['reference']]

            # Parse metadata
            metadata = {}
            if 'metadata' in options:
                metadata_value = options['metadata']
                # Handle case where metadata appears multiple times (list)
                if isinstance(metadata_value, list):
                    # Combine all metadata entries
                    for meta_item in metadata_value:
                        metadata.update(cls.parse_metadata(meta_item))
                else:
                    metadata = cls.parse_metadata(metadata_value)

            # Extract tags from message for easier searching
            tags = []
            if msg:
                tags = [word.lower() for word in re.findall(r'\b\w+\b', msg) if len(word) > 3]

            # Extract category from message
            category = cls.extract_category(msg)

            # Extract metadata fields for filtering
            signature_severity = metadata.get('signature_severity')
            attack_target = metadata.get('attack_target')
            deployment = metadata.get('deployment')
            affected_product = metadata.get('affected_product')
            confidence = metadata.get('confidence')
            performance_impact = metadata.get('performance_impact')
            created_at = metadata.get('created_at')
            updated_at = metadata.get('updated_at')

            return SuricataRule(
                id=sid,
                action=RuleAction(action),
                protocol=protocol,
                src_ip=src_ip,
                src_port=src_port,
                direction=direction,
                dst_ip=dst_ip,
                dst_port=dst_port,
                msg=msg,
                classtype=classtype,
                priority=priority,
                reference=references,
                rev=rev,
                metadata=metadata,
                options=options,
                raw_rule=rule_text,
                tags=tags,
                source=source,
                source_file=source_file,
                category=category,
                signature_severity=signature_severity,
                attack_target=attack_target,
                deployment=deployment,
                affected_product=affected_product,
                confidence=confidence,
                performance_impact=performance_impact,
                created_at=created_at,
                updated_at=updated_at
            )

        except Exception as e:
            print(f"Error parsing rule with suricataparser: {e}")
            print(f"Rule: {rule_text}")
            return None

    @classmethod
    def parse_file(cls, file_path: Path, source: Optional[str] = None) -> List[SuricataRule]:
        """
        Parse a Suricata rules file

        Args:
            file_path: Path to the rules file
            source: Rule source identifier (auto-detected from parent directory if not provided)

        Returns:
            List of parsed SuricataRule objects
        """
        rules = []

        # Auto-detect source from parent directory name if not provided
        if source is None:
            # Check if file is in a subdirectory of rules directory
            if file_path.parent.name not in ['rules', '.']:
                source = file_path.parent.name
            else:
                source = 'local'

        source_filename = file_path.name

        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                for line_num, line in enumerate(f, 1):
                    try:
                        rule = cls.parse_rule(line, source=source, source_file=source_filename)
                        if rule:
                            rules.append(rule)
                    except Exception as e:
                        print(f"Error parsing line {line_num} in {file_path}: {e}")
                        print(f"Line content: {line}")
                        continue
        except Exception as e:
            print(f"Error reading file {file_path}: {e}")

        return rules

    @classmethod
    def parse_directory(cls, directory_path: Path, source: Optional[str] = None, exclude_subdirs: bool = False) -> List[SuricataRule]:
        """
        Parse all .rules files in a directory

        Args:
            directory_path: Path to directory containing rules files
            source: Rule source identifier (auto-detected if not provided)
            exclude_subdirs: If True, only parse files in the directory itself, not subdirectories

        Returns:
            List of all parsed rules
        """
        all_rules = []

        if not directory_path.exists():
            print(f"Directory not found: {directory_path}")
            return all_rules

        # Find all .rules files
        if exclude_subdirs:
            # Only get files in the directory itself
            rules_files = list(directory_path.glob("*.rules"))
        else:
            # Get all files recursively (use set to avoid duplicates)
            rules_files = set(directory_path.glob("*.rules")) | set(directory_path.glob("**/*.rules"))
            rules_files = sorted(list(rules_files))

        print(f"Found {len(rules_files)} rule files in {directory_path}")

        for rules_file in rules_files:
            print(f"Parsing {rules_file.name}...")
            # Pass source if provided, otherwise it will be auto-detected
            rules = cls.parse_file(rules_file, source=source)
            all_rules.extend(rules)
            print(f"  Parsed {len(rules)} rules")

        return all_rules
