"""
Extensible pattern database for safe-install.

Loads exfiltration patterns from YAML files instead of hardcoded lists.
Uses a minimal YAML parser (no PyYAML dependency).
"""

import os
import re
from pathlib import Path


class PatternDatabase:
    def __init__(self, config=None):
        self.patterns = {}
        self.high_risk_files = {}
        self.file_extensions = {}
        self._load_builtin()
        self._load_custom(config or {})

    def _load_builtin(self):
        patterns_dir = Path(__file__).parent / 'data' / 'patterns'
        if not patterns_dir.exists():
            return
        for path in sorted(patterns_dir.glob('*.yml')):
            if path.name.endswith('.example'):
                continue
            self._load_file(path)

    def _load_custom(self, config):
        # User patterns in ~/.config/safe-install/patterns/
        user_dir = Path.home() / '.config' / 'safe-install' / 'patterns'
        custom_dirs = [user_dir]
        custom_dirs.extend(
            Path(d) for d in config.get('patterns', {}).get('custom_dirs', [])
        )
        for d in custom_dirs:
            if not d.is_dir():
                continue
            for path in sorted(d.glob('*.yml')):
                if path.name.endswith('.example'):
                    continue
                self._load_file(path)

    def _load_file(self, path):
        try:
            text = path.read_text(encoding='utf-8')
        except (OSError, UnicodeDecodeError):
            return
        data = _parse_yaml(text)
        if not data or data.get('version') != 1:
            return
        lang = data.get('language')
        if not lang:
            return

        if lang not in self.patterns:
            self.patterns[lang] = []
            self.high_risk_files[lang] = []
            self.file_extensions[lang] = set()

        for ext in data.get('file_extensions', []):
            self.file_extensions[lang].add(ext)

        for f in data.get('high_risk_files', []):
            if f not in self.high_risk_files[lang]:
                self.high_risk_files[lang].append(f)

        for p in data.get('patterns', []):
            if 'pattern' not in p or 'description' not in p:
                continue
            self.patterns[lang].append(p)

    def get_patterns(self, language):
        """Return patterns as list of (regex_string, description) tuples.

        This matches the format used by EXFIL_PATTERNS_* in core.py.
        """
        result = []
        for p in self.patterns.get(language, []):
            result.append((p['pattern'], p['description']))
        return result

    def get_patterns_full(self, language):
        """Return full pattern dicts with all metadata."""
        return list(self.patterns.get(language, []))

    def get_file_extensions(self, language):
        return self.file_extensions.get(language, set())

    def get_high_risk_files(self, language):
        return list(self.high_risk_files.get(language, []))

    def get_patterns_by_lang(self):
        """Return dict matching PATTERNS_BY_LANG format in core.py.

        Returns {language: ([(pattern, desc), ...], {extensions})}
        """
        result = {}
        for lang in self.patterns:
            result[lang] = (self.get_patterns(lang), self.get_file_extensions(lang))
        return result

    def get_all_high_risk_files(self):
        """Return dict matching HIGH_RISK_FILES format in core.py."""
        return dict(self.high_risk_files)

    def add_pattern(self, language, pattern_dict):
        if language not in self.patterns:
            self.patterns[language] = []
            self.high_risk_files[language] = []
            self.file_extensions[language] = set()
        self.patterns[language].append(pattern_dict)

    def languages(self):
        return list(self.patterns.keys())


# ---------------------------------------------------------------------------
# Minimal YAML parser -- handles only the subset used by pattern files:
#   - top-level scalar keys (version, language)
#   - top-level lists of strings (file_extensions, high_risk_files)
#   - top-level list of mappings (patterns), where each mapping has
#     scalar values or lists of strings
# No anchors, flow style, multi-line strings, or nested mappings.
# ---------------------------------------------------------------------------

def _parse_yaml(text):
    lines = text.splitlines()
    result = {}
    i = 0
    while i < len(lines):
        line = lines[i]
        stripped = line.strip()

        # Skip blank / comment
        if not stripped or stripped.startswith('#'):
            i += 1
            continue

        indent = len(line) - len(line.lstrip())

        # Top-level key (indent == 0)
        if indent == 0 and ':' in stripped:
            key, _, val = stripped.partition(':')
            key = key.strip()
            val = val.strip()

            if val and not val.startswith('#'):
                # Inline scalar value
                result[key] = _parse_scalar(val)
                i += 1
            else:
                # Block value -- peek at next non-empty line to decide type
                i += 1
                child_lines = _collect_block(lines, i)
                if not child_lines:
                    result[key] = None
                    continue
                first_content = child_lines[0].strip()
                if first_content.startswith('- ') and ':' not in first_content.split("'")[0].split('"')[0]:
                    # Simple list of scalars
                    result[key] = _parse_scalar_list(child_lines)
                elif first_content.startswith('- '):
                    # List of mappings
                    result[key] = _parse_mapping_list(child_lines)
                else:
                    result[key] = _parse_scalar(first_content)
                i += len(child_lines)
        else:
            i += 1

    return result


def _collect_block(lines, start):
    """Collect all lines belonging to a block (indented under a key)."""
    if start >= len(lines):
        return []
    # Find indent of first content line
    block_indent = None
    collected = []
    i = start
    while i < len(lines):
        line = lines[i]
        stripped = line.strip()
        if not stripped or stripped.startswith('#'):
            collected.append(line)
            i += 1
            continue
        indent = len(line) - len(line.lstrip())
        if block_indent is None:
            if indent == 0:
                break
            block_indent = indent
        if indent < block_indent:
            break
        collected.append(line)
        i += 1
    # Trim trailing blanks
    while collected and not collected[-1].strip():
        collected.pop()
    return collected


def _parse_scalar_list(lines):
    result = []
    for line in lines:
        stripped = line.strip()
        if not stripped or stripped.startswith('#'):
            continue
        if stripped.startswith('- '):
            val = stripped[2:].strip()
            result.append(_parse_scalar(val))
    return result


def _parse_mapping_list(lines):
    """Parse a YAML list of mappings (each item starts with '- key: val')."""
    items = []
    current = None
    i = 0
    while i < len(lines):
        line = lines[i]
        stripped = line.strip()
        if not stripped or stripped.startswith('#'):
            i += 1
            continue

        if stripped.startswith('- ') and ':' in stripped:
            # New list item
            if current is not None:
                items.append(current)
            current = {}
            # Parse the first key on the '- ' line
            first_pair = stripped[2:].strip()
            k, _, v = first_pair.partition(':')
            k = k.strip()
            v = v.strip()
            if v and not v.startswith('#'):
                current[k] = _parse_scalar(v)
            else:
                # Sub-list under this key
                i += 1
                sub_lines = _collect_sub_list(lines, i)
                current[k] = _parse_scalar_list(sub_lines)
                i += len(sub_lines)
                continue
        elif current is not None and ':' in stripped and not stripped.startswith('- '):
            # Continuation key in current mapping
            k, _, v = stripped.partition(':')
            k = k.strip()
            v = v.strip()
            if v and not v.startswith('#'):
                current[k] = _parse_scalar(v)
            else:
                # Sub-list
                i += 1
                sub_lines = _collect_sub_list(lines, i)
                current[k] = _parse_scalar_list(sub_lines)
                i += len(sub_lines)
                continue
        i += 1

    if current is not None:
        items.append(current)
    return items


def _collect_sub_list(lines, start):
    """Collect lines for a sub-list (indented list items under a mapping key)."""
    collected = []
    if start >= len(lines):
        return collected
    # Determine expected indent
    base_indent = None
    i = start
    while i < len(lines):
        line = lines[i]
        stripped = line.strip()
        if not stripped or stripped.startswith('#'):
            collected.append(line)
            i += 1
            continue
        indent = len(line) - len(line.lstrip())
        if base_indent is None:
            if not stripped.startswith('- '):
                break
            base_indent = indent
        if indent < base_indent:
            break
        if not stripped.startswith('- '):
            break
        collected.append(line)
        i += 1
    return collected


def _parse_scalar(val):
    if not val:
        return None
    # Strip inline comments (not inside quotes)
    if val.startswith("'") and val.endswith("'"):
        return val[1:-1]
    if val.startswith('"') and val.endswith('"'):
        return val[1:-1]
    # Inline list: [a, b, c]
    if val.startswith('[') and val.endswith(']'):
        inner = val[1:-1].strip()
        if not inner:
            return []
        return [_parse_scalar(x.strip()) for x in _split_list(inner)]
    if val.lower() == 'true':
        return True
    if val.lower() == 'false':
        return False
    if val.lower() == 'null' or val == '~':
        return None
    try:
        return int(val)
    except ValueError:
        pass
    try:
        return float(val)
    except ValueError:
        pass
    # Strip trailing inline comment
    if ' #' in val:
        val = val[:val.index(' #')].rstrip()
    return val


def _split_list(text):
    """Split comma-separated values, respecting quotes."""
    parts = []
    current = []
    in_quote = None
    for ch in text:
        if ch in ('"', "'") and in_quote is None:
            in_quote = ch
            current.append(ch)
        elif ch == in_quote:
            in_quote = None
            current.append(ch)
        elif ch == ',' and in_quote is None:
            parts.append(''.join(current))
            current = []
        else:
            current.append(ch)
    if current:
        parts.append(''.join(current))
    return parts
