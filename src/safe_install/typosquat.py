from .core import c
from .data.popular_packages import POPULAR


HOMOGLYPHS = {
    "rn": "m", "m": "rn",
    "l": "1", "1": "l",
    "O": "0", "0": "O",
    "vv": "w", "w": "vv",
    "cl": "d", "d": "cl",
}


class TyposquatDetector:
    def __init__(self, config=None):
        self.config = config or {}
        self.popular = {}
        for eco, pkgs in POPULAR.items():
            self.popular[eco] = {self._normalize(p): p for p in pkgs}

    def check(self, package_name: str, ecosystem: str = "pip") -> list[dict]:
        known = self.popular.get(ecosystem, {})
        norm = self._normalize(package_name)

        if norm in known:
            return []

        warnings = []
        seen = set()

        for norm_pop, original in known.items():
            if original in seen:
                continue

            reason = self._check_homoglyphs(norm, norm_pop)
            if reason:
                warnings.append({"popular": original, "distance": 0, "reason": reason})
                seen.add(original)
                continue

            reason = self._check_separators(norm, norm_pop)
            if reason:
                warnings.append({"popular": original, "distance": 0, "reason": reason})
                seen.add(original)
                continue

            reason = self._check_prefix_suffix(norm, norm_pop)
            if reason:
                warnings.append({"popular": original, "distance": 1, "reason": reason})
                seen.add(original)
                continue

            dist = self._levenshtein(norm, norm_pop)
            if 0 < dist <= 2 and len(norm) > 3:
                warnings.append({"popular": original, "distance": dist, "reason": f"edit distance {dist}"})
                seen.add(original)

        warnings.sort(key=lambda w: w["distance"])
        return warnings

    def _levenshtein(self, s1: str, s2: str) -> int:
        if len(s1) < len(s2):
            return self._levenshtein(s2, s1)
        if not s2:
            return len(s1)

        prev = list(range(len(s2) + 1))
        for i, c1 in enumerate(s1):
            curr = [i + 1]
            for j, c2 in enumerate(s2):
                cost = 0 if c1 == c2 else 1
                curr.append(min(curr[j] + 1, prev[j + 1] + 1, prev[j] + cost))
            prev = curr
        return prev[-1]

    def _check_homoglyphs(self, name: str, popular: str) -> str | None:
        for orig, repl in HOMOGLYPHS.items():
            if orig in name:
                swapped = name.replace(orig, repl, 1)
                if swapped == popular:
                    return f"homoglyph swap: '{orig}' looks like '{repl}' (similar to {popular})"
        return None

    def _check_separators(self, name: str, popular: str) -> str | None:
        stripped_name = name.replace("-", "").replace("_", "").replace(".", "")
        stripped_pop = popular.replace("-", "").replace("_", "").replace(".", "")
        if stripped_name == stripped_pop and name != popular:
            return f"separator swap (matches '{popular}' with different delimiters)"
        return None

    def _check_prefix_suffix(self, name: str, popular: str) -> str | None:
        prefixes = ("python-", "python_", "py-", "py_", "node-", "node_",
                     "js-", "js_", "rust-", "rust_", "go-", "go_")
        suffixes = ("-python", "_python", "-py", "_py", "-js", "_js",
                     "-node", "_node", "-rs", "_rs", "-go", "_go",
                     "2", "3", "js", "py", "-dev", "-beta", "-next",
                     "-core", "-cli", "-lib", "-api", "-sdk", "-utils")

        for prefix in prefixes:
            if name.startswith(prefix) and name[len(prefix):] == popular:
                return f"suspicious prefix '{prefix}' added to '{popular}'"

        for suffix in suffixes:
            if name.endswith(suffix) and name[:-len(suffix)] == popular:
                return f"suspicious suffix '{suffix}' added to '{popular}'"

        return None

    def _normalize(self, name: str) -> str:
        return name.lower().replace("_", "-").replace(".", "-")

    def report(self, warnings: list[dict]) -> bool:
        if not warnings:
            return False

        print(f"\n  {c('[TYPOSQUAT]', 'red')} Potential typosquatting detected:")
        for w in warnings:
            if w["distance"] == 0:
                severity = c("[HIGH]", "red")
            else:
                severity = c("[WARN]", "yellow")
            print(f"    {severity} Similar to '{c(w['popular'], 'bold')}' -- {w['reason']}")

        return True
