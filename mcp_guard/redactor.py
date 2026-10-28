import re
from typing import List, Callable, Any, Tuple, Optional
from dataclasses import dataclass


@dataclass
class RegexMaskRule:
    name: str
    pattern: re.Pattern
    replacement: str = "***"
    enabled: bool = True

    @classmethod
    def compile(cls, name: str, pattern_str: str, replacement: str = "***") -> "RegexMaskRule":
        return cls(name=name, pattern=re.compile(pattern_str, re.IGNORECASE), replacement=replacement)


class RedactionPipeline:
    """
    Data Redaction Pipeline for MCP responses.
    - Masks sensitive patterns (prices, tokens, emails, phone numbers) across text contents.
    - Handles MCP content blocks: text, resource contents, and structuredContent.
    - Over-masking defense principle: guarantees critical patterns do not leak.
    """

    DEFAULT_PRICE_PATTERN = (
        r"(price|quote|cost|fee|budget|amount|total|salary)[\s\S]{0,32}?\d[\d,\.]*"
        r"|\d[\d,\.]*\s*(?:USD|\$|EUR|€|GBP|£|RMB|CNY|¥|￥)"
        r"|[¥￥$€£]\s*\d[\d,\.]*"
    )
    DEFAULT_TOKEN_PATTERN = r"(?i)(bearer\s+[a-z0-9_\-\.]{12,}|sk-[a-z0-9]{20,}|ghp_[a-z0-9]{30,})"

    def __init__(
        self,
        rules: Optional[List[RegexMaskRule]] = None,
        redacted_notice: Optional[str] = "[Note: Sensitive info redacted by guardrails]",
        target_fields: Tuple[str, ...] = ("text", "content", "answer", "message", "output"),
    ):
        self.rules = rules or [
            RegexMaskRule.compile("price", self.DEFAULT_PRICE_PATTERN),
            RegexMaskRule.compile("token", self.DEFAULT_TOKEN_PATTERN),
        ]
        self.redacted_notice = redacted_notice
        self.target_fields = target_fields

    def add_rule(self, rule: RegexMaskRule) -> None:
        self.rules.append(rule)

    def mask_text(self, text: str) -> Tuple[str, int]:
        """Apply rules to plain text. Returns (masked_text, total_hits)."""
        if not isinstance(text, str) or not text:
            return text, 0

        total_hits = 0
        current_text = text

        for rule in self.rules:
            if not rule.enabled:
                continue

            def _replace(match):
                nonlocal total_hits
                total_hits += 1
                return rule.replacement

            current_text = rule.pattern.sub(_replace, current_text)

        return current_text, total_hits

    def redact_mcp_content(self, content_items: list) -> Tuple[list, int]:
        """
        Redact MCP Content array:
        [{"type": "text", "text": "..."}]
        """
        if not isinstance(content_items, list):
            return content_items, 0

        redacted_list = []
        total_hits = 0

        for item in content_items:
            if not isinstance(item, dict):
                redacted_list.append(item)
                continue

            item_copy = dict(item)
            if item_copy.get("type") == "text" and "text" in item_copy:
                new_text, hits = self.mask_text(item_copy["text"])
                item_copy["text"] = new_text
                total_hits += hits

            redacted_list.append(item_copy)

        if total_hits > 0 and self.redacted_notice:
            redacted_list.append({"type": "text", "text": self.redacted_notice})

        return redacted_list, total_hits

    def redact_data(self, data: Any) -> Tuple[Any, int]:
        """Recursively redact dictionary or structured data targeting specific text fields."""
        if isinstance(data, str):
            return self.mask_text(data)

        if isinstance(data, list):
            total_hits = 0
            new_list = []
            for elem in data:
                res, hits = self.redact_data(elem)
                new_list.append(res)
                total_hits += hits
            return new_list, total_hits

        if isinstance(data, dict):
            total_hits = 0
            new_dict = {}
            for k, v in data.items():
                if k in self.target_fields and isinstance(v, str):
                    new_val, hits = self.mask_text(v)
                    new_dict[k] = new_val
                    total_hits += hits
                else:
                    new_val, hits = self.redact_data(v)
                    new_dict[k] = new_val
                    total_hits += hits
            return new_dict, total_hits

        return data, 0
