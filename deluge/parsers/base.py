from __future__ import annotations
from abc import ABC, abstractmethod
from deluge.core.models import ScanResult


class BaseParser(ABC):
    @property
    @abstractmethod
    def name(self) -> str:
        """Unique identifier for the parser."""
        pass

    @abstractmethod
    def can_parse(self, content: str) -> bool:
        """Heuristic check to see if content matches this parser's format."""
        pass

    @abstractmethod
    def parse(self, content: str) -> ScanResult:
        """Parse content into standardized Pydantic models."""
        pass
