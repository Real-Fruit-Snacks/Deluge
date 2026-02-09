from __future__ import annotations
from typing import List, Type, Optional
from .base import BaseParser


class ParserFactory:
    _parsers: List[BaseParser] = []

    @classmethod
    def register(cls, parser_class: Type[BaseParser]) -> Type[BaseParser]:
        """Decorator or manual method to register a parser class."""
        cls._parsers.append(parser_class())
        return parser_class

    @classmethod
    def get_parser(cls, content: str) -> Optional[BaseParser]:
        """Detects and returns the appropriate parser for the content."""
        for parser in cls._parsers:
            if parser.can_parse(content):
                return parser
        return None

    @classmethod
    def list_parsers(cls) -> List[str]:
        """Returns a list of registered parser names."""
        return [p.name for p in cls._parsers]


# Import parsers to trigger registration (must be after ParserFactory definition)
from . import nmap_xml as nmap_xml  # noqa: E402
from . import nmap_stdout as nmap_stdout  # noqa: E402
from . import rustscan as rustscan  # noqa: E402
