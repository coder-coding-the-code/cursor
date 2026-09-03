from __future__ import annotations

from abc import ABC, abstractmethod

from semantic_firewall.engine.canonicalize import CanonicalResult
from semantic_firewall.schema import Finding, InspectRequest


class Detector(ABC):
    name: str

    @abstractmethod
    def scan(self, req: InspectRequest, canonical: CanonicalResult) -> list[Finding]:
        raise NotImplementedError
