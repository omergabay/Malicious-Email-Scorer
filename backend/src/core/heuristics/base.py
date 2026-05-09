from abc import ABC, abstractmethod
from typing import Dict, Any, Optional
from core.vt_client import VirusTotalClient

class BaseHeuristic(ABC):
    """Abstract base class for all email heuristics.

    To add a new heuristic, inherit from this class, implement `name` and `evaluate`,
    then register the instance in HeuristicEngine.__init__.
    """

    def __init__(self, vt_client: Optional[VirusTotalClient] = None) -> None:
        """
        Args:
            vt_client: Optional VirusTotal client passed down from the engine.
        """
        self.vt_client = vt_client

    @property
    @abstractmethod
    def name(self) -> str:
        """Unique snake_case identifier for this heuristic (used as the breakdown key)."""
        pass

    @abstractmethod
    async def evaluate(self, email_data: Dict[str, Any]) -> Dict[str, Any]:
        """Runs the heuristic analysis against a single email.

        Args:
            email_data: Parsed email payload dict matching EmailPayload schema.

        Returns:
            Dict with 'score' (int) and 'details' (dict of heuristic-specific findings).
        """
        pass
