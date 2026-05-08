from abc import ABC, abstractmethod
from typing import Dict, Any, Optional
from core.vt_client import VirusTotalClient

class BaseHeuristic(ABC):
    """
    Abstract Base Class for all email heuristics.
    Scalability Rule: To add a new check, just inherit from this class.
    """

    def __init__(self, vt_client: Optional[VirusTotalClient] = None) -> None:
        self.vt_client = vt_client

    @property
    @abstractmethod
    def name(self) -> str:
        """Unique identifier for the heuristic."""
        pass

    @abstractmethod
    def evaluate(self, email_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Executes the logic. 
        Returns a dict containing 'score_impact' (int) and 'details' (dict).
        """
        pass