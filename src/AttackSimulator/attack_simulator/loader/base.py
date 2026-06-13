"""
Abstract base class for dataset loaders.
"""

from abc import ABC, abstractmethod
from typing import Any, Generator


class DatasetLoader(ABC):
    """
    Interface for loading security telemetry data.
    """

    @abstractmethod
    def load(self, source_path: str) -> Generator[dict[str, Any], None, None]:
        """
        Streams events from source path one by one to keep memory footprint low.
        """
        pass
