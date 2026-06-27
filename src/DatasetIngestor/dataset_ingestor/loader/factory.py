"""
Factory for resolving and instantiating appropriate DatasetLoaders.
"""

from dataset_ingestor.loader.base import DatasetLoader
from dataset_ingestor.loader.custom import CustomLoader
from dataset_ingestor.loader.mordor import MordorLoader


class DatasetLoaderFactory:
    """
    Dynamically creates DatasetLoader instances based on file extension or source type.
    """

    @staticmethod
    def get_loader(source_type: str) -> DatasetLoader:
        """
        Get loader by explicit source type string.
        """
        if source_type == "mordor":
            return MordorLoader()
        elif source_type == "custom":
            return CustomLoader()
        else:
            raise ValueError(f"Unknown source type: {source_type}")

    @staticmethod
    def get_loader_by_path(path: str) -> DatasetLoader:
        """
        Deduce loader based on path extension (ZIP/TAR.GZ -> Mordor, otherwise Custom).
        """
        if path.endswith((".zip", ".tar.gz")):
            return MordorLoader()
        return CustomLoader()
