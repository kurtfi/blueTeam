"""
Handles secure downloading of attack scenario datasets.
"""

import os
from urllib.parse import urlparse
import httpx
import structlog

logger = structlog.get_logger(__name__)


class DatasetDownloader:
    """
    Client for fetching and storing remote dataset files securely.
    """

    async def download_dataset(self, url: str) -> str:
        """
        Downloads a dataset from a URL to the local data/ directory.
        Returns the absolute local path to the downloaded file.
        """
        parsed_url = urlparse(url)
        filename = os.path.basename(parsed_url.path)
        if not filename or filename in (".", ".."):
            raise ValueError(f"Could not extract a valid filename from URL: {url}")

        dest_dir = "data"
        abs_dest_dir = os.path.abspath(dest_dir)
        local_path = os.path.abspath(os.path.join(abs_dest_dir, filename))

        # Strict containment check to prevent path traversal
        if not local_path.startswith(abs_dest_dir + os.sep) and local_path != abs_dest_dir:
            raise ValueError(f"Path traversal detected in URL: {url}")

        if os.path.exists(local_path) and os.path.getsize(local_path) > 100:
            logger.info("downloader.file_already_downloaded", filename=filename)
            return local_path

        try:
            os.makedirs(dest_dir, exist_ok=True)
            logger.info("downloader.download_started", url=url, dest=local_path)
            async with httpx.AsyncClient(follow_redirects=True, timeout=60.0) as client:
                response = await client.get(url)
                if response.status_code != 200:
                    raise Exception(f"HTTP Status {response.status_code}")
                with open(local_path, "wb") as f:
                    f.write(response.content)
            logger.info("downloader.download_completed", path=local_path, size_bytes=len(response.content))
            return local_path
        except Exception as e:
            raise Exception(f"Failed to download file from {url}: {e}")
