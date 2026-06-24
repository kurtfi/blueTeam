import pytest
from dataset_ingestor.ingestion import IngestionService


@pytest.mark.asyncio
async def test_download_dataset_path_traversal():
    service = IngestionService()

    # 1. Test URL with path traversal at the end of the path (resolves to parent dir)
    url_ends_with_dotdot = "http://example.com/foo/.."
    with pytest.raises(ValueError, match="Could not extract a valid filename"):
        await service.download_dataset(url_ends_with_dotdot)

    # 2. Test URL with dot at the end of the path
    url_ends_with_dot = "http://example.com/foo/."
    with pytest.raises(ValueError, match="Could not extract a valid filename"):
        await service.download_dataset(url_ends_with_dot)


@pytest.mark.asyncio
async def test_download_dataset_invalid_filename():
    service = IngestionService()

    # Test URL that has no path component or filename
    url_no_filename = "http://example.com/"
    with pytest.raises(ValueError, match="Could not extract a valid filename"):
        await service.download_dataset(url_no_filename)


@pytest.mark.asyncio
async def test_download_dataset_query_safe():
    service = IngestionService()

    # Test URL where query contains path traversal, but it should resolve safely to data/download
    url_with_query = "http://example.com/download?file=../../etc/passwd"
    try:
        # It should pass the path traversal check and fail only on the HTTP download part
        await service.download_dataset(url_with_query)
    except Exception as e:
        # Assert it failed on download, not path traversal
        assert "Path traversal detected" not in str(e)
        assert "Failed to download file" in str(e)
