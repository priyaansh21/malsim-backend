"""
utils/exceptions.py — Custom exception hierarchy for MalSim.

All domain errors inherit from MalSimError so global exception handlers
can catch them cleanly without colliding with FastAPI's own HTTPException.
"""

from fastapi import HTTPException, status


class MalSimError(Exception):
    """Base class for all application-level errors."""
    def __init__(self, message: str, status_code: int = 500):
        super().__init__(message)
        self.message = message
        self.status_code = status_code


class FileNotFoundError(MalSimError):
    def __init__(self, file_id: str):
        super().__init__(f"File record '{file_id}' not found.", 404)


class AnalysisNotReadyError(MalSimError):
    def __init__(self, file_id: str, status: str):
        super().__init__(
            f"Analysis for '{file_id}' is not yet complete (status: {status}).",
            202,
        )


class FileValidationError(MalSimError):
    def __init__(self, detail: str):
        super().__init__(f"File validation failed: {detail}", 422)


class StorageError(MalSimError):
    def __init__(self, detail: str):
        super().__init__(f"Storage error: {detail}", 500)


def raise_http(error: MalSimError) -> None:
    """Convert a MalSimError into a FastAPI HTTPException."""
    raise HTTPException(status_code=error.status_code, detail=error.message)
