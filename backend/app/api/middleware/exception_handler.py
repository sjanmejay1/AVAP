import logging
from typing import Any

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

from app.api.responses.api_response import ErrorDetails, ErrorResponse
from app.core.exceptions import AppException

logger = logging.getLogger(__name__)


def _redacted_errors(exc: RequestValidationError) -> list[dict[str, Any]]:
    """Validation errors without the submitted values."""
    return [
        {key: value for key, value in error.items() if key not in ("input", "ctx")}
        for error in exc.errors()
    ]


def setup_exception_handlers(app: FastAPI) -> None:
    """Register custom exception handlers with the FastAPI application."""

    @app.exception_handler(AppException)
    async def app_exception_handler(
        request: Request, exc: AppException
    ) -> JSONResponse:
        """Handle custom application exceptions."""
        logger.info(
            f"Application Exception: {exc.error_code} - {exc.message}",
            extra={
                "context": {
                    "url": str(request.url),
                    "method": request.method,
                    "details": exc.details,
                }
            },
        )

        error_resp = ErrorResponse(
            error=ErrorDetails(
                code=exc.error_code,
                message=exc.message,
                details=exc.details,
            )
        )
        return JSONResponse(
            status_code=exc.status_code,
            content=error_resp.model_dump(),
        )

    @app.exception_handler(RequestValidationError)
    async def validation_exception_handler(
        request: Request, exc: RequestValidationError
    ) -> JSONResponse:
        """Handle FastAPI validation exceptions (e.g., bad Pydantic payloads).

        The offending `input` value is dropped from both the log and the
        response: it can be a password or an API key. `ctx` is dropped too
        because it may hold exception objects that are not JSON-safe.
        """
        errors = _redacted_errors(exc)
        logger.info(
            "Request Validation Error",
            extra={
                "context": {
                    "url": str(request.url),
                    "method": request.method,
                    "errors": errors,
                }
            },
        )

        error_resp = ErrorResponse(
            error=ErrorDetails(
                code="VALIDATION_ERROR",
                message="Request validation failed",
                details={"errors": errors},
            )
        )
        return JSONResponse(
            status_code=422,
            content=error_resp.model_dump(),
        )

    @app.exception_handler(StarletteHTTPException)
    async def http_exception_handler(
        request: Request, exc: StarletteHTTPException
    ) -> JSONResponse:
        """Handle generic HTTP exceptions (e.g., 404 Not Found from router)."""
        error_resp = ErrorResponse(
            error=ErrorDetails(
                code="HTTP_ERROR",
                message=str(exc.detail),
            )
        )
        return JSONResponse(
            status_code=exc.status_code,
            content=error_resp.model_dump(),
        )

    @app.exception_handler(Exception)
    async def unhandled_exception_handler(
        request: Request, exc: Exception
    ) -> JSONResponse:
        """Handle unexpected exceptions.

        Logs the full exception internally, but returns a sanitized 500 response
        to the client to prevent leaking implementation details.
        """
        logger.exception(
            "Unhandled Exception",
            extra={"context": {"url": str(request.url), "method": request.method}},
        )

        error_resp = ErrorResponse(
            error=ErrorDetails(
                code="INTERNAL_SERVER_ERROR",
                message="An unexpected internal error occurred.",
            )
        )
        return JSONResponse(
            status_code=500,
            content=error_resp.model_dump(),
        )
