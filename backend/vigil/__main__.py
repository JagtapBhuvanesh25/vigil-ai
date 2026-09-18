"""Entry point for `python -m vigil`."""

import uvicorn


def main() -> None:
    """Start the Vigil AI backend with uvicorn."""
    uvicorn.run(
        "vigil.api.main:app",
        host="0.0.0.0",
        port=8000,
        reload=True,
    )


if __name__ == "__main__":
    main()
