import csv
import io
import json
import re
from pathlib import Path

from fastapi import HTTPException


ALLOWED_EXTENSIONS = {".txt", ".csv", ".json", ".pdf"}


def validate_upload(filename: str, data: bytes) -> str:
    if not filename or not isinstance(filename, str):
        raise HTTPException(400, "Invalid filename")

    if (
        len(filename) > 200
        or filename in {".", ".."}
        or "/" in filename
        or "\\" in filename
        or any(ord(char) < 32 or ord(char) == 127 for char in filename)
        or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._ -]*", filename)
    ):
        raise HTTPException(400, "Unsafe filename")

    extension = Path(filename).suffix.lower()

    if extension not in ALLOWED_EXTENSIONS:
        raise HTTPException(400, "Unsupported file format")

    if not data:
        raise HTTPException(400, "Empty files are not allowed")

    if extension == ".pdf":
        if not data.startswith(b"%PDF-"):
            raise HTTPException(400, "Invalid PDF signature")

        return "application/pdf"

    if b"\x00" in data:
        raise HTTPException(400, "Binary content is not allowed")

    try:
        content = data.decode("utf-8-sig")
    except UnicodeDecodeError:
        raise HTTPException(400, "Invalid UTF-8 content")

    if extension == ".json":
        try:
            json.loads(content)
        except json.JSONDecodeError:
            raise HTTPException(400, "Invalid JSON content")

        return "application/json"

    if extension == ".csv":
        try:
            rows = list(csv.reader(io.StringIO(content), strict=True))
        except csv.Error:
            raise HTTPException(400, "Invalid CSV content")

        if not rows or not any(row for row in rows):
            raise HTTPException(400, "CSV contains no records")

        return "text/csv"

    return "text/plain"