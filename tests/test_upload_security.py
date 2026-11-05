import pytest
from fastapi import HTTPException

from app.upload_security import validate_upload


def test_valid_text():
    assert validate_upload("notes.txt", b"Hello AegisVault") == "text/plain"


def test_valid_csv():
    assert validate_upload("records.csv", b"name,role\nalice,VIEWER\n") == "text/csv"


def test_valid_json():
    assert validate_upload("config.json", b'{"policy":"PRIVATE"}') == "application/json"


def test_valid_pdf_signature():
    assert validate_upload("report.pdf", b"%PDF-1.7\nsample") == "application/pdf"


@pytest.mark.parametrize(
    "filename",
    [
        "../secret.txt",
        "folder/file.txt",
        r"folder\file.txt",
        "malware.exe",
        "script.py",
        ".hidden.txt",
        "bad\nname.txt",
    ],
)
def test_unsafe_filenames(filename):
    with pytest.raises(HTTPException):
        validate_upload(filename, b"sample")


def test_empty_file():
    with pytest.raises(HTTPException):
        validate_upload("empty.txt", b"")


def test_binary_disguised_as_text():
    with pytest.raises(HTTPException):
        validate_upload("malware.txt", b"\x00\x01\x02")


def test_invalid_json():
    with pytest.raises(HTTPException):
        validate_upload("invalid.json", b"{invalid json}")


def test_invalid_pdf():
    with pytest.raises(HTTPException):
        validate_upload("fake.pdf", b"not a pdf")