"""
ScamLens — Investigation routes.

PHASE 4 SCOPE:
Each endpoint here performs only basic input validation and returns a
clearly labeled development placeholder InvestigationResult. None of
the following exist yet, and none of these endpoints pretend they do:

  - OCR (image text extraction)
  - Text analyzer (independent text signal analysis)
  - URL analyzer (independent URL/domain analysis)
  - Deterministic risk engine (risk_score / risk_level calculation)
  - Featherless AI interpretation (scam_category / explanation / recommendations)
  - SQLite persistence

Because those stages don't exist, this file never fabricates a
risk_score, risk_level, scam_category, or investigation_steps that
imply real analysis happened. Every response explicitly reports
status="not_implemented" and lists only what actually occurred
(input received + validated).
"""

from fastapi import APIRouter, File, HTTPException, UploadFile, status

from app.models import (
    EmailInvestigateRequest,
    InvestigationResult,
    MessageInvestigateRequest,
    URLInvestigateRequest,
)

router = APIRouter(prefix="/api/investigate", tags=["investigation"])

NOT_IMPLEMENTED_LIMITATIONS = (
    "This is a development placeholder response. Extraction, independent "
    "analysis, the deterministic risk engine, and AI interpretation are "
    "not yet implemented. No real scam investigation has been performed "
    "on this input."
)

# Basic upload constraints for the image endpoint. OCR itself is not
# implemented yet — this only validates that a usable image was sent.
ALLOWED_IMAGE_CONTENT_TYPES = {"image/png", "image/jpeg", "image/jpg", "image/webp"}
MAX_IMAGE_SIZE_BYTES = 10 * 1024 * 1024  # 10 MB


@router.post("/message", response_model=InvestigationResult)
def investigate_message(payload: MessageInvestigateRequest) -> InvestigationResult:
    """
    Accepts a pasted message and returns a placeholder result.
    Pydantic (MessageInvestigateRequest) already enforces that the
    message is present, non-blank, and within length limits.
    """
    return InvestigationResult(
        status="not_implemented",
        input_type="message",
        investigation_steps=[
            "Received message input.",
            "Validated message is present and non-blank.",
            "Extraction, analysis, and risk scoring not yet implemented.",
        ],
        limitations=NOT_IMPLEMENTED_LIMITATIONS,
    )


@router.post("/url", response_model=InvestigationResult)
def investigate_url(payload: URLInvestigateRequest) -> InvestigationResult:
    """
    Accepts a URL and returns a placeholder result.
    IMPORTANT: this endpoint never visits or fetches the submitted URL.
    """
    return InvestigationResult(
        status="not_implemented",
        input_type="url",
        investigation_steps=[
            "Received URL input.",
            "Validated URL is present and non-blank.",
            "URL was NOT visited or fetched (never auto-visit suspicious URLs).",
            "Extraction, analysis, and risk scoring not yet implemented.",
        ],
        limitations=NOT_IMPLEMENTED_LIMITATIONS,
    )


@router.post("/email", response_model=InvestigationResult)
def investigate_email(payload: EmailInvestigateRequest) -> InvestigationResult:
    """
    Accepts pasted email content (headers and/or body) and returns a
    placeholder result.
    """
    return InvestigationResult(
        status="not_implemented",
        input_type="email",
        investigation_steps=[
            "Received email content input.",
            "Validated email content is present and non-blank.",
            "Extraction, analysis, and risk scoring not yet implemented.",
        ],
        limitations=NOT_IMPLEMENTED_LIMITATIONS,
    )


@router.post("/image", response_model=InvestigationResult)
async def investigate_image(file: UploadFile = File(...)) -> InvestigationResult:
    """
    Accepts an uploaded screenshot and returns a placeholder result.

    Validates content-type and size only. The file is read into memory
    solely to check its size, then discarded — it is NOT persisted to
    disk or database, consistent with the "no permanent screenshot
    storage" requirement. OCR/text extraction is not implemented yet.
    """
    if file.content_type not in ALLOWED_IMAGE_CONTENT_TYPES:
        raise HTTPException(
            status_code=status.HTTP_415_UNSUPPORTED_MEDIA_TYPE,
            detail=(
                f"Unsupported image type '{file.content_type}'. "
                f"Allowed types: {', '.join(sorted(ALLOWED_IMAGE_CONTENT_TYPES))}."
            ),
        )

    contents = await file.read()

    if len(contents) == 0:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Uploaded image file is empty.",
        )

    if len(contents) > MAX_IMAGE_SIZE_BYTES:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail=f"Image exceeds the {MAX_IMAGE_SIZE_BYTES // (1024 * 1024)}MB size limit.",
        )

    # Explicitly not stored: `contents` goes out of scope here and is
    # never written to disk or a database.

    return InvestigationResult(
        status="not_implemented",
        input_type="image",
        investigation_steps=[
            "Received image upload.",
            "Validated image content-type and size.",
            "Image was not persisted to disk or database.",
            "OCR extraction, analysis, and risk scoring not yet implemented.",
        ],
        limitations=NOT_IMPLEMENTED_LIMITATIONS,
    )