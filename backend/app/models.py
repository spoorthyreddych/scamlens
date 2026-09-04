"""
ScamLens — Pydantic models.

Defines:
- Request models for each investigation input type (message, url, email).
  Image input uses FastAPI's UploadFile directly in the route instead of
  a Pydantic model, since it's a multipart file upload.
- The shared InvestigationResult response contract that every
  investigation endpoint returns. This mirrors the final result shape
  required by the project spec:
    risk_score, risk_level, scam_category, detected_signals, evidence,
    suspicious_text, extracted_urls, recommendations,
    investigation_steps, confidence, limitations

PHASE 4 SCOPE:
This file only defines data shapes and basic field-level validation.
No risk scoring, OCR, URL analysis, or AI interpretation logic lives
here — those arrive in later phases.
"""

from typing import List, Optional
from pydantic import BaseModel, Field, field_validator


# ---------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------

class MessageInvestigateRequest(BaseModel):
    """Request body for POST /api/investigate/message"""

    message: str = Field(
        ...,
        min_length=3,
        max_length=20000,
        description="The raw pasted message text to investigate.",
    )

    @field_validator("message")
    @classmethod
    def message_must_not_be_blank(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("message must not be blank or whitespace-only")
        return value


class URLInvestigateRequest(BaseModel):
    """Request body for POST /api/investigate/url"""

    url: str = Field(
        ...,
        min_length=3,
        max_length=2048,
        description="The URL to investigate. Not fetched or visited by this endpoint.",
    )

    @field_validator("url")
    @classmethod
    def url_must_not_be_blank(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("url must not be blank or whitespace-only")
        return value


class EmailInvestigateRequest(BaseModel):
    """Request body for POST /api/investigate/email"""

    email_content: str = Field(
        ...,
        min_length=3,
        max_length=50000,
        description="The full pasted email content (headers and/or body) to investigate.",
    )

    @field_validator("email_content")
    @classmethod
    def email_content_must_not_be_blank(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("email_content must not be blank or whitespace-only")
        return value


# ---------------------------------------------------------------------
# Shared response contract
# ---------------------------------------------------------------------

class InvestigationResult(BaseModel):
    """
    The final result contract returned by every investigation endpoint.

    In this phase, endpoints populate this with clearly labeled
    placeholder values (status="not_implemented") because the
    extraction, analysis, risk engine, and AI interpretation stages
    do not exist yet. No field here is ever filled with a fabricated
    real-looking scam verdict.
    """

    status: str = Field(
        ...,
        description="Pipeline status for this response, e.g. 'not_implemented' or 'ok'.",
    )
    input_type: str = Field(
        ..., description="Which input type was investigated: message, url, image, or email."
    )
    risk_score: Optional[int] = Field(
        default=None, description="0-100 deterministic risk score. Null until the risk engine exists."
    )
    risk_level: Optional[str] = Field(
        default=None, description="low | medium | high | critical. Null until the risk engine exists."
    )
    scam_category: Optional[str] = Field(
        default=None, description="AI-interpreted scam category. Null until AI interpretation exists."
    )
    detected_signals: List[str] = Field(
        default_factory=list, description="Signal identifiers raised by independent analysis modules."
    )
    evidence: List[str] = Field(
        default_factory=list, description="Human-readable evidence statements backing the risk score."
    )
    suspicious_text: Optional[str] = Field(
        default=None, description="Specific suspicious excerpt(s) identified in the input."
    )
    extracted_urls: List[str] = Field(
        default_factory=list, description="URLs extracted from the input during the extraction stage."
    )
    recommendations: List[str] = Field(
        default_factory=list, description="Recommended actions for the user."
    )
    investigation_steps: List[str] = Field(
        default_factory=list, description="Ordered, factual log of pipeline steps actually performed."
    )
    confidence: Optional[str] = Field(
        default=None, description="Confidence descriptor for the result. Null until scoring exists."
    )
    limitations: str = Field(
        ..., description="Plain-language statement of what this response does and does not represent."
    )