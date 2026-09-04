from app.services.ai_investigator import investigate_with_ai

original_text = """
Urgent! Your SBI bank account will be suspended today.
Click the link immediately and enter your login password and OTP.
"""

evidence = [
    {
        "id": "REQUEST_FOR_OTP",
        "description": "The message asks the user to provide an OTP.",
        "severity": "CRITICAL",
        "weight": 9
    },
    {
        "id": "URGENCY_LANGUAGE",
        "description": "The message creates immediate pressure.",
        "severity": "MEDIUM",
        "weight": 6
    },
    {
        "id": "BRAND_IMPERSONATION_CLAIM",
        "description": "The message claims association with a bank.",
        "severity": "HIGH",
        "weight": 8
    }
]

risk_result = {
    "risk_score": 78,
    "risk_level": "CRITICAL",
    "detected_signals": [
        "REQUEST_FOR_OTP",
        "URGENCY_LANGUAGE",
        "BRAND_IMPERSONATION_CLAIM"
    ]
}

result = investigate_with_ai(
    original_text=original_text,
    evidence=evidence,
    risk_result=risk_result
)

print("\nAI INVESTIGATION RESULT:\n")
print(result)