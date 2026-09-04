from app.services.investigation_service import investigate

message = """
URGENT! Your SBI bank account will be suspended today.

Click this link immediately:
http://sbi-secure-login-verify.xyz

Enter your username, password and OTP to verify your account.
"""

result = investigate(message)

print("\n========== SCAMLENS INVESTIGATION ==========\n")

print("Risk Score:", result.get("risk_score"))
print("Risk Level:", result.get("risk_level"))

print("\nURLs Detected:")
print(result.get("urls_detected"))

print("\nSignals:")
for signal in result.get("evidence", []):
    print("-", signal.get("id"))

print("\nAI Investigation:")
print(result.get("ai_investigation"))