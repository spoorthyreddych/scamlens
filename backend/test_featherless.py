import os
from dotenv import load_dotenv
from openai import OpenAI

load_dotenv()

api_key = os.getenv("FEATHERLESS_API_KEY")
model = os.getenv("FEATHERLESS_MODEL")

print("API key found:", bool(api_key))
print("Model:", model)

client = OpenAI(
    base_url="https://api.featherless.ai/v1",
    api_key=api_key
)

response = client.chat.completions.create(
    model=model,
    messages=[
        {
            "role": "system",
            "content": "You are a helpful AI assistant."
        },
        {
            "role": "user",
            "content": "Say hello in one short sentence."
        }
    ],
    max_tokens=50
)

print("\nFeatherless Response:")
print(response.choices[0].message.content)