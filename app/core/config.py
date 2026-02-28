import os
from pydantic import BaseModel
from dotenv import load_dotenv

load_dotenv()

class Settings(BaseModel):
    # Supabase
    SUPABASE_URL: str = os.getenv("SUPABASE_URL", "")
    SUPABASE_KEY: str = os.getenv("SUPABASE_KEY", "")
    SUPABASE_POSTGREST_TIMEOUT_S: float = float(os.getenv("SUPABASE_POSTGREST_TIMEOUT_S", "120"))
    SUPABASE_STORAGE_TIMEOUT_S: int = int(os.getenv("SUPABASE_STORAGE_TIMEOUT_S", "60"))
    SUPABASE_FUNCTION_TIMEOUT_S: int = int(os.getenv("SUPABASE_FUNCTION_TIMEOUT_S", "30"))

    # AI / LLM
    PINECONE_API_KEY: str = os.getenv("Pinecone_Api_Key", "")
    PINECONE_KB_INDEX_NAME: str = os.getenv("PINECONE_KB_INDEX_NAME", "infraai")
    OPENROUTER_API_KEY: str = os.getenv("openrouter", "")
    OPENROUTER_MODEL: str = os.getenv("OPENROUTER_MODEL", "openai/gpt-5.2")
    GEMINI_API_KEY: str = os.getenv("Gemini_Api_Key", "")

    # AWS
    AWS_ACCESS_KEY_ID: str = os.getenv("access_key", "")
    AWS_SECRET_ACCESS_KEY: str = os.getenv("secrete_access", "")
    AWS_REGION: str = "ap-south-1"

    # Worker Settings
    WORKER_COUNT: int = int(os.getenv("WORKER_COUNT", "1"))
    CHAT_WORKER_COUNT: int = int(os.getenv("CHAT_WORKER_COUNT", "1"))
    SQS_QUEUE_NAME: str = os.getenv("SQS_QUEUE_NAME", "Chatqueue")
    SQS_VISIBILITY_TIMEOUT: int = int(os.getenv("SQS_VISIBILITY_TIMEOUT", "900"))

    # Integrations
    CLERK_PUBLIC_KEY: str = """-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAxFwlegGWXS3gVaKyX/Ck
pwRENl+blwEkCtqfnjjHSV5TScDHwum4uQFcAW6VgyESbeA6tDI5VF72ZRcJ58yE
m1uJLLDQNDrG0BAa2jYAgcRZeQcJklXp+E5C7kv+wQh/19/24/ze09l9N2jIvhKk
OCICAoJ/AtnsvsYRhi74z+HVzEZZmVtofeHxZBlBU3XX0v0u9gYnqsm550Ndk/K3
fHY1QOV8mAYKMrqhrpbC4dsGDn9WGta0h003zrHrMauA9mvnGBgIdHMXZiYWjC7M
mkew+iKms63o1+K6p16OGX3DR+WYnjCWOf6SxsTWOxTCBzxow+m693Afg3stBLR3
ZQIDAQAB
-----END PUBLIC KEY-----"""
    CLERK_SECRET_KEY: str = os.getenv("CLERK_SECRET_KEY", "")

    # Infisical
    INFISICAL_CLIENT_ID: str = os.getenv('clientId', '')
    INFISICAL_CLIENT_SECRET: str = os.getenv('clientSecret', '')

settings = Settings()
