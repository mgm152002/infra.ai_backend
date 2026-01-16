import os
from typing import Optional, List
from langchain_openai import ChatOpenAI
from langchain_core.messages import SystemMessage, HumanMessage

# OpenRouter configuration
OPENROUTER_API_KEY = os.getenv("openrouter")
OPENROUTER_BASE_URL = "https://openrouter.ai/api/v1"
DEFAULT_MODEL_NAME = os.getenv("OPENROUTER_MODEL", "openai/gpt-5.2")

def get_llm(model_name: Optional[str] = None, **kwargs) -> ChatOpenAI:
    """Return a ChatOpenAI instance configured to talk to OpenRouter."""
    if not OPENROUTER_API_KEY:
        # Fallback to checking os.getenv directly if not initialized at import
        api_key = os.getenv("openrouter")
        if not api_key:
            raise ValueError("OpenRouter API key not set. Please define the 'openrouter' environment variable.")
    else:
        api_key = OPENROUTER_API_KEY
        
    return ChatOpenAI(
        model=model_name or DEFAULT_MODEL_NAME,
        api_key=api_key,
        base_url=OPENROUTER_BASE_URL,
        **kwargs,
    )

def call_llm(
    user_content: str,
    *,
    system_content: Optional[str] = None,
    model_name: Optional[str] = None,
) -> str:
    """Convenience helper that sends a single-turn prompt to the LLM and returns the text content."""
    messages = []
    if system_content:
        messages.append(SystemMessage(content=system_content))
    messages.append(HumanMessage(content=user_content))
    llm = get_llm(model_name=model_name)
    response = llm.invoke(messages)
    return response.content
