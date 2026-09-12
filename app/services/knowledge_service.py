"""Knowledge-base storage and query operations."""

import os
import uuid
from datetime import datetime
from typing import Any, Dict, List, Optional

from fastapi import HTTPException, UploadFile, status
from openai import OpenAI
from pinecone import Pinecone


pc = Pinecone(api_key=os.getenv("Pinecone_Api_Key"))
OPENROUTER_API_KEY = os.getenv("openrouter")
OPENROUTER_BASE_URL = "https://openrouter.ai/api/v1"

# --- Knowledge base (Pinecone vector index) helpers ---

PINECONE_KB_INDEX_NAME = os.getenv("PINECONE_KB_INDEX_NAME", "infraai")
KB_TOP_K_DEFAULT = int(os.getenv("KB_TOP_K_DEFAULT", "5"))
KB_SCORE_THRESHOLD_DEFAULT = float(os.getenv("KB_SCORE_THRESHOLD_DEFAULT", "0.7"))
# Path to the global architecture knowledge-base Markdown file. This document
# is treated as base context for all KB queries when present.
ARCHITECTURE_KB_FILE_PATH = os.getenv("ARCHITECTURE_KB_FILE_PATH", "architecture_kb.md")
# Deterministic doc_id for the architecture KB when stored in Pinecone so we
# can safely replace previous versions on re-upload.
ARCHITECTURE_KB_DOC_ID = os.getenv("ARCHITECTURE_KB_DOC_ID", "architecture_kb")

# OpenRouter embedding client (OpenAI-compatible embeddings via OpenRouter)
OPENROUTER_SITE_URL = os.getenv("OPENROUTER_SITE_URL")
OPENROUTER_SITE_NAME = os.getenv("OPENROUTER_SITE_NAME")

embedding_client: Optional[OpenAI] = None
if OPENROUTER_API_KEY:
    embedding_client = OpenAI(
        base_url=OPENROUTER_BASE_URL,
        api_key=OPENROUTER_API_KEY,
    )


def _get_architecture_kb_text() -> str:
    """Return the contents of the global architecture KB Markdown file, if any.

    If the file does not exist or cannot be read, an empty string is returned.
    """
    path = ARCHITECTURE_KB_FILE_PATH
    if not path:
        return ""
    try:
        if not os.path.exists(path):
            return ""
        with open(path, "r", encoding="utf-8") as f:
            return f.read()
    except Exception:
        # Treat any filesystem or encoding errors as "no architecture KB" so that
        # callers remain robust.
        return ""


def _get_kb_index():
    """Return Pinecone index handle for the knowledge base."""
    try:
        return pc.Index(PINECONE_KB_INDEX_NAME)
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Knowledge base index '{PINECONE_KB_INDEX_NAME}' is not available: {str(e)}",
        )


def _embed_texts(texts: List[str]) -> List[List[float]]:
    """Embed a list of texts using OpenRouter's OpenAI-compatible embeddings API.

    Uses the `openai/text-embedding-ada-002` model via OpenRouter.
    """
    if not texts:
        return []
    if embedding_client is None:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="OpenRouter embedding client is not configured; cannot compute embeddings for knowledge base.",
        )
    try:
        extra_headers: Dict[str, str] = {}
        if OPENROUTER_SITE_URL:
            extra_headers["HTTP-Referer"] = OPENROUTER_SITE_URL
        if OPENROUTER_SITE_NAME:
            extra_headers["X-Title"] = OPENROUTER_SITE_NAME

        kwargs: Dict[str, Any] = {
            "model": "openai/text-embedding-ada-002",
            "input": texts,
            "encoding_format": "float",
        }
        if extra_headers:
            kwargs["extra_headers"] = extra_headers

        response = embedding_client.embeddings.create(**kwargs)
        return [item.embedding for item in response.data]
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to compute embeddings via OpenRouter: {str(e)}",
        )


def _chunk_text(text: str, max_chars: int = 1000, overlap: int = 200) -> List[str]:
    """Simple text splitter that keeps chunks around max_chars, with optional overlap."""
    text = text or ""
    if not text.strip():
        return []
    chunks: List[str] = []
    start = 0
    length = len(text)
    while start < length:
        end = min(start + max_chars, length)
        chunk = text[start:end]
        chunks.append(chunk.strip())
        if end == length:
            break
        start = max(0, end - overlap)
    return [c for c in chunks if c]


def query_knowledge_base(
    query: str,
    top_k: int = KB_TOP_K_DEFAULT,
    score_threshold: float = KB_SCORE_THRESHOLD_DEFAULT,
) -> List[dict]:
    """
    Query the Pinecone vector knowledge base and return a list of matches.

    Each match has: score, text, source, doc_id, chunk_index.
    The global architecture KB document (if configured) is always prepended as
    a synthetic match so that it acts as base context for all queries.
    """
    if not query or not query.strip():
        matches: List[dict] = []
    else:
        index = _get_kb_index()
        embedding = _embed_texts([query])[0]

        try:
            res = index.query(
                vector=embedding,
                top_k=top_k,
                include_metadata=True,
            )
        except Exception as e:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Failed to query knowledge base: {str(e)}",
            )

        # Handle different possible response shapes
        matches_raw = []
        if isinstance(res, dict):
            matches_raw = res.get("matches", [])
        elif hasattr(res, "to_dict"):
            res_dict = res.to_dict()
            matches_raw = res_dict.get("matches", [])
        elif hasattr(res, "matches"):
            matches_raw = res.matches

        matches = []
        for m in matches_raw or []:
            if isinstance(m, dict):
                score = m.get("score")
                metadata = m.get("metadata") or {}
            else:
                score = getattr(m, "score", None)
                metadata = getattr(m, "metadata", {}) or {}

            if score is None:
                continue
            if score_threshold is not None and float(score) < float(score_threshold):
                continue

            matches.append(
                {
                    "score": float(score),
                    "text": metadata.get("text", ""),
                    "source": metadata.get("source_file_name") or metadata.get("source") or "",
                    "doc_id": metadata.get("doc_id") or "",
                    "chunk_index": metadata.get("chunk_index"),
                }
            )

    # Always prepend the architecture KB document (if present) so that it acts
    # as base knowledge for everything.
    arch_text = ""
    try:
        arch_text = _get_architecture_kb_text()
    except Exception:
        arch_text = ""

    if arch_text and arch_text.strip():
        matches.insert(
            0,
            {
                "score": 1.0,
                "text": arch_text,
                "source": "architecture_kb",
                "doc_id": "architecture_kb",
                "chunk_index": 0,
            },
        )

    return matches


def store_document_in_kb(text: str, source_file_name: Optional[str] = None) -> dict:
    """
    Split a document into chunks, embed, and store in the Pinecone KB index.
    Returns a summary including doc_id and number of chunks stored.
    """
    index = _get_kb_index()
    chunks = _chunk_text(text)
    if not chunks:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Uploaded document contained no extractable text.",
        )

    embeddings = _embed_texts(chunks)
    if len(embeddings) != len(chunks):
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Embedding service returned unexpected number of vectors.",
        )

    doc_id = str(uuid.uuid4())
    now = datetime.utcnow().isoformat()

    vectors = []
    for idx, (chunk, emb) in enumerate(zip(chunks, embeddings)):
        vectors.append(
            {
                "id": f"{doc_id}_{idx}",
                "values": emb,
                "metadata": {
                    "text": chunk,
                    "source_file_name": source_file_name,
                    "doc_id": doc_id,
                    "chunk_index": idx,
                    "created_at": now,
                },
            }
        )

    try:
        index.upsert(vectors=vectors)
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to upsert vectors into knowledge base: {str(e)}",
        )

    return {"doc_id": doc_id, "chunks_indexed": len(vectors)}


def store_architecture_in_kb(text: str, source_file_name: Optional[str] = None) -> dict:
    """Index the global architecture KB document into the Pinecone KB index.

    On each call, any previous architecture KB vectors (matching
    ARCHITECTURE_KB_DOC_ID) are removed so that only the latest version is kept.
    """
    index = _get_kb_index()
    chunks = _chunk_text(text)
    if not chunks:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Uploaded architecture document contained no extractable text.",
        )

    embeddings = _embed_texts(chunks)
    if len(embeddings) != len(chunks):
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Embedding service returned unexpected number of vectors for architecture KB.",
        )

    now = datetime.utcnow().isoformat()

    # Remove any previous architecture KB vectors so that only the latest upload
    # is active in the index.
    try:
        index.delete(filter={"doc_id": ARCHITECTURE_KB_DOC_ID})
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to delete previous architecture knowledge from index: {str(e)}",
        )

    vectors = []
    for idx, (chunk, emb) in enumerate(zip(chunks, embeddings)):
        vectors.append(
            {
                "id": f"{ARCHITECTURE_KB_DOC_ID}_{idx}",
                "values": emb,
                "metadata": {
                    "text": chunk,
                    "source_file_name": source_file_name,
                    "doc_id": ARCHITECTURE_KB_DOC_ID,
                    "chunk_index": idx,
                    "created_at": now,
                    "is_architecture_kb": True,
                },
            }
        )

    try:
        index.upsert(vectors=vectors)
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to upsert architecture knowledge into index: {str(e)}",
        )

    return {"doc_id": ARCHITECTURE_KB_DOC_ID, "chunks_indexed": len(vectors)}


def extract_text_from_upload(file: UploadFile) -> str:
    """
    Extract plain text from an uploaded file (PDF or text/*).
    Falls back to UTF-8 decode for unknown types.
    """
    contents = file.file.read()
    filename = (file.filename or "").lower()
    content_type = (file.content_type or "").lower()

    text = ""
    try:
        if filename.endswith(".pdf") or "pdf" in content_type:
            try:
                from pypdf import PdfReader  # type: ignore
            except ImportError:
                raise HTTPException(
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    detail="PDF support is not installed. Please add 'pypdf' to requirements.txt.",
                )
            import io as _io

            reader = PdfReader(_io.BytesIO(contents))
            pages_text: List[str] = []
            for page in reader.pages:
                page_text = page.extract_text() or ""
                pages_text.append(page_text)
            text = "\n".join(pages_text)
        elif content_type.startswith("text/") or filename.endswith((".txt", ".md", ".markdown")):
            text = contents.decode("utf-8", errors="ignore")
        else:
            # Best-effort decode for other types
            text = contents.decode("utf-8", errors="ignore")
    finally:
        file.file.close()

    return text or ""
