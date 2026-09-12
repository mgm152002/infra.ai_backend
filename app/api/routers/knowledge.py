"""Knowledge-base API routes."""

import os
from datetime import datetime
from typing import Annotated

import jwt
from fastapi import APIRouter, Depends, File, HTTPException, UploadFile, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jwt import PyJWTError

from app.core.config import settings
from app.core.database import supabase
from app.core.security import verify_token
from app.services.knowledge_service import (
    ARCHITECTURE_KB_DOC_ID,
    ARCHITECTURE_KB_FILE_PATH,
    PINECONE_KB_INDEX_NAME,
    _get_kb_index,
    extract_text_from_upload,
    query_knowledge_base,
    store_architecture_in_kb,
    store_document_in_kb,
)

router = APIRouter()
security = HTTPBearer()


@router.post("/addKnowledge")
def addKnowledge(
    credentials: Annotated[HTTPAuthorizationCredentials, Depends(security)],
    file: UploadFile = File(...),
):
    """Ingest a SOP or other knowledge-base document into the Pinecone vector index.

    This endpoint is protected by the same JWT-based auth used elsewhere. The caller
    must provide a valid `Authorization: Bearer <token>` header, and the token must
    correspond to an existing user in the `Users` table.
    """
    # Authenticate the request (mirror logic from `verify_token` without using it as a
    # dependency to avoid definition-order issues).
    try:
        token = credentials.credentials
        payload = jwt.decode(token, key=settings.CLERK_PUBLIC_KEY, algorithms=["RS256"])
        email = payload.get("email")
        if email is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Could not validate credentials - email not found",
            )
        user_response = supabase.table("Users").select("id").eq("email", email).execute()
        if not user_response.data or len(user_response.data) == 0:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found",
            )
        user_id = user_response.data[0]["id"]
    except PyJWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials - invalid token",
        )

    # If we reach here, the caller is authenticated and mapped to a valid user.
    try:
        raw_text = extract_text_from_upload(file)
        if not raw_text.strip():
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Uploaded file contained no readable text.",
            )

        result = store_document_in_kb(
            text=raw_text,
            source_file_name=file.filename,
        )

        # Best-effort: record document metadata in Supabase for listing/deletion
        try:
            supabase.table("KnowledgeBaseDocs").insert(
                {
                    "doc_id": result["doc_id"],
                    "source_file_name": file.filename,
                    "chunks_indexed": result["chunks_indexed"],
                    "user_id": user_id,
                    "email": email,
                    "index_name": PINECONE_KB_INDEX_NAME,
                    "created_at": datetime.utcnow().isoformat(),
                }
            ).execute()
        except Exception as meta_err:
            # Do not fail ingestion if metadata recording fails
            print(
                f"Failed to record KnowledgeBaseDocs metadata for doc_id={result['doc_id']}: {str(meta_err)}"
            )

        return {
            "status": "ok",
            "doc_id": result["doc_id"],
            "chunks_indexed": result["chunks_indexed"],
            "index_name": PINECONE_KB_INDEX_NAME,
        }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to add knowledge: {str(e)}",
        )


@router.post("/knowledge/architecture")
def upload_architecture_knowledge(
    credentials: Annotated[HTTPAuthorizationCredentials, Depends(security)],
    file: UploadFile = File(...),
):
    """Upload a Markdown/text file describing the global infrastructure architecture.

    The raw text is stored both on disk at `ARCHITECTURE_KB_FILE_PATH` (for
    backwards-compatible global base context) and in the Pinecone vector index
    used by the assistant so that architecture knowledge participates in
    semantic search.
    """
    # Authenticate the request (same pattern as /addKnowledge).
    try:
        token = credentials.credentials
        payload = jwt.decode(token, key=settings.CLERK_PUBLIC_KEY, algorithms=["RS256"])
        email = payload.get("email")
        if email is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Could not validate credentials - email not found",
            )
        user_response = supabase.table("Users").select("id").eq("email", email).execute()
        if not user_response.data or len(user_response.data) == 0:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found",
            )
        _user_id = user_response.data[0]["id"]  # reserved for future auditing/use
    except PyJWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials - invalid token",
        )

    try:
        raw_text = extract_text_from_upload(file)
        if not raw_text.strip():
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Uploaded file contained no readable text.",
            )

        # Index architecture KB into Pinecone under a deterministic doc_id so it can
        # be queried alongside other knowledge documents.
        kb_result = store_architecture_in_kb(
            text=raw_text,
            source_file_name=file.filename,
        )

        # Persist architecture KB to the configured filesystem path (overwriting any
        # previous version) so query_knowledge_base can continue to inject it as a
        # global base document.
        try:
            dir_name = os.path.dirname(ARCHITECTURE_KB_FILE_PATH)
            if dir_name:
                os.makedirs(dir_name, exist_ok=True)
            with open(ARCHITECTURE_KB_FILE_PATH, "w", encoding="utf-8") as f:
                f.write(raw_text)
        except Exception as fs_err:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Failed to persist architecture knowledge file: {str(fs_err)}",
            )

        # Persist architecture document metadata in Supabase so the frontend can
        # list it alongside regular knowledge documents.
        try:
            existing_arch = (
                supabase.table("KnowledgeBaseDocs")
                .select("id")
                .eq("doc_id", ARCHITECTURE_KB_DOC_ID)
                .eq("user_id", _user_id)
                .limit(1)
                .execute()
            )
            arch_row = {
                "user_id": _user_id,
                "email": email,
                "doc_id": ARCHITECTURE_KB_DOC_ID,
                "source_file_name": file.filename,
                "chunks_indexed": kb_result["chunks_indexed"],
                "index_name": PINECONE_KB_INDEX_NAME,
            }
            if existing_arch.data:
                supabase.table("KnowledgeBaseDocs").update(arch_row).eq(
                    "id", existing_arch.data[0]["id"]
                ).execute()
            else:
                supabase.table("KnowledgeBaseDocs").insert(arch_row).execute()
        except Exception:
            pass

        return {
            "status": "ok",
            "message": "Architecture knowledge base updated",
            "file_path": ARCHITECTURE_KB_FILE_PATH,
            "doc_id": kb_result["doc_id"],
            "chunks_indexed": kb_result["chunks_indexed"],
            "index_name": PINECONE_KB_INDEX_NAME,
        }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to store architecture knowledge: {str(e)}",
        )


@router.get("/knowledge/architecture/docs", response_model=dict)
async def list_architecture_documents(user_data: dict = Depends(verify_token)):
    """List architecture documents ingested via /knowledge/architecture for the authenticated user."""
    try:
        user_id = user_data["user_id"]
        response = (
            supabase.table("KnowledgeBaseDocs")
            .select("id, doc_id, source_file_name, chunks_indexed, index_name, created_at")
            .eq("user_id", user_id)
            .eq("doc_id", ARCHITECTURE_KB_DOC_ID)
            .order("created_at", desc=True)
            .execute()
        )
        return {"response": response}
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to fetch architecture documents: {str(e)}",
        )


@router.get("/getKnowledge")
def askQuestion(question: str):
    """
    Query the vector-based knowledge base for the given question.
    Returns concatenated relevant chunks (if any) plus metadata.
    """
    matches = query_knowledge_base(question)
    if not matches:
        return {
            "response": "",
            "matches": [],
            "has_knowledge": False,
        }

    combined = "\n\n".join(m["text"] for m in matches if m.get("text"))
    return {
        "response": combined,
        "matches": matches,
        "has_knowledge": True,
    }


@router.get("/knowledge/docs", response_model=dict)
async def list_knowledge_documents(user_data: dict = Depends(verify_token)):
    """List knowledge-base documents ingested via /addKnowledge for the authenticated user.

    Expected Supabase table (must be created separately):

        create table "KnowledgeBaseDocs" (
            id uuid primary key default gen_random_uuid(),
            user_id uuid not null references "Users"(id) on delete cascade,
            email text,
            doc_id text not null,
            source_file_name text,
            chunks_indexed integer,
            index_name text,
            created_at timestamptz default now()
        );

        create index "KnowledgeBaseDocs_user_id_created_at_idx"
            on "KnowledgeBaseDocs"(user_id, created_at desc);
    """
    try:
        user_id = user_data["user_id"]
        response = (
            supabase.table("KnowledgeBaseDocs")
            .select("id, doc_id, source_file_name, chunks_indexed, index_name, created_at")
            .eq("user_id", user_id)
            .order("created_at", desc=True)
            .execute()
        )
        return {"response": response}
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to fetch knowledge base documents: {str(e)}",
        )


@router.delete("/knowledge/{doc_id}", response_model=dict)
async def delete_knowledge_document(doc_id: str, user_data: dict = Depends(verify_token)):
    """Delete a knowledge-base document from Pinecone index and Supabase metadata.

    Only documents owned by the authenticated user (as recorded in KnowledgeBaseDocs)
    can be deleted.
    """
    try:
        # Ensure the document exists and belongs to this user
        existing = (
            supabase.table("KnowledgeBaseDocs")
            .select("id")
            .eq("doc_id", doc_id)
            .eq("user_id", user_data["user_id"])
            .limit(1)
            .execute()
        )
        if not existing.data:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Knowledge document not found for this user",
            )
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to validate knowledge document: {str(e)}",
        )

    # Delete vectors from Pinecone (metadata-based delete)
    index = _get_kb_index()
    try:
        index.delete(filter={"doc_id": doc_id})
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to delete vectors from knowledge base index: {str(e)}",
        )

    # Delete metadata rows from Supabase
    try:
        response = (
            supabase.table("KnowledgeBaseDocs")
            .delete()
            .eq("doc_id", doc_id)
            .eq("user_id", user_data["user_id"])
            .execute()
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to delete knowledge document metadata: {str(e)}",
        )

    return {"status": "ok", "response": response}
