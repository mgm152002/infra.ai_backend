from supabase import create_client, Client
from supabase.lib.client_options import SyncClientOptions
from app.core.config import settings

supabase: Client = create_client(
    settings.SUPABASE_URL,
    settings.SUPABASE_KEY,
    options=SyncClientOptions(
        postgrest_client_timeout=settings.SUPABASE_POSTGREST_TIMEOUT_S,
        storage_client_timeout=settings.SUPABASE_STORAGE_TIMEOUT_S,
        function_client_timeout=settings.SUPABASE_FUNCTION_TIMEOUT_S,
    ),
)
