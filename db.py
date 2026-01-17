import os

from supabase import Client, create_client


def get_supabase() -> Client:
    url = os.environ.get("SUPABASE_URL")
    key = os.environ.get("SUPABASE_SERVICE_ROLE_KEY")

    if not url or not key:
        raise RuntimeError(
            "Missing SUPABASE_URL and/or SUPABASE_SERVICE_ROLE_KEY environment variables"
        )

    return create_client(url, key)


supabase: Client = get_supabase()
