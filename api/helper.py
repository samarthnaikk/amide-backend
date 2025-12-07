import secrets
import binascii
import os
from supabase import create_client, Client
from dotenv import load_dotenv

load_dotenv()

SUPABASE_URL = os.getenv("SUPABASE_URL")
SUPABASE_KEY = os.getenv("SUPABASE_SERVICE_KEY")

supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY)

def generate_key(email_id):
    try:
        existing_user = supabase.table("users").select("*").eq("email", email_id).execute()
        if existing_user.data:
            return False
        random_bytes = secrets.token_bytes(32)
        api_key = "amide_" + binascii.hexlify(random_bytes).decode()
        response = supabase.table("users").update({"api": api_key}).eq("email", email_id).execute()
        if response.data:
            return True
        else:
            return False
    except Exception:
        return False

def verify_key(api_key):
    try:
        user = supabase.table("users").select("email").eq("api", api_key).execute()
        if user.data:
            return user.data[0]["email"]
        else:
            return None
    except Exception:
        return None

if __name__ == "__main__":

    test_email = "zzz@gmail.com"
    result = generate_key(test_email)
    print(f"Function result: {result}")
