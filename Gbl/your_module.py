import requests
from requests.auth import HTTPBasicAuth

MPESA_CONSUMER_KEY = "hV8s2GQfEjGfzEWq504mHkGbPm1FtpE2t7KI6asKuyEd50KS"
MPESA_CONSUMER_SECRET = "WgNofqiscvyxmBxpTZFrEC5nF1nVfFDFBjtL01LlYhetWpANK9tfyaU8JsBiGlEi"
MPESA_SHORTCODE = "852648"
MPESA_PASSKEY = "bfb279f9aa9bdbcf158e97dd71a467cd2e0c893059b10f78e6b72ada1ed2c919"
MPESA_CALLBACK_URL = "https://gblkenya.com/mpesa_callback"
MPESA_BASE_URL = "https://api.safaricom.co.ke"
# MPESA_BASE_URL = "https://sandbox.safaricom.co.ke"

def get_mpesa_token():
    url = f"{MPESA_BASE_URL}/oauth/v1/generate?grant_type=client_credentials"

    try:
        response = requests.get(url, auth=HTTPBasicAuth(MPESA_CONSUMER_KEY, MPESA_CONSUMER_SECRET))
        print(f"MPESA Token Request Status Code: {response.status_code}")
        print(f"MPESA Token Response: {response.text}")  # Log the full response for debugging

        if response.status_code == 200:
            return response.json().get("access_token")

        return None

    except Exception as e:
        print(f"Exception occurred in get_mpesa_token: {str(e)}")
        return None


# ✅ **Test the function**
token = get_mpesa_token()
print("Generated Token:", token)
