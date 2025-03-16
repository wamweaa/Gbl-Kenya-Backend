import requests
import base64
from datetime import datetime
from requests.auth import HTTPBasicAuth

# MPESA API Credentials
MPESA_SHORTCODE = "174379"
MPESA_PASSKEY = "bfb279f9aa9bdbcf158e97dd71a467cd2e0c893059b10f78e6b72ada1ed2c919"
MPESA_CONSUMER_KEY = "hV8s2GQfEjGfzEWq504mHkGbPm1FtpE2t7KI6asKuyEd50KS"
MPESA_CONSUMER_SECRET = "WgNofqiscvyxmBxpTZFrEC5nF1nVfFDFBjtL01LlYhetWpANK9tfyaU8JsBiGlEi"
MPESA_BASE_URL = "https://sandbox.safaricom.co.ke/mpesa/stkpush/v1/processrequest"
MPESA_TOKEN_URL = "https://sandbox.safaricom.co.ke/oauth/v1/generate?grant_type=client_credentials"
MPESA_CALLBACK_URL = "https://gbl-kenya-backend.onrender.com/stk_callback"

def get_mpesa_token():
    """
    Fetch a fresh MPESA access token.
    """
    response = requests.get(MPESA_TOKEN_URL, auth=HTTPBasicAuth(MPESA_CONSUMER_KEY, MPESA_CONSUMER_SECRET))
    if response.status_code == 200:
        return response.json().get("access_token")
    print("Error fetching token:", response.json())
    return None

def generate_password():
    """
    Generate the password dynamically for MPESA API.
    """
    timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
    password_str = f"{MPESA_SHORTCODE}{MPESA_PASSKEY}{timestamp}"
    password = base64.b64encode(password_str.encode()).decode()
    return password, timestamp

def initiate_stk_push(phone_number, amount):
    """
    Initiate an STK push payment request.
    """
    token = get_mpesa_token()
    if not token:
        return {"error": "Failed to retrieve MPESA token"}, 500

    password, timestamp = generate_password()
    
    payload = {
        "BusinessShortCode": MPESA_SHORTCODE,
        "Password": password,
        "Timestamp": timestamp,
        "TransactionType": "CustomerPayBillOnline",
        "Amount": amount,
        "PartyA": phone_number,
        "PartyB": MPESA_SHORTCODE,
        "PhoneNumber": phone_number,
        "CallBackURL": MPESA_CALLBACK_URL,
        "AccountReference": "CompanyXLTD",
        "TransactionDesc": "Payment of X"
    }

    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {token}"
    }

    response = requests.post(MPESA_BASE_URL, json=payload, headers=headers)
    return response.json(), response.status_code