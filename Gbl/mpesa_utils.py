import requests
from requests.auth import HTTPBasicAuth
import base64
from datetime import datetime

CONSUMER_KEY = "wmL02I8q8BUglDEV2eXaJJri38GsAiATsaFFMSZuIjDDMHF2"
CONSUMER_SECRET = "FeN6rlR3CQrSe5dGztLVnmucrL8B4UhGo9poECuNsT1YPlaBoL3SF1DDSvXnzmGj"
SHORTCODE = "852648"
PASSKEY = "your_passkey"
CALLBACK_URL = "https://yourdomain.com/api/mpesa/callback"

def get_access_token():
    api_url = "https://sandbox.safaricom.co.ke/oauth/v1/generate?grant_type=client_credentials"
    response = requests.get(api_url, auth=HTTPBasicAuth(CONSUMER_KEY, CONSUMER_SECRET))
    return response.json().get('access_token')

def initiate_stk_push(phone_number, amount):
    access_token = get_access_token()
    timestamp = datetime.now().strftime('%Y%m%d%H%M%S')
    password = base64.b64encode(f'{SHORTCODE}{PASSKEY}{timestamp}'.encode()).decode()

    stk_push_url = "https://sandbox.safaricom.co.ke/mpesa/stkpush/v1/processrequest"
    headers = {"Authorization": f"Bearer {access_token}"}
    
    payload = {
        "BusinessShortCode": SHORTCODE,
        "Password": password,
        "Timestamp": timestamp,
        "TransactionType": "CustomerPayBillOnline",
        "Amount": amount,
        "PartyA": phone_number,
        "PartyB": SHORTCODE,
        "PhoneNumber": phone_number,
        "CallBackURL": CALLBACK_URL,
        "AccountReference": "Order1234",
        "TransactionDesc": "Payment for your cart items"
    }
    
    response = requests.post(stk_push_url, json=payload, headers=headers)
    return response.json()
