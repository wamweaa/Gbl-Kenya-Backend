import requests
from config import MPESA_CONSUMER_KEY, MPESA_CONSUMER_SECRET

def get_access_token():
    url = "https://api.safaricom.co.ke/oauth/v1/generate?grant_type=client_credentials"
    #https://api.safaricom.co.ke/oauth/v1/generate?grant_type=client_credentials



    try:
        response = requests.get(url, auth=(MPESA_CONSUMER_KEY, MPESA_CONSUMER_SECRET))
        print("MPESA Access Token Response:", response.text)  # Log response
        response.raise_for_status()  # Raise error for bad response
        return response.json().get("access_token")
    except requests.exceptions.RequestException as e:
        print("Error fetching MPESA access token:", e)
        return None
