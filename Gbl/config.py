# MPESA_CONSUMER_KEY = "hV8s2GQfEjGfzEWq504mHkGbPm1FtpE2t7KI6asKuyEd50KS"
# MPESA_CONSUMER_SECRET = "WgNofqiscvyxmBxpTZFrEC5nF1nVfFDFBjtL01LlYhetWpANK9tfyaU8JsBiGlEi"
# MPESA_SHORTCODE = "852648"
# MPESA_PASSKEY = "bfb279f9aa9bdbcf158e97dd71a467cd2e0c893059b10f78e6b72ada1ed2c919"
# MPESA_CALLBACK_URL = "https://gblkenya.com/mpesa_callback"
# MPESA_BASE_URL = "https://api.safaricom.co.ke"
# MPESA_BASE_URL = "https://sandbox.safaricom.co.ke"

import os
from dotenv import load_dotenv

load_dotenv()

MPESA_CONSUMER_KEY = os.getenv("hV8s2GQfEjGfzEWq504mHkGbPm1FtpE2t7KI6asKuyEd50KS")
MPESA_CONSUMER_SECRET = os.getenv("WgNofqiscvyxmBxpTZFrEC5nF1nVfFDFBjtL01LlYhetWpANK9tfyaU8JsBiGlEi")
MPESA_SHORTCODE = os.getenv("174379")
MPESA_PASSKEY = os.getenv("bfb279f9aa9bdbcf158e97dd71a467cd2e0c893059b10f78e6b72ada1ed2c919")
CALLBACK_URL = os.getenv("https://gblkenya.com/mpesa_callback")

