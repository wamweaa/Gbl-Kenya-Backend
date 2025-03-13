from flask import Flask, request, jsonify

app = Flask(__name__)

@app.route('/callback', methods=['POST'])
def callback():
    data = request.get_json()
    print("MPESA Callback Data:", data)  # Log response
    return jsonify({"message": "Callback received"}), 200

if __name__ == '__main__':
    app.run(debug=True, port=5001)
