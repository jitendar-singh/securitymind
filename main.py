from flask import Flask, request, jsonify
from flask_cors import CORS
from secmind.agent import secmind

app = Flask(__name__)
CORS(app)  # This will enable CORS for all routes

@app.route('/chat', methods=['POST'])
def chat():
    data = request.get_json()
    user_message = data.get('message')

    if not user_message:
        return jsonify({'error': 'No message provided'}), 400

    try:
        # Assuming the agent has a method like `chat` or `invoke`
        agent_response = secmind.chat(user_message)
        return jsonify({'response': agent_response})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    app.run(port=5001, debug=True)
