from flask import Flask, request, jsonify

app = Flask(__name__)

@app.route('/signup', methods=['POST'])
def signup():
    if request.content_type != "application/json":
        return jsonify({'error': 'Content-Type must be application/json'}), 400

    if not request.is_json:
        return jsonify({'error': 'Request body must be JSON'}), 400

    data = request.get_json()
    print(data)
    return jsonify({
        'status': 'ok',
        'received': data
    }), 200

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5001, debug=True)
