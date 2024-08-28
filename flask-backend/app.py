from flask import Flask, jsonify, request
import requests
from flask_cors import CORS
import openai

app = Flask(__name__)
CORS(app)

# Configure OpenAI API endpoint and headers
openai_api_url = "https://dlab-openai01.openai.azure.com/openai/deployments/Sofiene_First_Model/chat/completions?api-version=2024-02-01"
openai_headers = {
    "Content-Type": "application/json",
    "api-key": "a6cf4102a24f48c5bc291262b5e886a9",
}

# Global variable to store token count
latest_token_count = None

owasp_checklist = [
    "Check for SQL Injection vulnerabilities.",
    "Check for Cross-Site Scripting (XSS) vulnerabilities.",
    "Check for insecure direct object references.",
]

@app.route('/')
def home():
    return 'Hello from SECTIK'

@app.route('/analyze_code', methods=['POST'])
def analyze_code():
    global latest_token_count
    try:
        data = request.get_json()
        if not data:
            return jsonify({'error': 'No data received'}), 400
        files = data.get('files', [])

        passed_checks = []
        failed_checks = []

        if not files:
            return jsonify({'error': 'No files provided'}), 400

        # Prepare the data for the Azure OpenAI API
        file_content = files[0]['content'] if files else ''
        
        # Create a detailed prompt
        owasp_prompt = "\n".join(owasp_checklist)
        openai_request_payload = {
            "model": "gpt-3.5-turbo",
            "messages": [
                {"role": "system", "content": "You are a code review assistant specializing in security analysis."},
                {"role": "user", "content": f"Analyze the following code for security vulnerabilities against this checklist:\n\n{owasp_prompt}\n\nCode:\n{file_content}\n\nFor each item in the checklist, clearly indicate whether the code passed or failed the check and provide a brief explanation."}
            ],
            "max_tokens": 1000
        }

        response = requests.post(openai_api_url, headers=openai_headers, json=openai_request_payload)
        response.raise_for_status()

        openai_response = response.json()

        latest_token_count = openai_response.get('usage', {}).get('total_tokens', 0)
        analysis_result = openai_response.get('choices', [{}])[0].get('message', {}).get('content', '')

        # Process the analysis result and classify passed/failed checks
        for check in owasp_checklist:
            # Extract specific details from the response to determine pass/fail
            if f"{check.lower()}: pass" in analysis_result.lower():
                passed_checks.append(check)
            elif f"{check.lower()}: fail" in analysis_result.lower():
                failed_checks.append(check)
            else:
                # Default to failed if the response is unclear
                failed_checks.append(check)

        return jsonify({
            'total_tokens': latest_token_count,
            'passed_checks': passed_checks,
            'failed_checks': failed_checks,
            'openai_response': analysis_result
        })

    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/token_count', methods=['GET'])
def token_count():
    if latest_token_count is None:
        return jsonify({'error': 'No token count available'}), 404

    return jsonify({'total_tokens': latest_token_count})

if __name__ == "__main__":
    app.run(port=8081)
