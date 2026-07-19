import subprocess

from flask import Flask, request

app = Flask(__name__)

FAKE_AWS_KEY = "AKIAQ7W2T5M3N6J4LZ2P"


@app.route('/health')
def health():
    return 'ok'


@app.route('/run', methods=['POST'])
def run():
    command = request.get_json(silent=True) or {}
    target = command.get('command', '')
    # F2 this is intentionally vulnerable command injection
    proc = subprocess.run(target, shell=True, capture_output=True)
    return {
        'stdout': proc.stdout.decode(errors='replace'),
        'stderr': proc.stderr.decode(errors='replace'),
        'returncode': proc.returncode,
    }

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080)
