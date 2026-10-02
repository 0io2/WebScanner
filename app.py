from flask import Flask, render_template, request
from scanner import VulnerabilityScanner

app = Flask(__name__)

@app.route("/", methods=["GET", "POST"])
def index():
    scan_results = None
    target = None
    if request.method == "POST":
        target = request.form.get("target_url")
        if target:
            # التأكد من أن الرابط يبدأ بـ http أو https
            if not target.startswith("http://") and not target.startswith("https://"):
                target = "http://" + target
            
            scanner = VulnerabilityScanner(target)
            scan_results = scanner.run_scanner()
            
    return render_template("index.html", results=scan_results, target=target)

if __name__ == "__main__":
    app.run(debug=True, port=5000)