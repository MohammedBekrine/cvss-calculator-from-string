from flask import Flask, request, jsonify, render_template
import cvssCalculator as calc


app = Flask(__name__)


@app.get("/health")
def health():
    return jsonify({"status": "ok"})


@app.get("/")
def index():
    return render_template("index.html")


@app.route("/calculate", methods=["GET", "POST"])
def calculate():
    """
    Calculate CVSS Base Score from a vector string.

    Accepts:
    - GET:  /calculate?vector=CVSS:3.1/...
    - POST: JSON {"vector": "CVSS:3.1/..."}
            or form field 'vector'
    """
    vector = None

    if request.method == "GET":
        vector = request.args.get("vector")
    else:
        data = request.get_json(silent=True) or {}
        vector = data.get("vector") or request.form.get("vector")

    if not vector:
        return (
            jsonify({
                "error": "missing_vector",
                "message": "Provide CVSS vector via query ?vector=... or JSON/form field 'vector'",
            }),
            400,
        )

    try:
        ver, _ = calc.parse_vector(vector)
        score = calc.compute_from_vector(vector)
        return jsonify({
            "vector": vector,
            "version": ver,
            "score": score,
        })
    except RuntimeError as e:
        # Likely missing optional dependency for CVSS v4.0
        return jsonify({
            "error": "runtime_error",
            "message": str(e),
        }), 500
    except ValueError as e:
        return jsonify({
            "error": "invalid_input",
            "message": str(e),
        }), 400
    except Exception as e:
        return jsonify({
            "error": "internal_error",
            "message": str(e),
        }), 500


if __name__ == "__main__":
    # Default dev server
    app.run(host="0.0.0.0", port=5000, debug=True)
