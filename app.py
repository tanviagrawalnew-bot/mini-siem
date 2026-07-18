from flask import Flask, render_template, request
import os

app = Flask(__name__)

# Upload Folder Configuration
UPLOAD_FOLDER = "uploads"
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER


# ---------------- Home ----------------

@app.route("/")
def home():
    return render_template("index.html")


# ---------------- Dashboard ----------------

@app.route("/dashboard")
def dashboard():
    return render_template("dashboard.html")


# ---------------- Upload Logs ----------------

@app.route("/upload", methods=["GET", "POST"])
def upload():

    if request.method == "POST":

        file = request.files.get("logfile")

        if file and file.filename:

            filepath = os.path.join(
                app.config["UPLOAD_FOLDER"],
                file.filename
            )

            file.save(filepath)

            return f"{file.filename} uploaded successfully!"

    return render_template("upload.html")


# ---------------- Reports ----------------

@app.route("/reports")
def reports():
    return render_template("reports.html")


# ---------------- Run App ----------------

if __name__ == "__main__":

    app.run(debug=True)