import yara, zipfile, secrets, string, os
from markupsafe import Markup
from flask import Flask, request, flash, redirect, render_template

low_risk = yara.compile("LowRisk.yara")
medium_risk = yara.compile("MedRisk.yara")
high_risk = yara.compile("HighRisk.yara")

app = Flask("ratpoison")
app.config["SECRET_KEY"] = "".join(
    secrets.choice(string.ascii_letters + string.digits + string.punctuation)
    for _ in range(32)
)

MAX_UNZIP_SIZE = 100 * 1024 * 1024


@app.route("/", methods=["GET", "POST"])
def index():
    if request.method == "POST":
        file = request.files["file"]
        flashed_data = ""
        if file.filename == "":
            flash("You must select a file to upload.")
            return redirect(request.url)
        else:
            with zipfile.ZipFile(file.stream._file) as zipp:
                for file_info in zipp.infolist():
                    if file_info.filename.endswith(".class"):
                        # if greater than 100MB
                        if file_info.file_size > MAX_UNZIP_SIZE:
                            flashed_data += Markup(
                                f"I did not unzip {file_info.filename} because it was > {MAX_UNZIP_SIZE} bytes.<br>"
                            )
                        file_name = zipp.extract(file_info, path="tmp")
                        high_risk_result = high_risk.match(file_name)
                        if len(high_risk_result) > 0:
                            flashed_data += Markup(
                                f"This jar file contains the high risk file {file_info.filename}, we matched {high_risk_result['main'][0]['strings'][0]['data']}<br>"
                            )
                            continue
                        medium_risk_result = medium_risk.match(file_name)
                        if len(medium_risk_result) > 0:
                            flashed_data += Markup(
                                f"This jar file contains the medium risk file {file_info.filename}, we matched {medium_risk_result['main'][0]['strings'][0]['data']}<br>"
                            )
                            continue
                        low_risk_result = low_risk.match(file_name)
                        if len(low_risk_result) > 0:
                            flashed_data += Markup(
                                f"This jar file contains potentially risky files {file_info.filename}, we matched {low_risk_result['main'][0]['strings'][0]['data']}<br>"
                            )
                            continue
                        os.remove(file_name)
                if flashed_data == "":
                    flashed_data = "We think the file is clean, but we can't be sure."
                flash(flashed_data)
                return redirect(request.url)
    else:
        return render_template("main.html")


if __name__ == "__main__":
    app.run(host="localhost")
