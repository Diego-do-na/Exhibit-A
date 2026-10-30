import os

from flask import Flask, request

BASE = "/srv/files"
app = Flask(__name__)


@app.route("/download")
def download():
    return send(request.args.get("name", ""))


def send(name):
    with open(os.path.join(BASE, name), "rb") as handle:
        return handle.read()


def create_app():
    inner = Flask("inner")

    @inner.get("/raw")
    def raw():
        return send(request.args.get("name", ""))

    return inner
