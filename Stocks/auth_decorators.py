from flask import session, request, jsonify
from functools import wraps
from Stocks import app
from Stocks.models import User
import jwt


def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        user = dict(session).get("profile", None)
        # data = {}
        if "x-access-token" in request.headers:
            token = request.headers["x-access-token"]
        # return 401 if token is not passed
        if not token and not user:
            return jsonify({"message": "Login required !!"}), 401
        try:
            # decoding the payload to fetch the stored details
            if token:
                data = jwt.decode(token, app.config["SECRET_KEY"])
                current_user = User.query.filter_by(public_id=data["public_id"]).first()
            if user:
                current_user = user
            
        except:
            return jsonify({"message": "Token is invalid !!"}), 401
        # returns the current logged in users contex to the routes
        return f(*args, **kwargs)

    return decorated

