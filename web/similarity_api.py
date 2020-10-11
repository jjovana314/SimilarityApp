"""
Calculate similarity between two texts.

@version: 1.0
@author: Jovana Jovanovic
"""

from http import HTTPStatus
from flask import Flask, jsonify, request
from flask_restful import Resource, Api
from pymongo import MongoClient
from werkzeug.wrappers import BaseResponse
from flask_jwt_extended import (
    JWTManager, jwt_required, create_access_token,
    jwt_refresh_token_required, create_refresh_token,
    get_jwt_identity
)
import bcrypt
import similarity_helper as helper
import operator


OK = HTTPStatus.OK
INVALID_USERNAME = 301
INVALID_PASSWORD = 302
OUT_OF_TOKENS = 303


app = Flask(__name__)
app.config["JWT_SECRET_KEY"] = b"@\xe4\x82+{\xed)~\x92\x84K\x11:)\x95\xf4"
jwt = JWTManager(app)
api = Api(app)

client = MongoClient("mongodb://db:27017")
db = client.SimilarityDB        # creating database
users = db["Users"]             # users database created

# valid keys for registration
register_keys_valid = ["username", "password"]

# number of tokens given on start
num_of_tokens = 6


class Register(Resource):
    """ Register a user. """
    def post(self) -> BaseResponse:
        """ Called when we have a POST request from server.

        Returns:
            BaseResponse object with message and code
        """
        # get data, username and password
        posted_data = request.get_json()
        list_keys = list(posted_data.keys())
        validation = helper.validate_keys(
            list_keys, register_keys_valid
        )
        if not validation:
            return jsonify(
                {
                    "Message": "Keys are not valid!",
                    "Code": HTTPStatus.BAD_REQUEST
                }
            )
        username = posted_data["username"]
        password = posted_data["password"]

        # if there is user with this username in database
        if helper.user_exist(username, users):
            return jsonify(
                {
                    "Code": INVALID_USERNAME,
                    "Message": "Invalid username!"
                }
            )

        # hashing password
        hashed_pw = bcrypt.hashpw(password.encode("utf8"), bcrypt.gensalt())
        # creating user and store information in database
        users.insert(
            {
                "Username": username,
                "Password": hashed_pw,
                "Tokens": num_of_tokens
            }
        )
        return jsonify(
            {
                "access_token": create_access_token(identity=username),
                "refresh_token": create_refresh_token(identity=username),
                "code": OK
            }
        )


# valid keys for detect request
detect_keys_valid = ["username", "password", "text1", "text2"]


class Detect(Resource):
    """ Detect similarity between two texts. """
    def post(self) -> BaseResponse:
        """ Called when we have a POST request from server.

        Returns:
            BaseResponse object with message and code
        """
        posted_data = request.get_json()
        keys_list = list(posted_data.keys())
        # validating keys from server
        validation = helper.validate_keys(keys_list, detect_keys_valid)
        if not validation:
            return jsonify(
                {
                    "Message": "Keys are not valid!",
                    "Code": HTTPStatus.BAD_REQUEST
                }
            )
        username = posted_data["username"]
        password = posted_data["password"]
        text1 = posted_data["text1"]
        text2 = posted_data["text2"]

        # validating that user exist in database
        if not helper.user_exist(username, users):
            return jsonify(
                {
                    "Code": INVALID_USERNAME,
                    "Message": "Invalid username detected!"
                }
            )

        # make sure that password is correct
        correct_pw = helper.verify_pw(username, password, users)
        if not correct_pw:
            return jsonify(
                {
                    "Code": INVALID_USERNAME,
                    "Message": "Invalid password detected!"
                }
            )
        tokens_current = helper.count_tokens(username, users)
        if tokens_current <= 0:
            return jsonify(
                {
                    "Code": OUT_OF_TOKENS,
                    "Message": "You're out of tokens, please refill!"
                }
            )
        ratio = helper.similarity_ratio(text1, text2)
        # ! don't forget to take one token
        helper.update_tokens(users, username, operator.sub, 1)
        return jsonify(
            {
                "Code": OK,
                "Similarity": ratio,
                "Message": "Similarity score calculated successfully."
            }
        )


# valid keys for refill
refill_tokens_valid = ["username", "admin_password", "amout"]
admin_password = "abmnOp12.80"


class Refill(Resource):
    """ Refill tokens. """
    def post(self) -> BaseResponse:
        """ Called when we have a POST request from server.

        Returns:
            BaseResponse object with message and code
        """
        # crypt admin password and insert into database
        admin_password_crypted = bcrypt.hashpw(
            admin_password.encode("utf8"), bcrypt.gensalt()
        )
        users.insert(
            {
                "Username": "admin",
                "Password": admin_password_crypted
            }
        )
        # get data and validate keys
        data = request.get_json()
        keys_list = list(data.keys())
        keys_validation = helper.validate_keys(refill_tokens_valid, keys_list)
        if not keys_validation:
            return jsonify(
                {
                    "Message": "Keys you entered are not valid.",
                    "Code": HTTPStatus.BAD_REQUEST
                }
            )
        username = data["username"]
        admin_pwd = data["admin_password"]
        amout_tokens = data["amout"]
        if not helper.user_exist(username, users):
            return jsonify(
                {
                    "Message": "Account with this username does not exist.",
                    "Code": INVALID_USERNAME
                }
            )
        verification = helper.verify_pw("admin", admin_pwd, users)
        if not verification:
            return jsonify(
                {
                    "Message": "Password is incorrect!",
                    "Code": INVALID_PASSWORD
                }
            )
        # add tokens
        helper.update_tokens(users, username, operator.add, amout_tokens)
        return jsonify(
            {
                "Message": "Your tokens updated successfully.",
                "Code": OK
            }
        )


api.add_resource(Register, "/register")
api.add_resource(Detect, "/detect")
api.add_resource(Refill, "/refill")

if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0")
