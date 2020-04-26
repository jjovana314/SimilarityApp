""" Helper for similarity API. """

import bcrypt
import spacy
from pymongo import MongoClient


def user_exist(username: str, users: MongoClient) -> bool:
    """ Check if there is user with given username.

    Args:
        username (str): username
        users (MongoClient): database

    Returns:
        bool: True if username exist in database, False otherwise
    """
    # if there is no user with this username
    if users.find({"Username": username}).count() == 0:
        return False
    return True


def verify_pw(
    username: str, password: str, users: MongoClient
) -> bool:
    """ Password verification.

    Args:
        users (MongoClient): users database
        username (str): username
        password (str): password

    Returns:
        bool: True if password is valid, False otherwise
    """
    if not user_exist(username, users):
        return False

    hashed_pw = users.find(
        {
            "Username": username
        }
    )[0]["Password"]

    if bcrypt.hashpw(password.encode("utf8"), hashed_pw) == hashed_pw:
        return True
    else:
        return False


def count_tokens(username: str, users: MongoClient) -> int:
    """ Counting tokens from database.

    Args:
        users (MongoClient): users database
        username (str): username

    Returns:
        tokens (int): number of tokens for current user
    """
    tokens = users.find(
        {
            "Username": username
        }
    )[0]["Tokens"]
    return tokens


def similarity_ratio(text1: str, text2: str) -> float:
    """ Calculating similarity between two texts.

    Args:
        text1 (str): text for calculation
        text2 (str): text for calculation

    Returns:
        float: similarity ratio (number between 0 and 1)
    """
    nlp = spacy.load("en_core_web_sm")  # natural language processing
    # change string to nlp object
    text1 = nlp(text1)
    text2 = nlp(text2)

    # ratio is a number between 0 and 1
    # the closer to 1, the more similar texts are
    return text1.similarity(text2)


def validate_keys(keys_valid: list, keys: list) -> bool:
    """ Keys validation.

    Args:
        keys_valid (list): list of valid keys
        keys (list): list of keys for validation

    Returns:
        bool: True if keys are valid, False otherwise
    """
    if len(keys_valid) != len(keys):
        return False

    for k in keys:
        if k not in keys_valid:
            return False

    return True


def update_tokens(
    users: MongoClient, username: str, operator_: object, amout: int
) -> None:
    """ Updating tokens.

    Args:
        users (MongoClient): database
        username (str): username
        operator_ (object): + or - for adding or removing tokens
        amout (int): number of tokens that you want to add or remove
    """
    num_tokens = users.find(
        {
            "Username": username
        }
    )[0]["Tokens"]
    new_tokens_value = operator_(num_tokens, amout)
    users.update(
        {
            "Username": username
        },
        {
            "$set": {"Tokens": new_tokens_value}
        }
    )
