"""
Resources:
    - Register a new user
    - Detect similarity of texts
    - Refill

Register a new user:
    * URLs:
        - /register
    * Method:
        - POST
    * Parameters:
        - username
        - password
    * Status:
        - 200 OK
        - 301 INVALID_USERNAME

Detect similarity of docs:
    * URLs:
        - /detect
    * Method:
        - POST
    * Parameters:
        - username
        - password
        - text 1
        - text 2
    * Status:
        - 200 OK
        - 301 INVALID_USERNAME
        - 302 INVALID_PASSWORD
        - 303 OUT_OF_TOKENS

Refill:
    * URLs:
        - /refill
    * Method:
        - POST
    * Parameters:
        - username
        - admin_password
        - refill amount
    * Status:
        - 200 OK
        - 301 INVALID_USERNAME
        - 304 INVALID_ADMIN_PASSWORD
"""

register = """
{
    "username": str,
    "password": str
}
"""

detect = """
{
    "username": str,
    "password": str,
    "text1": str,
    "text2": str
}
"""

refill = """
{
    "username": str,
    "admin_password": str,
    "add_tokens": int
}
"""
