import os

from flask import Flask, jsonify
from keycloak import KeycloakAdmin

app = Flask(__name__)

admin = KeycloakAdmin(
    server_url=os.environ["KEYCLOAK_URL"],
    username=os.environ["KEYCLOAK_USERNAME"],
    password=os.environ["KEYCLOAK_PASSWORD"],
    realm_name=os.environ["KEYCLOAK_REALM"],   # "trino" — target realm for operations
    user_realm_name="master",                   # realm the admin credentials live in
    client_id=os.environ["KEYCLOAK_CLIENT_ID"],
    verify=True,
)

@app.route("/users/<username>")
def get_user(username):
    print(f"Requested username: '{username}'", flush=True)

    users = admin.get_users({"username": username})   # no more admin.realm_name = ... needed
    print(f"Found: {users}", flush=True)

    if not users:
        return jsonify({"error": "not found"}), 404

    user = users[0]
    groups = admin.get_user_groups(user["id"])
    return jsonify({
        "username": user["username"],
        "email": user.get("email"),
        "enabled": user["enabled"],
        "groups": [g["name"] for g in groups],
    })

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)