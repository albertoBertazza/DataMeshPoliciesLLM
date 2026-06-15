from flask import Flask, jsonify, abort
from ldap3 import Server, Connection, ALL, SUBTREE

app = Flask(__name__)

LDAP_URL = "ldap://ldap:389"
BIND_DN = "cn=admin,dc=example,dc=com"
BIND_PW = "admin"
USER_BASE = "ou=users,dc=example,dc=com"

server = Server(LDAP_URL, get_info=ALL)

@app.route("/users/<username>")
def get_user_attrs(username):
    conn = Connection(server, BIND_DN, BIND_PW, auto_bind=True)

    conn.search(
        USER_BASE,
        f"(uid={username})",
        SUBTREE,
        attributes=['mail', 'telephoneNumber']
    )

    if not conn.entries:
        abort(404)

    entry = conn.entries[0]

    return jsonify({
        "mail": entry.mail.value,
        "telephoneNumber": entry.telephoneNumber.value
    })