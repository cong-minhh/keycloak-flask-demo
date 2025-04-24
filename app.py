import os
from flask import Flask, redirect, url_for, session, render_template_string, jsonify, request
from authlib.integrations.flask_client import OAuth
from dotenv import load_dotenv
from functools import wraps
from jwt import decode as jwt_decode
import uuid

load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv("FLASK_SECRET_KEY")

oauth = OAuth(app)
oauth.register(
    name="keycloak",
    client_id=os.getenv("KEYCLOAK_CLIENT_ID"),
    client_secret=os.getenv("KEYCLOAK_CLIENT_SECRET"),
    server_metadata_url=os.getenv("KEYCLOAK_SERVER_METADATA_URL"),
    client_kwargs={"scope": "openid profile email"},
)

# Decorators
def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if "user" not in session:
            return redirect(url_for("index"))
        return f(*args, **kwargs)
    return decorated

def role_required(*required_roles, client="hr-app"):
    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            user = session.get("user", {})
            realm_roles = user.get("realm_access", {}).get("roles", [])
            client_roles = user.get("resource_access", {}).get(client, {}).get("roles", [])
            all_roles = set(realm_roles + client_roles)
            if not any(role in all_roles for role in required_roles):
                return "403 Forbidden: Access denied", 403
            return f(*args, **kwargs)
        return decorated
    return decorator

# UI Template
BASE_TEMPLATE = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Keycloak Flask Demo</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
</head>
<body>
    <nav class="navbar navbar-expand-lg navbar-light bg-light mb-4">
        <div class="container-fluid">
            <a class="navbar-brand" href="/">Flask App</a>
            {% if user %}
            <span class="navbar-text me-3">
                Hello, {{ user['preferred_username'] }}
            </span>
            <form action="{{ url_for('logout') }}" method="post">
                <button class="btn btn-outline-danger">Logout</button>
            </form>
            {% else %}
            <form action="{{ url_for('login') }}" method="post">
                <button class="btn btn-outline-primary">Login</button>
            </form>
            {% endif %}
        </div>
    </nav>
    <div class="container">
        {% block content %}{% endblock %}
    </div>
</body>
</html>
'''

@app.route("/")
def index():
    user = session.get("user")

    if user:
        content = '''   
        <div class="btn-group mb-4" role="group">
        <a href="{{ url_for('admin') }}" class="btn btn-outline-primary">For Admin Page</a>
        <a href="{{ url_for('user') }}" class="btn btn-outline-success">For User Page</a>
        <a href="{{ url_for('employee') }}" class="btn btn-outline-success">For Employee Page</a>
        <a href="{{ url_for('access') }}" class="btn btn-outline-info">Access Roles</a>
        </div>
        <h1 class="mb-4">Welcome, {{ user['preferred_username'] }}</h1>

        <div class="mb-4">
            <h4>Access Token (Debug)</h4>
            <pre class="bg-light border p-3 rounded">{{ user | tojson(indent=2) }}</pre>
        </div>


        '''
    else:
        content = '''
        <div class="text-center">
            <h1>Welcome to the Keycloak Flask Demo</h1>
            <p>Please log in to access the protected routes.</p>
        </div>
        '''

    return render_template_string(BASE_TEMPLATE.replace("{% block content %}{% endblock %}", content), user=user)

@app.route("/admin")
@login_required
@role_required("hr_admin")
def admin():
    content = '''
    <div class="alert alert-primary"><strong>Admin Dashboard:</strong> Only users with the admin role can see this.</div>
    '''
    return render_template_string(BASE_TEMPLATE.replace("{% block content %}{% endblock %}", content), user=session.get("user"))

@app.route("/user")
@login_required
@role_required("hr_user")
def user():
    content = '''
    <div class="alert alert-success"><strong>User Page:</strong> Only users with the user role can see this.</div>
    '''
    return render_template_string(BASE_TEMPLATE.replace("{% block content %}{% endblock %}", content), user=session.get("user"))


@app.route("/employee")
@login_required
@role_required("employee")  
def employee():
    content = '''
    <div class="alert alert-success"><strong>User Page:</strong> Any employee with the user role can see this.</div>
    '''
    return render_template_string(BASE_TEMPLATE.replace("{% block content %}{% endblock %}", content), user=session.get("user"))

@app.route("/userinfo")
@login_required
def userinfo():
    user = session.get("user")
    content = '''
    <h2>User Info Debug</h2>
    <pre class="bg-light border p-3">{{ user | tojson(indent=2) }}</pre>
    '''
    return render_template_string(BASE_TEMPLATE.replace("{% block content %}{% endblock %}", content), user=user)

@app.route("/access")
@login_required
def access():
    user = session.get("user")
    roles = user.get("realm_access", {}).get("roles", [])
    content = '''
    <h2>Access Overview</h2>
    <ul class="list-group">
        {% for role in roles %}
        <li class="list-group-item">{{ role }}</li>
        {% endfor %}
    </ul>
    '''
    return render_template_string(BASE_TEMPLATE.replace("{% block content %}{% endblock %}", content), user=user, roles=roles)

@app.route("/login", methods=["POST"])
def login():
    nonce = uuid.uuid4().hex
    session["nonce"] = nonce
    redirect_uri = url_for("auth", _external=True)
    return oauth.keycloak.authorize_redirect(redirect_uri, nonce=nonce)

@app.route("/auth")
def auth():
    token = oauth.keycloak.authorize_access_token()
    id_token = oauth.keycloak.parse_id_token(token, nonce=session.get("nonce"))
    access_token = token.get("access_token")
    access_claims = jwt_decode(access_token, options={"verify_signature": False})
    session["user"] = access_claims
    session["userinfo"] = id_token  # Optional if you want user info too
    print("Realm Roles:", access_claims.get("realm_access", {}).get("roles"))
    print("Client Roles:", access_claims.get("resource_access", {}).get("flask-app", {}).get("roles"))
    return redirect(url_for("index"))

@app.route("/logout", methods=["POST"])
def logout():
    session.pop("user", None)
    logout_url = f"{os.getenv('KEYCLOAK_LOGOUT_URL')}?redirect_uri={url_for('index', _external=True)}"
    return redirect(logout_url)

if __name__ == "__main__":
    app.run(debug=True)
