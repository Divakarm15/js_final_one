"""
flask_example.py
================
Shows EVERY common vulnerable pattern and its fix side-by-side.
Drop xss_protection.py next to this file and run it.

    pip install flask bleach
    python flask_example.py
"""

from flask import Flask, request, render_template_string
from xss_protection import init_flask_protection, sanitize, sanitize_url, escape_output

app = Flask(__name__)
init_flask_protection(app)   # ← one line, all headers + Jinja2 helpers set up


# ─────────────────────────────────────────────────────────────────────────────
# PATTERN 1: URL parameter reflected on page
# ─────────────────────────────────────────────────────────────────────────────
# Vulnerable URL: /search?q=<script>alert(1)</script>

@app.route("/search")
def search():
    # ❌ VULNERABLE
    # q = request.args.get('q', '')
    # return f"<p>Results for: {q}</p>"

    # ✅ FIXED — sanitize input, Jinja2 auto-escapes on output
    q = sanitize(request.args.get('q', ''))

    return render_template_string("""
        <h2>Results for: {{ q }}</h2>
    """, q=q)
    # Jinja2 {{ q }} auto-escapes — even if sanitize() missed something,
    # the template layer catches it as a second line of defence.


# ─────────────────────────────────────────────────────────────────────────────
# PATTERN 2: Form input reflected back (e.g. validation error)
# ─────────────────────────────────────────────────────────────────────────────

@app.route("/register", methods=["GET", "POST"])
def register():
    error = ""
    name  = ""

    if request.method == "POST":
        # ❌ VULNERABLE
        # name = request.form['name']
        # if len(name) < 2:
        #     error = f"Name '{name}' is too short"   ← name goes straight into HTML

        # ✅ FIXED — sanitize BEFORE doing anything with the value
        name = sanitize(request.form.get('name', ''))
        email = sanitize(request.form.get('email', ''))

        if len(name) < 2:
            error = f"Name '{escape_output(name)}' is too short"
            # escape_output() is redundant here because sanitize() already
            # stripped tags — but it's good defence-in-depth.

    return render_template_string("""
        <form method="post">
          {% if error %}<p style="color:red">{{ error }}</p>{% endif %}
          <input name="name"  value="{{ name }}"  placeholder="Your name">
          <input name="email" value="{{ email }}" placeholder="Email">
          <button type="submit">Register</button>
        </form>
    """, error=error, name=name, email=email)
    # {{ error }}, {{ name }}, {{ email }} — all auto-escaped by Jinja2


# ─────────────────────────────────────────────────────────────────────────────
# PATTERN 3: User content stored in DB and rendered (stored XSS)
# ─────────────────────────────────────────────────────────────────────────────

comments_db = []  # pretend this is your database

@app.route("/comments", methods=["GET", "POST"])
def comments():
    if request.method == "POST":
        # ❌ VULNERABLE — stored XSS
        # comments_db.append(request.form['comment'])

        # ✅ FIXED — sanitize BEFORE storing in database
        # Use allow_html=True only if you want bold/links in comments
        # Use allow_html=False (default) for plain text only
        comment = sanitize(request.form.get('comment', ''), allow_html=False)
        author  = sanitize(request.form.get('author', 'Anonymous'))

        comments_db.append({'text': comment, 'author': author})

    return render_template_string("""
        <form method="post">
          <input  name="author"  placeholder="Name">
          <textarea name="comment" placeholder="Comment"></textarea>
          <button type="submit">Post</button>
        </form>
        <hr>
        {% for c in comments %}
          <p><strong>{{ c.author }}</strong>: {{ c.text }}</p>
        {% endfor %}
    """, comments=comments_db)


# ─────────────────────────────────────────────────────────────────────────────
# PATTERN 4: Redirect / open redirect with user-supplied URL
# ─────────────────────────────────────────────────────────────────────────────

from flask import redirect

@app.route("/go")
def go():
    url = request.args.get('url', '/')

    # ❌ VULNERABLE — allows javascript:alert(1) as a redirect
    # return redirect(url)

    # ✅ FIXED — sanitize_url() blocks javascript:, data:, vbscript:
    safe = sanitize_url(url)
    return redirect(safe)


# ─────────────────────────────────────────────────────────────────────────────
# PATTERN 5: Rich text / bio — allow *some* HTML but strip dangerous bits
# ─────────────────────────────────────────────────────────────────────────────

@app.route("/profile", methods=["GET", "POST"])
def profile():
    bio = ""
    if request.method == "POST":
        # allow_html=True → keeps <b>, <i>, <a href="...">, <p>, etc.
        # but strips <script>, onclick=, javascript: href, etc.
        bio = sanitize(request.form.get('bio', ''), allow_html=True)

    return render_template_string("""
        <form method="post">
          <textarea name="bio" placeholder="Your bio (HTML allowed)"></textarea>
          <button type="submit">Save</button>
        </form>
        {% if bio %}
          <div>
            {# ⚠️ The ONLY safe place to use |safe is AFTER sanitize(allow_html=True) #}
            <p>{{ bio | safe }}</p>
          </div>
        {% endif %}
    """, bio=bio)


# ─────────────────────────────────────────────────────────────────────────────
# PATTERN 6: JSON API — set correct content-type
# ─────────────────────────────────────────────────────────────────────────────

from flask import jsonify

@app.route("/api/user")
def api_user():
    name = sanitize(request.args.get('name', ''))

    # ✅ jsonify() sets Content-Type: application/json automatically
    # Browsers won't render JSON as HTML, blocking reflected XSS in APIs
    return jsonify({'name': name, 'status': 'ok'})


if __name__ == "__main__":
    app.run(debug=True, port=5000)
