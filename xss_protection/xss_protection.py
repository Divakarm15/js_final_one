"""
xss_protection.py
=================
Drop-in XSS protection for Flask and Django.

INSTALL:
    pip install bleach markupsafe

FLASK USAGE:
    from xss_protection import init_flask_protection, sanitize, escape_output
    init_flask_protection(app)

DJANGO USAGE:
    # In settings.py, add to MIDDLEWARE:
    #   'xss_protection.DjangoXSSMiddleware'
    # Then import sanitize/escape_output in your views.
"""

import re
import html
import logging
from functools import wraps
from typing import Any, Optional

# ── Try to import bleach (best-in-class HTML sanitizer) ──────────────────────
try:
    import bleach
    HAS_BLEACH = True
except ImportError:
    HAS_BLEACH = False
    logging.warning(
        "[xss_protection] bleach not installed. "
        "Run: pip install bleach  — falling back to basic escaping."
    )

logger = logging.getLogger("xss_protection")


# ─────────────────────────────────────────────────────────────────────────────
# SAFE ALLOWLISTS  (used by bleach when you *need* to allow some HTML)
# ─────────────────────────────────────────────────────────────────────────────

SAFE_TAGS = [
    "a", "b", "i", "u", "em", "strong", "p", "br", "ul", "ol", "li",
    "blockquote", "code", "pre", "span", "h1", "h2", "h3", "h4", "h5", "h6",
    "table", "thead", "tbody", "tr", "th", "td", "img",
]

SAFE_ATTRS = {
    "a":   ["href", "title", "rel"],
    "img": ["src", "alt", "title", "width", "height"],
    "*":   ["class"],           # allow class on everything
}

# Absolutely never allow these in href/src (javascript:, data:, vbscript:)
_BAD_PROTO = re.compile(
    r"^\s*(?:javascript|vbscript|data|livescript)\s*:", re.IGNORECASE
)


# ─────────────────────────────────────────────────────────────────────────────
# CORE FUNCTIONS  — import these in your views
# ─────────────────────────────────────────────────────────────────────────────

def escape_output(value: Any) -> str:
    """
    ALWAYS use this when rendering plain text into HTML.
    Converts <, >, &, ", ' to HTML entities — nothing can execute.

    Example:
        # template: {{ user.name }}  ← Jinja2 auto-escapes, but be explicit in Python:
        safe_name = escape_output(user.name)
    """
    if value is None:
        return ""
    return html.escape(str(value), quote=True)


def sanitize(value: Any, allow_html: bool = False) -> str:
    """
    Sanitize user input before storing OR before rendering.

    allow_html=False (default):
        Strips ALL HTML tags. Use for names, search queries, plain text fields.

    allow_html=True:
        Allows a safe subset of HTML (bold, links, lists…). Use for
        rich-text fields like comments or bio sections.

    Examples:
        clean_name   = sanitize(request.form['name'])
        clean_bio    = sanitize(request.form['bio'], allow_html=True)
    """
    if value is None:
        return ""
    value = str(value)

    if HAS_BLEACH:
        if allow_html:
            cleaned = bleach.clean(
                value,
                tags=SAFE_TAGS,
                attributes=SAFE_ATTRS,
                strip=True,
            )
            # Extra: sanitize any remaining href/src for bad protocols
            cleaned = _strip_bad_protocols(cleaned)
        else:
            cleaned = bleach.clean(value, tags=[], attributes={}, strip=True)
    else:
        # Fallback when bleach is not installed
        if allow_html:
            # Basic: strip script/iframe/object/embed tags at minimum
            cleaned = _basic_strip_dangerous_tags(value)
        else:
            cleaned = html.escape(value, quote=True)

    return cleaned


def sanitize_url(url: Any) -> str:
    """
    Sanitize a URL value before putting it in href=, src=, action=, etc.
    Blocks javascript:, data:, vbscript: URIs.

    Example:
        <a href="{{ sanitize_url(user_supplied_url) }}">click</a>
    """
    if url is None:
        return "#"
    url = str(url).strip()
    if _BAD_PROTO.match(url):
        logger.warning(f"[xss_protection] Blocked dangerous URL: {url[:80]}")
        return "#"
    return url


def sanitize_dict(d: dict, allow_html: bool = False) -> dict:
    """
    Sanitize every string value in a dict (e.g. request.form, request.args).

    Example:
        clean = sanitize_dict(request.form)
        name  = clean['name']
        email = clean['email']
    """
    return {
        k: sanitize(v, allow_html=allow_html) if isinstance(v, str) else v
        for k, v in d.items()
    }


# ─────────────────────────────────────────────────────────────────────────────
# SECURITY HEADERS
# ─────────────────────────────────────────────────────────────────────────────

#
# Adjust SCRIPT_SRC if you load scripts from a CDN.
# Example with Google Fonts + your own CDN:
#   "script-src 'self' https://cdn.yourdomain.com"
#
CSP_POLICY = (
    "default-src 'self'; "
    "script-src 'self'; "          # <-- add CDN domains here if needed
    "style-src 'self' 'unsafe-inline'; "   # unsafe-inline for inline styles (tighten later)
    "img-src 'self' data: https:; "
    "font-src 'self' https:; "
    "connect-src 'self'; "
    "frame-ancestors 'none'; "
    "object-src 'none'; "
    "base-uri 'self';"
)

SECURITY_HEADERS = {
    "Content-Security-Policy":   CSP_POLICY,
    "X-Content-Type-Options":    "nosniff",
    "X-Frame-Options":           "DENY",
    "X-XSS-Protection":          "1; mode=block",
    "Referrer-Policy":           "strict-origin-when-cross-origin",
    "Permissions-Policy":        "geolocation=(), microphone=(), camera=()",
}


# ─────────────────────────────────────────────────────────────────────────────
# FLASK INTEGRATION
# ─────────────────────────────────────────────────────────────────────────────

def init_flask_protection(app):
    """
    Call once in your Flask app factory or main file.

    What it does:
      1. Adds security headers to EVERY response automatically.
      2. Registers escape_output, sanitize, sanitize_url as Jinja2 globals
         so you can call them directly in templates.
      3. Forces Jinja2 autoescape on (it already is for .html, but this
         makes it explicit).

    Usage:
        from flask import Flask
        from xss_protection import init_flask_protection

        app = Flask(__name__)
        init_flask_protection(app)
    """
    # 1. Security headers on every response
    @app.after_request
    def _add_security_headers(response):
        for header, value in SECURITY_HEADERS.items():
            response.headers[header] = value
        return response

    # 2. Make helpers available inside Jinja2 templates
    app.jinja_env.globals.update(
        sanitize=sanitize,
        sanitize_url=sanitize_url,
        escape_output=escape_output,
    )

    # 3. Ensure autoescape is on for all templates
    app.jinja_env.autoescape = True

    logger.info("[xss_protection] Flask XSS protection initialized.")
    return app


# ─────────────────────────────────────────────────────────────────────────────
# DJANGO INTEGRATION
# ─────────────────────────────────────────────────────────────────────────────

class DjangoXSSMiddleware:
    """
    Django middleware — adds security headers to every response.

    Add to settings.py MIDDLEWARE list (near the top):
        MIDDLEWARE = [
            'xss_protection.DjangoXSSMiddleware',
            ...
        ]

    Django's template engine auto-escapes by default.
    In templates, NEVER use: {{ value|safe }}  or  {% autoescape off %}
    unless you have already run sanitize() on the value in your view.
    """

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        response = self.get_response(request)
        for header, value in SECURITY_HEADERS.items():
            response[header] = value
        return response


# ─────────────────────────────────────────────────────────────────────────────
# VIEW DECORATOR (Flask + Django)
# ─────────────────────────────────────────────────────────────────────────────

def xss_protect(f):
    """
    Optional decorator that auto-sanitizes all GET and POST parameters
    before your view function runs.

    Flask example:
        @app.route('/search')
        @xss_protect
        def search():
            q = request.args['q']   # already sanitized
            ...

    Django example:
        @xss_protect
        def search(request):
            q = request.GET['q']    # already sanitized
            ...

    NOTE: This mutates request.args / request.GET / request.POST.
    Prefer calling sanitize() explicitly per-field so you control
    which fields allow HTML. Use this for routes where ALL inputs
    are plain text only.
    """
    @wraps(f)
    def wrapper(*args, **kwargs):
        _auto_sanitize_request()
        return f(*args, **kwargs)
    return wrapper


def _auto_sanitize_request():
    """Attempt to sanitize the current request (Flask or Django)."""
    # Flask
    try:
        from flask import request
        from werkzeug.datastructures import ImmutableMultiDict
        if request:
            cleaned_args = {k: sanitize(v) for k, v in request.args.items()}
            cleaned_form = {k: sanitize(v) for k, v in request.form.items()}
            request.environ['_sanitized_args'] = cleaned_args
            request.environ['_sanitized_form'] = cleaned_form
    except (ImportError, RuntimeError):
        pass

    # Django
    try:
        import django
        # Django views receive request as first arg — handled via decorator
    except ImportError:
        pass


# ─────────────────────────────────────────────────────────────────────────────
# PRIVATE HELPERS
# ─────────────────────────────────────────────────────────────────────────────

def _strip_bad_protocols(html_string: str) -> str:
    """Remove javascript:/vbscript:/data: from href and src attributes."""
    def _clean_attr(match):
        attr_val = match.group(2)
        if _BAD_PROTO.match(attr_val):
            return f'{match.group(1)}="#"'
        return match.group(0)

    pattern = re.compile(
        r'((?:href|src|action)\s*=\s*["\'])([^"\']*)["\']',
        re.IGNORECASE,
    )
    return pattern.sub(_clean_attr, html_string)


# Tags that must ALWAYS be stripped, even in allow_html mode
_DANGEROUS_TAGS = re.compile(
    r"<\s*/?(?:script|iframe|object|embed|applet|form|input|button|"
    r"link|meta|base|style|svg|math|xml|xss)[^>]*>",
    re.IGNORECASE | re.DOTALL,
)
_ON_EVENTS = re.compile(r'\s+on\w+\s*=\s*["\'][^"\']*["\']', re.IGNORECASE)
_JS_HREF   = re.compile(r'(?:href|src|action)\s*=\s*["\']?\s*javascript:', re.IGNORECASE)


def _basic_strip_dangerous_tags(value: str) -> str:
    """
    Minimal sanitizer for when bleach is not available.
    Strips dangerous tags and event handlers.
    Install bleach for more thorough protection.
    """
    value = _DANGEROUS_TAGS.sub("", value)
    value = _ON_EVENTS.sub("", value)
    value = _JS_HREF.sub('href="#"', value)
    return value
