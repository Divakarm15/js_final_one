"""
django_example.py
=================
Django-specific XSS fixes. Shows every common vulnerable pattern.

SETUP:
1. Copy xss_protection.py to your project root (or any importable location)
2. In settings.py:
       MIDDLEWARE = [
           'xss_protection.DjangoXSSMiddleware',   # ← add this line
           'django.middleware.security.SecurityMiddleware',
           ...
       ]
3. In settings.py, verify these are set (they are by default, don't disable them):
       # These enable Django's built-in XSS / security features
       SECURE_BROWSER_XSS_FILTER = True
       SECURE_CONTENT_TYPE_NOSNIFF = True
       X_FRAME_OPTIONS = 'DENY'

4. In views.py:
       from xss_protection import sanitize, sanitize_url, escape_output
"""

# ── settings.py additions ─────────────────────────────────────────────────────

SETTINGS_ADDITIONS = """
# --- Add to settings.py ---

MIDDLEWARE = [
    'xss_protection.DjangoXSSMiddleware',      # XSS security headers
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',  # NEVER remove this
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
]

# Django's template engine auto-escapes everything by default.
# Make sure TEMPLATES uses the default Django backend:
TEMPLATES = [{
    'BACKEND': 'django.template.backends.django.DjangoTemplates',
    'OPTIONS': {
        'context_processors': [...],
        # autoescape is True by default — do NOT set it to False
    },
}]

# Additional hardening
SECURE_BROWSER_XSS_FILTER   = True
SECURE_CONTENT_TYPE_NOSNIFF = True
X_FRAME_OPTIONS              = 'DENY'
SESSION_COOKIE_HTTPONLY      = True
SESSION_COOKIE_SAMESITE      = 'Lax'
CSRF_COOKIE_HTTPONLY         = True
"""


# ── views.py ──────────────────────────────────────────────────────────────────

VIEWS_EXAMPLE = """
# views.py

from django.shortcuts import render, redirect
from django.http import JsonResponse
from xss_protection import sanitize, sanitize_url, escape_output


# ─────────────────────────────────────────────────────────────────────────────
# PATTERN 1: URL parameter reflected on page
# ─────────────────────────────────────────────────────────────────────────────

def search(request):
    # ❌ VULNERABLE
    # q = request.GET.get('q', '')
    # return HttpResponse(f"<p>Results for: {q}</p>")

    # ✅ FIXED
    q = sanitize(request.GET.get('q', ''))
    return render(request, 'search.html', {'query': q})
    # In search.html: {{ query }}   ← Django auto-escapes this


# ─────────────────────────────────────────────────────────────────────────────
# PATTERN 2: Form with validation error reflected back
# ─────────────────────────────────────────────────────────────────────────────

def register(request):
    error = ''
    name  = ''

    if request.method == 'POST':
        # ❌ VULNERABLE
        # name = request.POST['name']
        # if len(name) < 2:
        #     error = f"Name '{name}' is too short"

        # ✅ FIXED — sanitize first, then use
        name  = sanitize(request.POST.get('name', ''))
        email = sanitize(request.POST.get('email', ''))

        if len(name) < 2:
            error = f"Name '{name}' is too short"
            # name is already sanitized; Django auto-escapes {{ error }} in template

    return render(request, 'register.html', {
        'error': error,
        'name':  name,
        'email': email,
    })


# ─────────────────────────────────────────────────────────────────────────────
# PATTERN 3: User content stored in DB (stored XSS)
# ─────────────────────────────────────────────────────────────────────────────

def post_comment(request):
    if request.method == 'POST':
        # ❌ VULNERABLE — storing raw user HTML in the database
        # Comment.objects.create(
        #     text   = request.POST['comment'],
        #     author = request.POST['author'],
        # )

        # ✅ FIXED — sanitize BEFORE saving to DB
        Comment.objects.create(
            text   = sanitize(request.POST.get('comment', ''), allow_html=False),
            author = sanitize(request.POST.get('author', 'Anonymous')),
        )

    comments = Comment.objects.all()
    return render(request, 'comments.html', {'comments': comments})
    # In comments.html: {{ comment.text }}   ← auto-escaped, safe


# ─────────────────────────────────────────────────────────────────────────────
# PATTERN 4: Open redirect
# ─────────────────────────────────────────────────────────────────────────────

def go(request):
    url = request.GET.get('url', '/')

    # ❌ VULNERABLE — javascript:alert(1) works as a redirect target
    # return redirect(url)

    # ✅ FIXED
    safe = sanitize_url(url)
    return redirect(safe)


# ─────────────────────────────────────────────────────────────────────────────
# PATTERN 5: JSON API response
# ─────────────────────────────────────────────────────────────────────────────

def api_user(request):
    name = sanitize(request.GET.get('name', ''))

    # ✅ JsonResponse sets Content-Type: application/json automatically
    # Browsers won't execute scripts inside a JSON response
    return JsonResponse({'name': name, 'status': 'ok'})
"""


# ── templates — rules ─────────────────────────────────────────────────────────

TEMPLATE_RULES = """
# Django template rules
# ─────────────────────────────────────────────────────────────────────────────

SAFE (Django auto-escapes these):
    {{ user.name }}
    {{ search_query }}
    {{ error_message }}

DANGEROUS — only use after sanitize(allow_html=True) in your view:
    {{ bio | safe }}       ← only safe if you called sanitize(bio, allow_html=True)

NEVER do this:
    {{ request.GET.name | safe }}    ← raw user input with |safe = XSS
    {% autoescape off %}             ← turns off ALL escaping

URL tags — Django escapes these automatically in href too:
    <a href="{% url 'profile' user.id %}">         ← safe (Django URL)
    <a href="{{ user_supplied_url }}">              ← only safe after sanitize_url()
"""

if __name__ == '__main__':
    print(SETTINGS_ADDITIONS)
    print(VIEWS_EXAMPLE)
    print(TEMPLATE_RULES)
