"""Root urlconf for `local_federation_settings`'s live dev server -- see that module's
docstring. Deliberately does not pull in `django.contrib.admin` the way
`tests/django/urls.py` does: this process exists only to serve
`.well-known/openid-federation` (and the rest of `django_gesundheitsid`'s routes) to
`gsi-server`, not to be a real application.
"""

from __future__ import annotations

from django.urls import include, path

urlpatterns = [
    path("", include("django_gesundheitsid.urls")),
]
