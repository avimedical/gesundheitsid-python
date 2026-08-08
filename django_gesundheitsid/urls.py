"""URL routes for the GesundheitsID relying party: the federation-facing entity
statement/idp-list endpoints, the downstream authorization<->callback pair, and this
relying party's own downstream OIDC provider face.

`app_name` is set so `reverse("django_gesundheitsid:token")` etc. resolve regardless of
where a project mounts this urlconf -- see `views.openid_configuration`/`views.token`,
which build absolute URLs from these names rather than hardcoding paths.
"""

from __future__ import annotations

from django.urls import path

from django_gesundheitsid import views

app_name = "django_gesundheitsid"

urlpatterns = [
    path(".well-known/openid-federation", views.entity_statement, name="entity-statement"),
    path("api/v1/idps", views.idps, name="idps"),
    path("auth", views.auth, name="auth"),
    path("auth/callback", views.auth_callback, name="auth-callback"),
    path(".well-known/openid-configuration", views.openid_configuration, name="openid-configuration"),
    path("auth/token", views.token, name="token"),
    path("jwks.json", views.jwks, name="jwks"),
]
