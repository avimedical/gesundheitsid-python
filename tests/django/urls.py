"""Root urlconf for the `django_gesundheitsid` test suite."""

from __future__ import annotations

from django.contrib import admin
from django.urls import include, path

urlpatterns = [
    path("admin/", admin.site.urls),
    path("", include("django_gesundheitsid.urls")),
]
