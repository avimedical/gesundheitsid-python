"""App config for `django_gesundheitsid`.

`ready()` eagerly parses and validates `GESUNDHEITSID` -- see `conf.py`'s module
docstring for why a misconfigured relying party must fail at process startup rather
than at the first request that happens to touch it.
"""

from __future__ import annotations

from django.apps import AppConfig


class GesundheitsIdConfig(AppConfig):
    name = "django_gesundheitsid"
    label = "django_gesundheitsid"
    verbose_name = "GesundheitsID"
    default_auto_field = "django.db.models.BigAutoField"

    def ready(self) -> None:
        from django_gesundheitsid.conf import get_settings

        get_settings()
