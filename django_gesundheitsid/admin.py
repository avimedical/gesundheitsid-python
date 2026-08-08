"""Read-only admin for `StoredEntry`.

These rows are short-lived, opaque session state (PAR context, single-use authorization
codes) generated and consumed entirely by `views.py` and `stores.DatabaseStore` -- adding,
editing, or hand-deleting one is never a legitimate operation, and could quietly break an
in-flight login for whoever's `state`/code it belongs to. The admin exists purely so an
operator can see what is currently stored (e.g. while debugging a stuck flow); routine
cleanup of expired rows is `StoredEntry.purge_expired` / the
`purge_expired_gesundheitsid_entries` management command, not a manual admin deletion.
"""

from __future__ import annotations

from django.contrib import admin
from django.http import HttpRequest

from django_gesundheitsid.models import StoredEntry


@admin.register(StoredEntry)
class StoredEntryAdmin(admin.ModelAdmin):
    list_display = ("key", "expires_at")
    readonly_fields = ("key", "value", "expires_at")
    search_fields = ("key",)
    ordering = ("-expires_at",)

    def has_add_permission(self, request: HttpRequest) -> bool:
        return False

    def has_change_permission(self, request: HttpRequest, obj: StoredEntry | None = None) -> bool:
        return False

    def has_delete_permission(self, request: HttpRequest, obj: StoredEntry | None = None) -> bool:
        return False
