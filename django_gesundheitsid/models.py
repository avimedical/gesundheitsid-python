"""`StoredEntry`: the Django model backing `stores.DatabaseStore`.

Rows are short-lived session state (PAR request context, single-use authorization codes)
keyed by an opaque, unguessable string -- never anything a human is meant to browse or
hand-edit, see `admin.py`. Nothing in this app deletes expired rows on its own; that is
`purge_expired`'s job, run periodically via the `purge_expired_gesundheitsid_entries`
management command.
"""

from __future__ import annotations

import datetime

from django.db import models
from django.utils import timezone

__all__ = ["StoredEntry"]


class StoredEntry(models.Model):
    key = models.CharField(max_length=255, unique=True, db_index=True)
    value = models.BinaryField()
    expires_at = models.DateTimeField(db_index=True)

    class Meta:
        indexes = [models.Index(fields=["expires_at"])]

    def __str__(self) -> str:  # pragma: no cover -- trivial, exercised only via the admin
        return self.key

    def is_expired(self, *, now: datetime.datetime | None = None) -> bool:
        current = now if now is not None else timezone.now()
        return current >= self.expires_at

    @classmethod
    def purge_expired(cls, *, now: datetime.datetime | None = None) -> int:
        """Delete every row whose TTL has elapsed. Returns the number of rows deleted."""
        current = now if now is not None else timezone.now()
        deleted, _ = cls.objects.filter(expires_at__lte=current).delete()
        return deleted
