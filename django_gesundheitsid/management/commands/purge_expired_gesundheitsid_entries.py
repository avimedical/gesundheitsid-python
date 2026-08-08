"""`manage.py purge_expired_gesundheitsid_entries` -- delete expired `StoredEntry` rows.

Only relevant when `GESUNDHEITSID["STORE_BACKEND"]` is `database`: `CacheStore` and
`InMemoryStore` expire entries on their own (the cache backend's own TTL, or lazy
eviction on read, respectively), but nothing prunes `StoredEntry` automatically -- run
this periodically (a cron entry, a Kubernetes CronJob, ...) or expired rows just
accumulate.
"""

from __future__ import annotations

from django.core.management.base import BaseCommand, CommandParser
from django.utils import timezone

from django_gesundheitsid.models import StoredEntry


class Command(BaseCommand):
    help = "Delete StoredEntry rows whose TTL has elapsed."

    def add_arguments(self, parser: CommandParser) -> None:
        parser.add_argument(
            "--dry-run",
            action="store_true",
            help="report how many rows would be deleted without deleting them",
        )

    def handle(self, *args: object, dry_run: bool = False, **options: object) -> None:
        if dry_run:
            count = StoredEntry.objects.filter(expires_at__lte=timezone.now()).count()
            self.stdout.write(f"{count} expired row(s) would be deleted")
            return

        deleted = StoredEntry.purge_expired()
        self.stdout.write(self.style.SUCCESS(f"deleted {deleted} expired row(s)"))
