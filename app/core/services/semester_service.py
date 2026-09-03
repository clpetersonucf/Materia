from core.models import DateRange, LogPlay
from django.core.cache import cache
from django.utils import timezone


class SemesterService:
    @staticmethod
    def get_current_semester() -> DateRange:
        # Check cache
        cached_result = cache.get("current-semester")
        if cached_result is not None:
            return cached_result

        # Find current semester by current time
        now = timezone.now()
        cur_semester = DateRange.objects.filter(
            start_at__lt=now, end_at__gt=now
        ).first()
        if cur_semester is None:
            raise Exception(
                "No current semester found! Please ensure a semester exists for the current time."
            )

        # Cache it and return
        cache.set("current-semester", cur_semester, 86400)  # cache for 24hrs
        return cur_semester

    def get_semester_by_id(id) -> DateRange:

        cached_result = cache.get(f"semester-{id}")
        if cached_result is not None:
            return cached_result

        semester = DateRange.objects.filter(pk=id).first()

        if semester is not None:
            cache.set(f"semester-{id}", semester, 86400)

        return semester

    @staticmethod
    def find_nearest_semester_with_logs(
        instance, ordered_semesters
    ) -> DateRange | None:
        # semesters are few, so checking them in the given order and stopping at the first
        # indexed exists() hit avoids scanning the much larger log_play table
        for candidate in ordered_semesters:
            if LogPlay.objects.filter(
                instance=instance, semester_id=candidate.id
            ).exists():
                return candidate

        return None
