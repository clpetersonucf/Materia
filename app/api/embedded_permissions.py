"""Default-deny capabilities for launch-scoped bearer grants.

Add each route/method explicitly, with its purposes and scope predicate, and test
both admission and rejection. View-level object permissions still apply.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from api.authentication import EmbeddedGrant
    from rest_framework.request import Request


def launch_scope(grant, request):
    return True


def bound_instance(grant, request):
    return request.resolver_match.kwargs.get("pk") == grant.instance_id


def initializing_instance(grant, request):
    return request.data.get("instanceId") == grant.instance_id


def own_score_history(grant, request):
    return (
        request.query_params.get("inst_id") == grant.instance_id
        and request.query_params.get("user") == str(grant.user_id)
        and request.query_params.get("context") == grant.context_id
    )


def _owns_play(grant, play_id):
    return bool(play_id) and grant.plays().filter(pk=play_id).exists()


def bound_play(grant, request):
    return not {
        "previewInstanceId",
        "previewPlayId",
    } & request.data.keys() and _owns_play(
        grant, request.resolver_match.kwargs.get("pk")
    )


def score_details(grant, request):
    return "preview_inst_id" not in request.query_params and _owns_play(
        grant, request.query_params.get("play_id")
    )


def storage_write(grant, request):
    return _owns_play(grant, request.data.get("play_id"))


def storage_read(grant, request):
    play_id = request.query_params.get("play_id")
    if not play_id:
        return request.query_params.get("inst_id") == grant.instance_id
    return _owns_play(grant, play_id)


@dataclass(frozen=True)
class Rule:
    purposes: frozenset[str]
    scope: Callable[[EmbeddedGrant, Request], bool]


PLAYER = frozenset({"player"})
SCORES = frozenset({"scores"})
DEEP_LINK = frozenset({"deep-link"})
ALL_PURPOSES = (
    PLAYER | SCORES | DEEP_LINK | {"course-navigation", "instructor-resource"}
)

EMBEDDED_RULES = {
    ("embedded-context", "GET"): Rule(ALL_PURPOSES, launch_scope),
    ("embedded-deep-link-instances", "GET"): Rule(DEEP_LINK, launch_scope),
    ("embedded-deep-link-selection", "POST"): Rule(DEEP_LINK, launch_scope),
    ("embedded-scores", "GET"): Rule(SCORES, launch_scope),
    ("embedded-score-resubmit", "POST"): Rule(SCORES, launch_scope),
    ("instances-detail", "GET"): Rule(PLAYER | SCORES, bound_instance),
    ("instances-performance", "GET"): Rule(PLAYER | SCORES, bound_instance),
    ("instances-question-sets", "GET"): Rule(PLAYER, bound_instance),
    ("sitemessage-list", "GET"): Rule(PLAYER, launch_scope),
    ("embedded-play", "POST"): Rule(PLAYER, initializing_instance),
    ("scores-history", "GET"): Rule(PLAYER, own_score_history),
    ("logplay-detail", "PUT"): Rule(PLAYER, bound_play),
    ("logplay-verify", "GET"): Rule(PLAYER, bound_play),
    ("logplay-resubmit", "POST"): Rule(PLAYER, bound_play),
    ("scores-details", "GET"): Rule(PLAYER, score_details),
    ("logstorage-list", "POST"): Rule(PLAYER, storage_write),
    ("logstorage-list", "GET"): Rule(PLAYER, storage_read),
}
