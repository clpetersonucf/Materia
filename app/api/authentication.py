import hashlib
import re
import secrets
from dataclasses import dataclass
from collections.abc import Mapping

import logging

from core.models import LogPlay, WidgetInstance
from django.conf import settings
from django.contrib.auth.models import User
from django.core.cache import cache
from lti_tool.models import LtiDeployment
from rest_framework.authentication import BaseAuthentication, get_authorization_header
from rest_framework.exceptions import AuthenticationFailed, PermissionDenied

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class EmbeddedGrant:
    user_id: int
    instance_id: str | None
    deployment_id: int
    launch_data: dict
    purpose: str = "player"
    play_id: str | None = None
    provisional_access: bool = False

    @property
    def context_id(self):
        return self.launch_data.get(
            "https://purl.imsglobal.org/spec/lti/claim/context", {}
        ).get("id", "")

    def plays(self):
        return LogPlay.objects.filter(
            user_id=self.user_id,
            instance_id=self.instance_id,
            context_id=self.context_id,
            lti_play_state__lti_association__deployment_id=self.deployment_id,
            lti_play_state__lti_association__resource_link=self.launch_data[
                "https://purl.imsglobal.org/spec/lti/claim/resource_link"
            ]["id"],
        )

    def authorize(self, request):
        """
        Only certain endpoints are authorized in embedded contexts with a grant token.
        Ensures the path, method, and associated params are valid.
        """
        if not isinstance(request.data, Mapping):
            raise PermissionDenied("Invalid embedded request body.")

        route = request.resolver_match.url_name

        embedded_routes = {
            "embedded-context": (
                "GET",
                {
                    "player",
                    "course-navigation",
                    "deep-link",
                    "instructor-resource",
                    "scores",
                },
            ),
            "embedded-deep-link-instances": ("GET", {"deep-link"}),
            "embedded-deep-link-selection": ("POST", {"deep-link"}),
            "embedded-scores": ("GET", {"scores"}),
            "embedded-score-resubmit": ("POST", {"scores"}),
        }

        if route in embedded_routes:
            method, purposes = embedded_routes[route]
            if request.method == method and self.purpose in purposes:
                return

        if self.purpose != "player":
            if (
                self.purpose == "scores"
                and request.method == "GET"
                and route in {"instances-detail", "instances-performance"}
                and request.resolver_match.kwargs.get("pk") == self.instance_id
            ):
                return
            raise PermissionDenied("This embedded launch does not allow that request.")

        path = request.path
        method = request.method
        instance_path = f"/api/instances/{self.instance_id}/"

        if method == "GET" and path in (
            instance_path,
            instance_path + "question_sets/",
            instance_path + "performance/",
            "/api/site-messages/",
        ):
            return

        if method == "POST" and path == "/api/embedded/play/":
            if request.data.get("instanceId") == self.instance_id:
                return

        if method == "GET" and path == "/api/scores/":
            if (
                request.query_params.get("inst_id") == self.instance_id
                and request.query_params.get("user") == str(self.user_id)
                and request.query_params.get("context") == self.context_id
            ):
                return

        play_id = None
        match = re.fullmatch(r"/api/play-sessions/([^/]+)/(verify/|resubmit/)?", path)
        if match:
            action = match.group(2)
            if (method, action) in (
                ("PUT", None),
                ("GET", "verify/"),
                ("POST", "resubmit/"),
            ):
                if not {"previewInstanceId", "previewPlayId"} & request.data.keys():
                    play_id = match.group(1)

        elif method == "GET" and path == "/api/scores/details/":
            if "preview_inst_id" not in request.query_params:
                play_id = request.query_params.get("play_id")

        elif path == "/api/storage/":
            if method == "POST":
                play_id = request.data.get("play_id")
            elif method == "GET":
                play_id = request.query_params.get("play_id")
                if (
                    not play_id
                    and request.query_params.get("inst_id") == self.instance_id
                ):
                    return
        if play_id and self.plays().filter(pk=play_id).exists():
            return
        raise PermissionDenied("This embedded launch does not allow that request.")


def _grant_key(token):
    digest = hashlib.sha256(token.encode("ascii")).hexdigest()
    return f"embedded-auth:{digest}"


def issue_embedded_token(
    user,
    instance,
    lti_launch,
    *,
    purpose="player",
    play_id=None,
    provisional_access=False,
):
    grant = EmbeddedGrant(
        user_id=user.pk,
        instance_id=instance.pk if instance else None,
        deployment_id=lti_launch.deployment.pk,
        launch_data=lti_launch.get_launch_data(),
        purpose=purpose,
        play_id=play_id,
        provisional_access=provisional_access,
    )
    token = secrets.token_urlsafe(32)
    cache.set(_grant_key(token), grant, timeout=settings.EMBEDDED_AUTH_TOKEN_TTL)
    if cache.get(_grant_key(token)) != grant:
        raise AuthenticationFailed("Embedded authentication storage is unavailable.")
    return token


class EmbeddedBearerAuthentication(BaseAuthentication):
    def authenticate_header(self, request):
        if get_authorization_header(request).lower().startswith(
            b"bearer"
        ) or request.path.startswith("/api/embedded/"):
            return "Bearer"
        return None

    def authenticate(self, request):
        header = get_authorization_header(request).split()

        if not header or header[0].lower() != b"bearer":
            return None
        if not settings.EMBEDDED_AUTH_ENABLED or len(header) != 2:
            raise AuthenticationFailed("Invalid embedded credential.")

        try:
            token = header[1].decode("ascii")
        except UnicodeDecodeError as exc:
            raise AuthenticationFailed("Invalid embedded credential.") from exc

        grant = cache.get(_grant_key(token))
        if not isinstance(grant, EmbeddedGrant):
            raise AuthenticationFailed("This session expired. Relaunch from your LMS.")

        user = User.objects.filter(pk=grant.user_id, is_active=True).first()

        if (
            user is None
            or not LtiDeployment.objects.filter(
                pk=grant.deployment_id, is_active=True, registration__is_active=True
            ).exists()
            or (
                grant.instance_id is not None
                and not WidgetInstance.objects.filter(
                    pk=grant.instance_id, guest_access=False, is_deleted=False
                ).exists()
            )
        ):
            raise AuthenticationFailed("This launch is no longer available.")

        grant.authorize(request)

        return user, grant
