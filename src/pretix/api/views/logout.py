import logging

from django.core.cache import cache
from django.http import JsonResponse
from django.contrib.auth import logout as auth_logout
from rest_framework.views import APIView
from rest_framework import status
from rest_framework.permissions import BasePermission
from pretix.api.auth.hmac import HMACAuthentication
from pretix.base.auth import remove_sso_session_from_cache

logger = logging.getLogger(__name__)


class PublicPermission(BasePermission):
    def has_permission(self, request, view):
        return True


class LogoutView(APIView):
    authentication_classes = [HMACAuthentication]
    permission_classes = [PublicPermission]

    def post(self, request, *args, **kwargs):
        session_key = request.session.session_key
        logger.info(f"Logout request received for session {session_key}")

        try:
            auth_logout(request)
            remove_sso_session_from_cache(request)

            return JsonResponse(
                {"message": "Successfully logged out."}, status=status.HTTP_200_OK
            )
        except Exception as e:
            logger.error("An error occurred during logout: %s", str(e))
            return JsonResponse(
                {"message": "Failed to log out. Please try again later."},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )
