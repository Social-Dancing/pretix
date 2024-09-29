import logging
import json

from django.conf import settings
from django.http import JsonResponse
from django.contrib.auth import logout as auth_logout, login as auth_login
from django.contrib.auth import get_backends
from rest_framework.views import APIView
from rest_framework import status
from rest_framework.permissions import BasePermission
from pretix.api.auth.socialdancing import UserAuthentication, HMACAuthentication, UserPermission
from pretix.base.auth import remove_sso_session_from_cache
from pretix.base.models import Organizer, User
from pretix.base.auth import (
    get_sso_session_cookie_key,
    get_sso_session,
)
from pretix.base.metrics import pretix_successful_logins
from pretix.api.serializers.organizer import OrganizerSettingsSerializer


logger = logging.getLogger(__name__)


class PublicPermission(BasePermission):
    def has_permission(self, request, view):
        return True


class LogoutView(APIView):
    # TODO: Avoid using `UserAuthentication` for now, as not all users will have
    # a Pretix session if they haven't accessed the ticketing platform yet.
    # Implement it after the next release.
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


class LoginView(APIView):
    authentication_classes = [HMACAuthentication, UserAuthentication]
    permission_classes = [PublicPermission]

    def post(self, request, *args, **kwargs):
        logger.debug(
            f"Login request received for user {request.user.id} ({request.user.email})")

        try:
            pretix_successful_logins.inc(1)
            backend = get_backends()[0]
            request.user.backend = f'{backend.__module__}.{backend.__class__.__name__}'
            auth_login(request, request.user, backend=request.user.backend)
            request.session['pretix_auth_long_session'] = settings.PRETIX_LONG_SESSIONS
            return JsonResponse({"message": "Successfully logged in"}, status=status.HTTP_200_OK)

        except Exception as e:
            logger.error(f"An error occurred during login: {str(e)}")
            return JsonResponse({"message": "Failed to log in user {request.user.id} ({request.user.email}). Please try again later."},
                                status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class UserSettingsView(APIView):
    authentication_classes = [HMACAuthentication, UserAuthentication]
    permission_classes = [UserPermission]

    def post(self, request, *args, **kwargs):
        fullname = request.data.get('fullname', None)
        target_id = request.data.get('targetUserId', None)

        logger.info(f"Changing user settings for user of ID {target_id}")

        if (fullname is None or target_id is None):
            logger.error("Missing values in request", extra={
                "user_data": {
                    "fullname": fullname,
                    "target_id": target_id
                }})
            return JsonResponse(
                {"message": "Failed to update user settings. Missing values."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        try:
            User.objects.filter(id=target_id).update(
                fullname=fullname)
            return JsonResponse(
                {"message": "Successfully updated user settings."}, status=status.HTTP_200_OK
            )

        except Exception as e:
            logger.error(
                "An error occurred updating user settings: %s", str(e))
            return JsonResponse(
                {"message": "Failed to update user settings. Please try again later."},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )


class OrganizerSettingsView(APIView):
    authentication_classes = [HMACAuthentication, UserAuthentication]
    permission_classes = [UserPermission]

    def post(self, request, *wargs, **kwargs):
        target_id = request.data.get('targetOrganizerId', None)
        logger.info(f"Changing user settings for user of ID {target_id}")

        try:
            Organizer.objects.filter(id=request.organizer.id).update(
                name=request.data.get('name', None))

            s = OrganizerSettingsSerializer(
                instance=request.organizer.settings, data=request.data, partial=True,
                organizer=request.organizer, context={
                    'request': request
                }
            )
            s.update(instance=request.organizer.settings, validated_data={
                'contact_mail': request.data.get('emailContact', None),
            })

            return JsonResponse(
                {"message": "Successfully updated organizer settings."}, status=status.HTTP_200_OK
            )
        except Exception as e:
            logger.error(
                "An error occurred updating organizer settings: %s", str(e))
            return JsonResponse(
                {"message": "Failed to update organizer settings. Please try again later."},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )


class CreateUser(APIView):
    authentication_classes = [HMACAuthentication]
    permission_classes = [PublicPermission]

    def post(self, request, *args, **kwargs):
        logger.debug("Creating new user.")
        cookie_key = get_sso_session_cookie_key(request)
        sso_token = request.COOKIES.get(cookie_key)

        if not sso_token:
            logger.debug("No SSO session token found. Not creating user.")
            return JsonResponse(
                {"message": "Failed to create user."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        sso_session_data = get_sso_session(request)
        if not sso_session_data:
            logger.debug("No SSO session data found. Not creating user.")
            return JsonResponse(
                {"message": "Failed to create user."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        user_email = sso_session_data.get("user", {}).get("email")
        if not user_email:
            logger.debug("No SSO related email found. Not creating user.")
            return JsonResponse(
                {"message": "Failed to create user."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        try:
            body_data = json.loads(request.body)
            # The password will not be used, as authentication will be handled
            # through Social Dancing.
            user = User.objects.create_user(
                email=user_email, password=User.objects.make_random_password(),
                fullname=body_data.get('name')
            )
            return JsonResponse(
                {"message": "Successfully created user in the Pretix system.", "pretixId": user.id}, status=status.HTTP_200_OK
            )

        except Exception as e:
            logger.error(
                "An error occurred creating a user: %s", str(e))
            return JsonResponse(
                {"message": "Failed to create user."},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )
