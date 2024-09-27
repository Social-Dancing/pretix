import logging

from django.http import JsonResponse
from django.contrib.auth import logout as auth_logout
from rest_framework.views import APIView
from rest_framework import status
from rest_framework.permissions import BasePermission
from pretix.api.auth.socialdancing import UserAuthentication, HMACAuthentication, UserPermission
from pretix.base.auth import remove_sso_session_from_cache
from pretix.base.models import Organizer, User
from pretix.api.serializers.organizer import OrganizerSettingsSerializer


logger = logging.getLogger(__name__)


class PublicPermission(BasePermission):
    def has_permission(self, request, view):
        return True


class LogoutView(APIView):
    authentication_classes = [HMACAuthentication, UserAuthentication]
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
