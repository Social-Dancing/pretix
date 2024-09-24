import logging

from django.http import JsonResponse
from rest_framework.views import APIView
from rest_framework import status
from pretix.api.auth.hmac import HMACAuthentication
from pretix.api.auth.permission import UserPermission
from pretix.base.models import User

logger = logging.getLogger(__name__)


class UserSettingsView(APIView):
    authentication_classes = [HMACAuthentication]
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
            logger.error("An error occurred saving user settings: %s", str(e))
            return JsonResponse(
                {"message": "Failed to update user settings. Please try again later."},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )
