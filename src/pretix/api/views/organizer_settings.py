import logging

from django.http import JsonResponse
from rest_framework.views import APIView
from rest_framework import status
from pretix.api.auth.hmac import HMACAuthentication
from pretix.api.auth.permission import UserPermission
from pretix.base.models import Organizer
from pretix.api.serializers.organizer import OrganizerSettingsSerializer


logger = logging.getLogger(__name__)


class OrganizerSettingsView(APIView):
    authentication_classes = [HMACAuthentication]
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
