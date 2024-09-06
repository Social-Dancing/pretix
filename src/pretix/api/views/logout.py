import json
import logging

from django.contrib.sessions.models import Session
from pretix.api.auth.hmac import HMACAuthentication
from pretix.base.models import User
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework.permissions import BasePermission

logger = logging.getLogger(__name__)


class PublicPermission(BasePermission):
    def has_permission(self, request, view):
        return True


class LogoutView(APIView):
    authentication_classes = [HMACAuthentication]
    permission_classes = [PublicPermission]

    def post(self, request, *args, **kwargs):
        logger.info("Logout request received.")

        try:
            body_data = json.loads(request.body)
            user_email = body_data.get("email", None)
            user_id = body_data.get("id", None)

            if not user_id and not user_email:
                logger.debug("No user ID or email provided.")
                return Response(
                    {"message": "Missing data."}, status=status.HTTP_400_BAD_REQUEST
                )

            if not user_id:
                logger.debug(
                    f"No user_id provided, looking up user by email: {user_email}"
                )
                user_id = User.objects.get(email=user_email).pk
                logger.info(f"User ID found: {user_id}")

            logged_out = False
            for session in Session.objects.all():
                session_data = session.get_decoded()

                if session_data.get("_auth_user_id") == str(user_id):
                    logger.debug(f"Deleting session: {session_data}")
                    logged_out = True
                    session.delete()

            if logged_out:
                logger.info("User successfully logged out.")
                return Response(
                    {"message": "Successfully logged out."}, status=status.HTTP_200_OK
                )
            else:
                logger.info("Failed to log out user.")
                return Response(
                    {"message": "Failed to log out user."},
                    status=status.HTTP_400_BAD_REQUEST,
                )

        except json.JSONDecodeError as e:
            logger.error(f"JSON decoding error: {e}")
            return Response(
                {"message": "Invalid JSON."}, status=status.HTTP_400_BAD_REQUEST
            )
        except User.DoesNotExist:
            logger.warning(f"User with email {user_email} does not exist.")
            return Response(
                {"message": "Missing data."}, status=status.HTTP_400_BAD_REQUEST
            )
        except Exception as e:
            logger.error(f"Unexpected error during logout: {e}")
            return Response(
                {"message": "An error occurred."},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )
