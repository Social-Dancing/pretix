import hmac
import hashlib
import logging

from django.conf import settings
from django.core.exceptions import ObjectDoesNotExist
from rest_framework.authentication import BaseAuthentication
from rest_framework.exceptions import AuthenticationFailed
from rest_framework.permissions import BasePermission
from pretix.base.models import User, Organizer


logger = logging.getLogger(__name__)


class HMACAuthentication(BaseAuthentication):
    def authenticate(self, request):
        logger.debug("Authenticating via HMAC signature...")

        # Get the HMAC signature from the request headers.
        signature = request.headers.get("X-Signature")
        if not signature:
            logger.warning("Missing HMAC signature")
            raise AuthenticationFailed("Missing signature")

        try:
            body = request.body.decode("utf-8")
        except UnicodeDecodeError:
            raise AuthenticationFailed("Invalid body encoding")

        # Calculate the HMAC of the request body using the secret key.
        secret = settings.DJANGO_HMAC_SECRET_KEY.encode("utf-8")
        expected_signature = hmac.new(
            secret, body.encode("utf-8"), hashlib.sha256
        ).hexdigest()

        # Verify the signature.
        if not hmac.compare_digest(expected_signature, signature):
            logger.warning("Invalid HMAC signature")
            raise AuthenticationFailed("Invalid signature")

        # The method of an authentication class must return a tuple (user, auth)
        # or None. IMPORTANT: Returning None here allows subsequent
        # authentication methods in the authentication chain to be executed.
        return None


class UserAuthentication(BaseAuthentication):
    def authenticate(self, request):
        logger.debug("Authenticating user...")

        user_id = request.session.get('_auth_user_id')
        if not user_id:
            logger.warning("No '_auth_user_id' found in session.")
            raise AuthenticationFailed("User not authenticated.")

        try:
            user = User.objects.get(id=user_id)
            # The method of an authentication class must return a tuple (user,
            # auth) or None.
            return (user, None)

        except ObjectDoesNotExist:
            logger.warning(
                f"UserPermission: Invalid user_id {user_id}. User does not exist.")
            raise AuthenticationFailed("User not found.")


class UserPermission(BasePermission):
    """
    Custom permission class tailored for specific Social Dancing API endpoints.
    This permission verifies that the user making the request is the intended
    target of the action or has the necessary permissions on the target
    organizer.
    """

    def has_permission(self, request, view):
        user_id = request.user.id
        target_user_id = request.data.get('targetUserId')
        target_organizer_id = request.data.get('targetOrganizerId')

        if not target_user_id and not target_organizer_id:
            logger.debug("No target IDs found in request body.")
            return False

        if target_user_id and str(user_id) != str(target_user_id):
            logger.warning(
                f"User ID {user_id} in session does not match target ID {target_user_id} in request body.")
            return False

        try:
            organizer = Organizer.objects.get(
                id=target_organizer_id) if target_organizer_id else None
            request.organizer = organizer
        except ObjectDoesNotExist:
            logger.warning(
                f"UserPermission: Invalid organizer_id {target_organizer_id}. Organizer does not exist.")
            return False

        if request.organizer and not request.organizer.user_can_modify_settings(request.user):
            logger.warning(
                f"User of ID {user_id} does not have permission to change settings of organizer with ID {request.organizer.id}.")
            return False

        return True
