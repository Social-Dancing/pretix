import hmac
import hashlib
import logging

from django.conf import settings
from django.core.exceptions import ObjectDoesNotExist
from rest_framework.authentication import BaseAuthentication
from rest_framework.exceptions import AuthenticationFailed
from rest_framework.permissions import BasePermission
from pretix.base.models import User, Organizer
from pretix.base.auth import (
    get_sso_session_cookie_key,
    get_sso_session,
)


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


class OrganizerSettingsPermission(BasePermission):
    """
    Custom permission class tailored for Social Dancing API endpoints. This
    permission verifies that the user has the permissions to apply organizer
    settings changes. 
    """

    def has_permission(self, request, view):
        user_id = request.user.id
        target_organizer_id = request.data.get('targetOrganizerId')

        if not target_organizer_id:
            logger.debug("No target IDs found in request body.")
            return False

        try:
            organizer = Organizer.objects.get(
                id=target_organizer_id) if target_organizer_id else None
            request.organizer = organizer
        except ObjectDoesNotExist:
            logger.warning(
                f"OrganizerSettingsPermission: Invalid organizer_id {target_organizer_id}. Organizer does not exist.")
            return False

        if request.organizer and not request.organizer.user_can_modify_organizer_settings(request.user):
            logger.warning(
                f"User {user_id} ({request.user.email}) does not have permission to change settings of organizer {request.organizer.id} ({request.organizer.name}).")
            return False

        return True


class TeamSettingsPermission(BasePermission):
    """
    Custom permission class tailored for Social Dancing API endpoints. This
    permission verifies that the user has the permissions to apply organizer
    settings changes. 
    """

    def has_permission(self, request, view):
        user_id = request.user.id
        target_organizer_id = request.data.get('targetOrganizerId')
        target_team_id = request.data.get("targetTeamId")

        if not target_team_id and not target_organizer_id:
            logger.debug("No target IDs found in request body.")
            return False

        try:
            organizer = Organizer.objects.get(
                id=target_organizer_id) if target_organizer_id else None
            request.organizer = organizer
        except ObjectDoesNotExist:
            logger.warning(
                f"OrganizerSettingsPermission: Invalid organizer_id {target_organizer_id}. Organizer does not exist.")
            return False

        if request.organizer and not request.organizer.user_can_modify_team_settings(request.user):
            logger.warning(
                f"User {user_id} ({request.user.email}) does not have permission to modify or create teams in organizer {request.organizer.id} ({request.organizer.name}).")
            return False

        return True


class UserSettingsPermission(BasePermission):
    """
    Custom permission class tailored for Social Dancing API endpoints. This
    permission verifies that the user is making a request to modify its own
    settings.
    """

    def has_permission(self, request, view):
        user_id = request.user.id
        target_user_id = request.data.get('targetUserId')

        if not target_user_id:
            logger.debug("No target IDs found in request body.")
            return False

        if target_user_id and str(user_id) != str(target_user_id):
            logger.warning(
                f"User ID {user_id} in session does not match target ID {target_user_id} in request body.")
            return False

        return True


class UserAuthentication(BaseAuthentication):
    """
    Custom permission class tailored for Social Dancing API endpoints. This
    class handles the user authentication process by checking for an existing
    user session in Pretix and, if not found, it attempts to authenticate the
    user via the Social Dancing session.
    """

    def authenticate(self, request):
        logger.debug("Authenticating user...")

        user_id = request.session.get('_auth_user_id')
        user_email = None
        if not user_id:
            logger.debug(
                "No '_auth_user_id' found in Pretix session. Checking Social Dancing session...")

            cookie_key = get_sso_session_cookie_key(request)
            sso_token = request.COOKIES.get(cookie_key)

            if not sso_token:
                logger.debug(
                    "No SSO session token found. Authentication denied.")
                raise AuthenticationFailed("User not authenticated.")

            sso_session_data = get_sso_session(request)
            if not sso_session_data:
                logger.debug(
                    "No SSO session data found. Authentication denied.")
                raise AuthenticationFailed("User not authenticated.")

            # Assumes that the user's email address is consistent between Social
            # Dancing and Pretix. This synchronization is critical for correctly
            # identifying and authenticating the user across both systems.
            user_email = sso_session_data.get("user", {}).get("email")
            if not user_email:
                logger.debug(
                    "No SSO related email found. Authentication denied.")
                raise AuthenticationFailed("User not authenticated.")

        try:
            user = User.objects.get(
                email=user_email) if user_email else User.objects.get(id=user_id)
            # The method of an authentication class must return a tuple (user,
            # auth) or None.
            return (user, None)

        except ObjectDoesNotExist:
            logger.warning(
                f"UserPermission: Invalid user_id {user_id} or user_email {user_email}. User does not exist.")
            raise AuthenticationFailed("User not found.")
