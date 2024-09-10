import hmac
import hashlib
import logging

from django.conf import settings
from rest_framework.authentication import BaseAuthentication
from rest_framework.exceptions import AuthenticationFailed

logger = logging.getLogger(__name__)


class HMACAuthentication(BaseAuthentication):
    def authenticate(self, request):
        # Get the HMAC signature from the request headers.
        signature = request.headers.get("X-Signature")
        if not signature:
            return None

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
        # or None.
        return (None, None)
