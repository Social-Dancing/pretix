import logging
import json

from django.conf import settings
from django.http import JsonResponse
from django.contrib.auth import logout as auth_logout, login as auth_login
from django.contrib.auth import get_backends
from rest_framework.views import APIView
from rest_framework import status
from rest_framework.permissions import BasePermission
from pretix.helpers.urls import slugify_string
from pretix.api.auth.socialdancing import (
    UserAuthentication, HMACAuthentication,
    UserSettingsPermission, OrganizerSettingsPermission,
    TeamSettingsPermission
)
from pretix.base.auth import remove_sso_session_from_cache
from pretix.base.models import Organizer, User, Team
from pretix.base.auth import (
    get_sso_session_cookie_key,
    get_sso_session,
)
from pretix.base.metrics import pretix_successful_logins
from pretix.api.serializers.organizer import OrganizerSettingsSerializer
from django.utils.translation import gettext_lazy as _

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
    permission_classes = [UserSettingsPermission]

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
    permission_classes = [OrganizerSettingsPermission]

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
            # Check if user already exists by email.
            existing_user = User.objects.filter(email=user_email).first()
            if existing_user:
                logger.debug(
                    f"User with email {user_email} already exists with ID {existing_user.id}.")
                return JsonResponse(
                    {"message": "User already exists.",
                        "pretixId": existing_user.id},
                    status=status.HTTP_200_OK
                )

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


class CreateOrganizer(APIView):
    authentication_classes = [HMACAuthentication, UserAuthentication]
    permission_classes = [PublicPermission]

    def post(self, request, *args, **kwargs):
        logger.debug("Creating new organizer.")

        try:
            body_data = json.loads(request.body)
            organization_name = body_data.get("name")

            slug = slugify_string(organization_name)
            organizer = Organizer.objects.create(
                name=organization_name, slug=slug)
            t = Team.objects.create(
                organizer=organizer,
                # In Core, we also implement team-based access control. However,
                # we support the concept of 'owners' (i.e., superusers) who are
                # not part of any specific team within the organization. To
                # ensure proper mapping between organization owners in Core and
                # their organizer status in Pretix, we create a team with the
                # reserved name '_owners' for this group of users.
                name=_("_owners"),
                all_events=True,
                can_create_events=True,
                can_change_teams=True,
                can_manage_gift_cards=True,
                can_change_organizer_settings=True,
                can_change_event_settings=True,
                can_change_items=True,
                can_manage_customers=True,
                can_manage_reusable_media=True,
                can_view_orders=True,
                can_change_orders=True,
                can_view_vouchers=True,
                can_change_vouchers=True,
            )
            t.members.add(request.user)

            s = OrganizerSettingsSerializer(
                instance=organizer.settings, data=request.data, partial=True,
                organizer=organizer, context={
                    'request': request
                }
            )
            s.update(instance=organizer.settings, validated_data={
                'contact_mail': body_data.get('emailContact', None),
            })

            return JsonResponse(
                {"message": "Successfully created organizer.", "pretixId": organizer.id}, status=status.HTTP_200_OK
            )

        except Exception as e:
            logger.error(
                "An error occurred creating new organizer: %s", str(e))
            return JsonResponse(
                {"message": "Failed to create organizer."},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )


class CreateTeam(APIView):
    authentication_classes = [HMACAuthentication, UserAuthentication]
    permission_classes = [TeamSettingsPermission]

    def post(self, request, *args, **kwargs):
        logger.debug("Creating new team.")

        try:
            body_data = json.loads(request.body)
            team_name = body_data.get("name", None)
            can_manage_organizer_settings = body_data.get(
                "canManageOrganizerSettings", False)
            can_manage_organizer_teams = body_data.get(
                "canManageOrganizerTeams", False)
            member_emails = body_data.get("memberEmails", [])

            team = Team.objects.create(
                organizer=request.organizer,
                # In Core, we also implement team-based access control. However,
                # we support the concept of 'owners' (i.e., superusers) who are
                # not part of any specific team within the organization. To
                # ensure proper mapping between organization owners in Core and
                # their organizer status in Pretix, we create a team with the
                # reserved name '_owners' for this group of users.
                name=team_name,
                all_events=True,
                can_create_events=True,
                can_change_teams=can_manage_organizer_teams,
                can_manage_gift_cards=True,
                can_change_organizer_settings=can_manage_organizer_settings,
                can_change_event_settings=True,
                can_change_items=True,
                can_manage_customers=True,
                can_manage_reusable_media=True,
                can_view_orders=True,
                can_change_orders=True,
                can_view_vouchers=True,
                can_change_vouchers=True,
            )

            for email in member_emails:
                try:
                    user = User.objects.get(email=email)
                    team.members.add(user)
                    logger.debug(
                        f"Added user {user.id} ({user.email}) to the team ${team.id} ({team.name}).")

                except User.DoesNotExist:
                    logger.warning(
                        f"User with email {email} does not exist. Creating user.")
                    try:
                        # Create a new user here as the user record will
                        # eventually be in sync with the Core record once the
                        # user is active in the Core system.
                        user = User.objects.create_user(
                            email=email, password=User.objects.make_random_password()
                        )
                        team.members.add(user)
                        logger.debug(
                            f"Created and added user {user.id} ({user.email}) to team {team.id} ({team.name}).")

                    except Exception as e:
                        logger.error(
                            f"Failed to create and add user with email {email} to team {team.id} ({team.name}): {str(e)}")

                except Exception as e:
                    logger.error(
                        f"Failed to add {user.id} ({user.email}) to the team ${team.id} ({team.name}): {str(e)}")

            return JsonResponse(
                {"message": "Successfully created team.", "pretixId": team.id}, status=status.HTTP_200_OK
            )

        except Exception as e:
            logger.error(
                "An error occurred creating a new team: %s", str(e))
            return JsonResponse(
                {"message": f"Failed to create team \"{team_name}\"."},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )


class UpdateTeam(APIView):
    authentication_classes = [HMACAuthentication, UserAuthentication]
    permission_classes = [TeamSettingsPermission]

    def post(self, request, *args, **kwargs):
        logger.debug("Updating team.")

        try:
            body_data = json.loads(request.body)
            target_team_id = body_data.get("targetTeamId", None)
            team_name = body_data.get("name", None)
            can_manage_organizer_settings = body_data.get(
                "canManageOrganizerSettings", False)
            can_manage_organizer_teams = body_data.get(
                "canManageOrganizerTeams", False)
            emails_to_add = body_data.get("emailsToAdd", [])
            emails_to_remove = body_data.get("emailsToRemove", [])

            team = None
            try:
                team = Team.objects.get(id=target_team_id)
            except Team.DoesNotExist:
                return JsonResponse({"message": "Team not found."}, status=status.HTTP_404_NOT_FOUND)

            team.name = team_name
            team.can_change_organizer_settings = can_manage_organizer_settings
            team.can_change_teams = can_manage_organizer_teams
            team.save()

            for email in emails_to_add:
                try:
                    user = User.objects.get(email=email)
                    team.members.add(user)
                    logger.debug(
                        f"Added user {user.id} ({user.email}) to the team {team.id} ({team.name}).")
                except User.DoesNotExist:
                    logger.debug(
                        f"Created and added user {user.id} ({user.email}) to team {team.id} ({team.name}).")
                    user = User.objects.create_user(
                        email=email, password=User.objects.make_random_password())
                    team.members.add(user)
                    logger.warning(
                        f"Created and added user with email {email} to the team.")

            for email in emails_to_remove:
                try:
                    user = User.objects.get(email=email)
                    team.members.remove(user)
                    logger.debug(
                        f"Removed user {user.id} ({user.email}) from the team {team.id} ({team.name}).")
                except User.DoesNotExist:
                    logger.warning(
                        f"User with email {email} does not exist. Cannot remove.")

            return JsonResponse({"message": "Successfully updated team.", "teamId": team.id}, status=status.HTTP_200_OK)

        except Exception as e:
            logger.error(
                "An error occurred updating team: %s", str(e))
            return JsonResponse(
                {"message": f"Failed to update team \"{team_name}\"."},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )


class DeleteTeam(APIView):
    authentication_classes = [HMACAuthentication, UserAuthentication]
    permission_classes = [TeamSettingsPermission]

    def post(self, request, *args, **kwargs):
        logger.debug("Deleting team.")

        try:
            body_data = json.loads(request.body)
            target_team_id = body_data.get("targetTeamId", None)
            team = Team.objects.get(id=target_team_id)
            team.delete()

            return JsonResponse(
                {"message": "Successfully deleted team."}, status=status.HTTP_200_OK
            )

        except Team.DoesNotExist:
            logger.error(f"Team with id {target_team_id} does not exist.")
            return JsonResponse(
                {"message": f"Team with id {target_team_id} does not exist."},
                status=status.HTTP_404_NOT_FOUND
            )

        except Exception as e:
            logger.error(
                "An error occurred deleting team: %s", str(e))
            return JsonResponse(
                {"message": f"Failed to delete team."},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )
