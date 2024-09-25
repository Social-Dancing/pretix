#
# This file is part of pretix (Community Edition).
#
# Copyright (C) 2014-2020 Raphael Michel and contributors
# Copyright (C) 2020-2021 rami.io GmbH and contributors
#
# This program is free software: you can redistribute it and/or modify it under the terms of the GNU Affero General
# Public License as published by the Free Software Foundation in version 3 of the License.
#
# ADDITIONAL TERMS APPLY: Pursuant to Section 7 of the GNU Affero General Public License, additional terms are
# applicable granting you additional permissions and placing additional restrictions on your usage of this software.
# Please refer to the pretix LICENSE file to obtain the full terms applicable to this work. If you did not receive
# this file, see <https://pretix.eu/about/en/license>.
#
# This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied
# warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU Affero General Public License for more
# details.
#
# You should have received a copy of the GNU Affero General Public License along with this program.  If not, see
# <https://www.gnu.org/licenses/>.
#

# This file is based on an earlier version of pretix which was released under the Apache License 2.0. The full text of
# the Apache License 2.0 can be obtained at <http://www.apache.org/licenses/LICENSE-2.0>.
#
# This file may have since been changed and any changes are released under the terms of AGPLv3 as described above. A
# full history of changes and contributors is available at <https://github.com/pretix/pretix>.
#
# This file contains Apache-licensed contributions copyrighted by: Ture Gjørup
#
# Unless required by applicable law or agreed to in writing, software distributed under the Apache License 2.0 is
# distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations under the License.

import logging

from django.core.exceptions import ObjectDoesNotExist
from rest_framework.permissions import SAFE_METHODS, BasePermission

from pretix.api.models import OAuthAccessToken
from pretix.base.models import Device, Event, User, Organizer
from pretix.base.models.auth import SuperuserPermissionSet
from pretix.base.models.organizer import TeamAPIToken
from pretix.helpers.security import (
    Session2FASetupRequired, SessionInvalid, SessionPasswordChangeRequired,
    SessionReauthRequired, assert_session_valid,
)


logger = logging.getLogger(__name__)


class EventPermission(BasePermission):

    def has_permission(self, request, view):
        if not request.user.is_authenticated and not isinstance(request.auth, (Device, TeamAPIToken)):
            return False

        if hasattr(view, '_get_permission_name'):
            required_permission = getattr(view, '_get_permission_name')(request)
        elif request.method not in SAFE_METHODS and hasattr(view, 'write_permission'):
            required_permission = getattr(view, 'write_permission')
        elif hasattr(view, 'permission'):
            required_permission = getattr(view, 'permission')
        else:
            required_permission = None

        if request.user.is_authenticated:
            try:
                # If this logic is updated, make sure to also update the logic in pretix/control/middleware.py
                assert_session_valid(request)
            except SessionInvalid:
                return False
            except SessionReauthRequired:
                return False
            except Session2FASetupRequired:
                return False
            except SessionPasswordChangeRequired:
                return False

        perm_holder = (request.auth if isinstance(request.auth, (Device, TeamAPIToken))
                       else request.user)
        if 'event' in request.resolver_match.kwargs and 'organizer' in request.resolver_match.kwargs:
            request.event = Event.objects.filter(
                slug=request.resolver_match.kwargs['event'],
                organizer__slug=request.resolver_match.kwargs['organizer'],
            ).select_related('organizer').first()
            if not request.event or not perm_holder.has_event_permission(request.event.organizer, request.event, request=request):
                return False
            request.organizer = request.event.organizer
            if isinstance(perm_holder, User) and perm_holder.has_active_staff_session(request.session.session_key):
                request.eventpermset = SuperuserPermissionSet()
            else:
                request.eventpermset = perm_holder.get_event_permission_set(request.organizer, request.event)

            if isinstance(required_permission, (list, tuple)):
                if not any(p in request.eventpermset for p in required_permission):
                    return False
            else:
                if required_permission and required_permission not in request.eventpermset:
                    return False

        elif 'organizer' in request.resolver_match.kwargs:
            if not request.organizer or not perm_holder.has_organizer_permission(request.organizer, request=request):
                return False
            if isinstance(perm_holder, User) and perm_holder.has_active_staff_session(request.session.session_key):
                request.orgapermset = SuperuserPermissionSet()
            else:
                request.orgapermset = perm_holder.get_organizer_permission_set(request.organizer)

            if isinstance(required_permission, (list, tuple)):
                if not any(p in request.eventpermset for p in required_permission):
                    return False
            else:
                if required_permission and required_permission not in request.orgapermset:
                    return False

        if isinstance(request.auth, OAuthAccessToken):
            if not request.auth.allow_scopes(['write']) and request.method not in SAFE_METHODS:
                return False
            if not request.auth.allow_scopes(['read']) and request.method in SAFE_METHODS:
                return False
        if isinstance(request.auth, OAuthAccessToken) and hasattr(request, 'organizer'):
            if not request.auth.organizers.filter(pk=request.organizer.pk).exists():
                return False
        return True


class EventCRUDPermission(EventPermission):
    def has_permission(self, request, view):
        if not super(EventCRUDPermission, self).has_permission(request, view):
            return False
        elif view.action == 'create' and 'can_create_events' not in request.orgapermset:
            return False
        elif view.action == 'destroy' and 'can_change_event_settings' not in request.eventpermset:
            return False
        elif view.action in ['update', 'partial_update'] \
                and 'can_change_event_settings' not in request.eventpermset:
            return False

        return True


class ProfilePermission(BasePermission):

    def has_permission(self, request, view):
        if not request.user.is_authenticated and not isinstance(request.auth, (Device, TeamAPIToken)):
            return False

        if request.user.is_authenticated:
            try:
                # If this logic is updated, make sure to also update the logic in pretix/control/middleware.py
                assert_session_valid(request)
            except SessionInvalid:
                return False
            except SessionReauthRequired:
                return False
            except Session2FASetupRequired:
                return False
            except SessionPasswordChangeRequired:
                return False

        if isinstance(request.auth, OAuthAccessToken):
            if not (request.auth.allow_scopes(['read']) or request.auth.allow_scopes(['profile'])) and request.method in SAFE_METHODS:
                return False

        return True


class AnyAuthenticatedClientPermission(BasePermission):

    def has_permission(self, request, view):
        if not request.user.is_authenticated and not isinstance(request.auth, (Device, TeamAPIToken)):
            return False

        if request.user.is_authenticated:
            try:
                # If this logic is updated, make sure to also update the logic in pretix/control/middleware.py
                assert_session_valid(request)
            except SessionInvalid:
                return False
            except SessionReauthRequired:
                return False
            except Session2FASetupRequired:
                return False
            except SessionPasswordChangeRequired:
                return False

        return True


class UserPermission(BasePermission):
    """
    Custom permission class tailored for specific Social Dancing API endpoints.
    This permission verifies that the user making the request is the intended
    target of the action or has the necessary permissions on the target
    organizer.
    """

    def has_permission(self, request, view):
        user_id = request.session.get('_auth_user_id')
        if not user_id:
            logger.warning("No '_auth_user_id' found in session.")
            return False

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
            user = User.objects.get(id=user_id)
            request.user = user
        except ObjectDoesNotExist:
            logger.warning(
                f"UserPermission: Invalid user_id {user_id}. User does not exist.")
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
