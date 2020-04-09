'''
Auth backend classes for ivatar/ivataraccount/
'''
import django_auth_ldap.backend
import copy
import operator
import pprint
import re
import warnings
from functools import reduce

import django.conf
import django.dispatch
import ldap
from django.contrib.auth import get_user_model
from django.contrib.auth.models import Group, Permission
from django.core.cache import cache
from django.core.exceptions import ImproperlyConfigured, ObjectDoesNotExist
from django.utils.inspect import func_supports_parameter
from .models import ConfirmedEmail

from django_auth_ldap.config import (
    ConfigurationWarning,
    LDAPGroupQuery,
    LDAPSearch,
    _LDAPConfig,
)

logger = _LDAPConfig.get_logger()

class LDAPBackend(django_auth_ldap.backend.LDAPBackend):
    def _get_or_create_user(self, force_populate=False):
        """
        Loads the User model object from the database or creates it if it
        doesn't exist. Also populates the fields, subject to
        AUTH_LDAP_ALWAYS_UPDATE_USER.
        """
        save_user = False

        username = self.backend.ldap_to_django_username(self._username)

        self._user, built = self.backend.get_or_build_user(username, self)
        self._user.ldap_user = self
        self._user.ldap_username = self._username

        should_populate = force_populate or self.settings.ALWAYS_UPDATE_USER or built

        if built:
            if self.settings.NO_NEW_USERS:
                raise self.AuthenticationFailed(
                    "user does not satisfy AUTH_LDAP_NO_NEW_USERS"
                )

            logger.debug("Creating Django user {}".format(username))
            self._user.set_unusable_password()
            save_user = True

        if should_populate:
            logger.debug("Populating Django user {}".format(username))
            self._populate_user()
            save_user = True

            # Give the client a chance to finish populating the user just
            # before saving.
            populate_user.send(type(self.backend), user=self._user, ldap_user=self)

        if save_user:
            self._user.save()
            (confirmed_id,
             external_photos) = ConfirmedEmail.objects.create_confirmed_email(
                 self._user.username, self._user.email,
                 True)


        # This has to wait until we're sure the user has a pk.
        if self.settings.MIRROR_GROUPS or self.settings.MIRROR_GROUPS_EXCEPT:
            self._normalize_mirror_settings()
            self._mirror_groups()

