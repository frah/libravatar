'''
Test our views in ivatar.ivataraccount.views and ivatar.views
'''
# pylint: disable=too-many-lines
from urllib.parse import urlsplit
from io import BytesIO
import io
import os
import django
from django.test import TestCase
from django.test import Client
from django.urls import reverse
from django.contrib.auth.models import User
from django.contrib.auth import authenticate
import hashlib

from libravatar import libravatar_url

from PIL import Image

os.environ['DJANGO_SETTINGS_MODULE'] = 'ivatar.settings'
django.setup()

# pylint: disable=wrong-import-position
from ivatar import settings
from ivatar.ivataraccount.forms import MAX_NUM_UNCONFIRMED_EMAILS_DEFAULT
from ivatar.ivataraccount.models import Photo, ConfirmedOpenId
from ivatar.utils import random_string
# pylint: enable=wrong-import-position


class Tester(TestCase):  # pylint: disable=too-many-public-methods
    '''
    Main test class
    '''
    client = Client()
    user = None
    username = random_string()
    password = random_string()
    email = '%s@%s.%s' % (username, random_string(), random_string(2))
    # Dunno why random tld doesn't work, but I'm too lazy now to investigate
    openid = 'http://%s.%s.%s/' % (username, random_string(), 'org')

    def login(self):
        '''
        Login as user
        '''
        self.client.login(username=self.username, password=self.password)

    def setUp(self):
        '''
        Prepare for tests.
        - Create user
        '''
        self.user = User.objects.create_user(
            username=self.username,
            password=self.password,
        )

    def test_incorrect_digest(self):
        """
        Test incorrect digest
        """
        response = self.client.get('/avatar/%s' % 'x'*65, follow=True)
        self.assertRedirects(
            response=response,
            expected_url='/static/img/deadbeef.png',
            msg_prefix='Why does an invalid hash not redirect to deadbeef?')
