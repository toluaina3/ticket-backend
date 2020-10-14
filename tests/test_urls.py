import unittest
from django.test import TestCase
from verify.models import User


class UrlTest(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.u1 = User.objects.create_user(first_name='test', last_name='python', email='test@gmail.com',
                                          password='password')
        cls.u2 = User.objects.create_user(first_name='not', last_name='user', email='not@gmail.com',
                                          password='password')

    def test_homepage(self):
        response = self.client.get('/login/')
        self.assertEqual(response.status_code, 200)

    def test_login(self):
        self.credentials = {'email': 'test@gmail.com', 'password': 'password'}
        user_login = self.client.login(email='test@gmail.com', password='password')
        # self.assertEqual(user_login, True)

    def test_active_login(self):
        self.credentials = {
            'email': 'toluaina3@gmail.com',
            'password': 'tunmi2014'}
        user_login = self.client.login(email='test@gmail.com', password='password')
        self.assertEqual(user_login, True)

    def test_view_with_login(self):
        "Request a page that is protected with @login_required"
        # Get the page without logging in. Should result in 302.
        response = self.client.get('/home/')
        self.assertRedirects(response, '/accounts/login/?next=/home/')

