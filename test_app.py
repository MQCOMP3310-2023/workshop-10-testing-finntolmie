import unittest
from flask import current_app
from project import create_app, db
from project.models import User


class TestWebApp(unittest.TestCase):
    def setUp(self):
        self.app = create_app({"SQLALCHEMY_DATABASE_URI": "sqlite://"})
        self.app.config["WTF_CSRF_ENABLED"] = False  # no CSRF during tests
        self.appctx = self.app.app_context()
        self.appctx.push()
        db.create_all()
        self.client = self.app.test_client()

    def tearDown(self):
        db.drop_all()
        self.appctx.pop()
        self.app = None
        self.appctx = None
        self.client = None

    def test_app(self):
        self.assertIsNotNone(self.app)
        self.assertEqual(current_app, self.app)

    def test_homepage_redirect(self):
        response = self.client.get("/", follow_redirects=True)
        self.assertEqual(response.status_code, 200)

    def test_registration_form(self):
        response = self.client.get("/signup")
        self.assertEqual(response.status_code, 200)

    def test_no_access_to_profile(self):
        # Check that non-logged-in user should be redirected to /login
        response = self.client.get("/profile", follow_redirects=True)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.request.path, "/login")

    def test_register_user(self):
        response = self.client.post(
            "/signup",
            data={"email": "user@test.com", "name": "test user", "password": "test123"},
            follow_redirects=True,
        )
        self.assertEqual(response.status_code, 200)
        # should redirect to the login page
        self.assertEqual(response.request.path, "/login")

        # verify that user can now login
        response = self.client.post(
            "/login",
            data={"email": "user@test.com", "password": "test123"},
            follow_redirects=True,
        )
        self.assertEqual(response.status_code, 200)
        html = response.get_data(as_text=True)
        self.assertIn("test user", html)

    def test_hashed_passwords(self):
        response = self.client.post(
            "/signup",
            data={"email": "user@test.com", "name": "test user", "password": "test123"},
            follow_redirects=True,
        )
        self.assertEqual(response.status_code, 200)
        # should redirect to the login page
        self.assertEqual(response.request.path, "/login")

        user = User.query.filter_by(email="user@test.com").first()
        self.assertIsNotNone(user)
        self.assertTrue(user.verify_password("test123"))

    def test_sql_injection(self):
        response = self.client.post(
            "/signup",
            data={
                "email": 'user@test.com"; drop table user; -- ',
                "name": "test user",
                "password": "test123",
            },
            follow_redirects=True,
        )
        self.assertEqual(response.status_code, 200)

    def test_xss_vulnerability(self):
        response = self.client.post(
            "/signup",
            data={
                "email": "new@email.com",
                "name": '<script>alert("hello");</script>',
                "password": "testpassword",
            },
            follow_redirects=True,
        )
        self.assertEqual(response.status_code, 200)

        response = self.client.post(
            "/login",
            data={"email": "new@email.com", "password": "testpassword"},
            follow_redirects=True,
        )
        self.assertEqual(response.status_code, 200)
        html = response.get_data(as_text=True)
        self.assertNotIn("<script>", html)
