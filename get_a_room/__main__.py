import os

import flet as ft
from flet.security import encrypt, decrypt
from flet.auth.providers.github_oauth_provider import GitHubOAuthProvider

secret_key = os.getenv("MY_APP_SECRET_KEY")
AUTH_TOKEN_KEY = "myapp.auth_token"

def main(page: ft.Page):

    provider = GitHubOAuthProvider(
        client_id=os.getenv("GITHUB_CLIENT_ID"),
        client_secret=os.getenv("GITHUB_CLIENT_SECRET"),
        redirect_url="http://localhost:8550/api/oauth/redirect",
    )

    def login_button_click(e):
        page.login(provider, scope=["public_repo"])

    def on_login(e: ft.LoginEvent):
        if not e.error:
            print("Name:", page.auth.user["name"])
            print("Login:", page.auth.user["login"])
            print("Email:", page.auth.user["email"])
            jt = page.auth.token.to_json()
            ejt = encrypt(jt, secret_key)
            page.client_storage.set(AUTH_TOKEN_KEY, ejt)
            toggle_login_buttons()

    def logout_button_click(e):
        page.client_storage.remove(AUTH_TOKEN_KEY)
        page.logout()

    def on_logout(e):
        toggle_login_buttons()

    def toggle_login_buttons():
        login_button.visible = page.auth is None
        logout_button.visible = page.auth is not None
        page.update()

    login_button = ft.ElevatedButton("Login with GitHub", on_click=login_button_click)
    logout_button = ft.ElevatedButton("Logout", on_click=logout_button_click)
    toggle_login_buttons()
    page.on_login = on_login
    page.on_logout = on_logout
    page.add(login_button, logout_button)
    ejt = page.client_storage.get(AUTH_TOKEN_KEY)
    if ejt:
        jt = decrypt(ejt, secret_key)
        if jt:
            page.login(provider, saved_token=jt)

ft.app(target=main, port=8550, view=ft.WEB_BROWSER)