"""Authentication backend for Microsoft Identity Platform using MSAL."""

import base64
import json

import msal
from django.conf import settings
from django.contrib.auth import get_user_model
from django.contrib.auth.backends import BaseBackend
from django.core.exceptions import ObjectDoesNotExist
from django.http import HttpRequest
from django.shortcuts import reverse

from .exceptions import MSALTokenError

# Create the Client App, this project assumes App Registration
client_app = msal.ConfidentialClientApplication(
    client_id=settings.MSAL_AUTH["client_id"],
    client_credential=settings.MSAL_AUTH["client_secret"],
    authority=f"https://login.microsoftonline.com/{settings.MSAL_AUTH['tenant_id'] or 'common'}",
)

UserModel = get_user_model()

def construct_msal_login_url(request: HttpRequest):
    """
    Construct the redirect URL for MSAL authentication.

    Args:
        request: Current HTTP request object.

    Returns:
        Redirect URL string.
    """
    # Get the next url from query string if present
    next_url = request.GET.get("next", "/")

    # Build our callback (redirect) URL that will be used once authenticated
    redirect_url = f"{settings.MSAL_AUTH['scheme']}://{settings.MSAL_AUTH['site_domain']}{reverse('msal_auth:callback')}"

    # Create the full Auth url for Microsoft Authentication
    auth_flow = client_app.initiate_auth_code_flow(
        scopes=settings.MSAL_AUTH["scopes"], redirect_uri=redirect_url
    )

    # Save to Session for use with callback getting Access Token
    request.session["auth_flow"] = auth_flow
    request.session["next"] = next_url
    return auth_flow


def get_access_token(request: HttpRequest):
    """
    Get access token from request using MSAL
    Args:
        request: HTTP request object.

    Returns:
        access_token: Access token.
    Raises:
        MSALTokenError: If MSAL token is invalid or can't be found
    """
    result = client_app.acquire_token_by_auth_code_flow(
        auth_code_flow=request.session.get("auth_flow", {}), auth_response=request.GET
    )

    if "access_token" in result:
        return result["access_token"]

    raise MSALTokenError(f"{result.get('error')} : {result.get('error_description')}")


class MicrosoftAuthenticationBackend(BaseBackend):
    """
    Authentication backend that uses the MSAL python library to access the new
    Microsoft Identity Platform
    """

    def authenticate(self, request, **kwargs):
        """
        Authenticate the login request.  Will create users with the following values:

        User(
            username = Entra Object Id,
            email = Entra Email or UPN,
            first_name = Given Name or Unknown,
            last_name = Family Name or Unknown,
        )

        Args:
            request: HTTP Request object.
            **kwargs:

        Returns:
            user: User object.
        """
        user: UserModel = None

        # if kwargs contains the password field than this is a local login, support
        # ability to keep local login around.
        if "password" not in kwargs:
            if "access_token" in kwargs:
                access_token = kwargs["access_token"]

                # TODO: Switch to using jwcrypto so tokens can be validated
                payload = json.loads(
                    base64.b64decode(access_token.split(".")[1] + "===")
                )  # The '===' prevents Invalid Padding issue

                # Attempt to get the user by object id, or create a new user
                user = UserModel.objects.get_or_create(username=payload["oid"], defaults={
                    "username": payload["oid"],
                    "email": payload.get("email", payload.get("upn", "")),
                    "first_name": payload.get("given_name", "Unknown"),
                    "last_name": payload.get("family_name", "Unknown"),
                })

                # Update names if needed (marriage, etc)
                if "given_name" in payload.keys():
                    if user.first_name != payload["given_name"]:
                        user.first_name = payload["given_name"]
                if "family_name" in payload.keys():
                    if user.last_name != payload["family_name"]:
                        user.last_name = payload["family_name"]

                # TODO: Maybe update email/upn if needed?

                # Save user
                user.save()

        return user

    def get_user(self, user_id):
        try:
            return UserModel.objects.get(pk=user_id)
        except ObjectDoesNotExist:
            return None
