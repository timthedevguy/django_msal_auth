# Django MSAL Auth

## Installation

```shell
pip install git+https://github.com/timthedevguy/django_msal_auth.git
```
or
```shell
poetry add git+https://github.com/timthedevguy/django_msal_auth.git
```

**Requires SessionMiddleware**

Add the following to your `INSTALLED_APPS` in `settings.py`:

```python
INSTALLED_APPS = [
    ...
    "django_msal_auth",
]
```

Add the following to your urls.py:

```python
from django.urls import path, include
urlpatterns = [
    ...
    path("microsoft/", include("django_msal_auth.urls")),
]
```

## Configuration

Create Application Registration in Azure AD and add the following to your Django settings.py with the values filled in from the Application Registration.

Your call back URL should be set to `https://<your-domain>/microsoft/callback/`.

```python
MSAL_AUTH = {
    "client_id": "",
    "client_secret": "",
    "tenant_id": "",
    "scopes": [
        ""
    ],
    "site_domain": "<your-domain>",
    "scheme": "https"
}
```
Scheme is not auto-detected using ```request.scheme``` just in case you don't have access to control proxy/header forwarding information.

Add backend to your `AUTHENTICATION_BACKENDS` in `settings.py`, leaving the default ModelBackend in place to allow for local users.

```python
AUTHENTICATION_BACKENDS = [
    "django_msal_auth.auth.MicrosoftAuthenticationBackend",
    "django.contrib.auth.backends.ModelBackend"
]
```

### Login without Login Page

If you don't want to display a login page then you can set the following setting in settings.py which will immediately start the Auth process with Entra AD.

```python
LOGIN_URL = "/microsoft/login/"
```

### Login with Login Page
To add MSAL to your registration/login page you can use the ```msal_auth_url``` template tag.

```html
{% load msal_tags %}
...
<a href="{% msal_auth_url %}">Login with Microsoft</a>
```

## How Users are created

When a user logs in and needs created the following fields are populated from Microsoft.

```python
UserObject.username = "Users Entra AD Object ID"
UserObject.email = "Users UPN"
UserObject.first_name = "Users Given Name if available, otherwise Unknown"
UserObject.last_name = "Users Sur Name if available, otherwise Unknown"
```


## URLS
The following URLS are provided by django_msal_auth

|URL|Name|Description|
|--|--|--|
|callback/|msal_auth:callback|Redirect callback url for MSAL response|
|login/|msal_auth:login|Provides direct login capability instead of creating a login page|
|logoff/|msal_auth:logoff|Initiates MSAL logoff|
