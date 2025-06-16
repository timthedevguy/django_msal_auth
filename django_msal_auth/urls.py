"""Django URL patterns for MSAL authentication."""

from django.urls import path

from . import views

app_name = 'msal_auth'
urlpatterns = [
    path('login/', views.to_auth_redirect, name='login'),
    path('callback/', views.from_auth_redirect, name='callback'),
    path('logoff/', views.signout, name='logoff'),
]
