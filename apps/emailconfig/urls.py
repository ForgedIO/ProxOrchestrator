from django.urls import path

from . import views

urlpatterns = [
    path("", views.email_settings, name="email_settings"),
    path("save/<str:backend_type>/", views.email_settings_save, name="email_settings_save"),
    path("toggle/", views.email_settings_toggle, name="email_settings_toggle"),
    path("test/<str:backend_type>/", views.email_settings_test, name="email_settings_test"),
]
