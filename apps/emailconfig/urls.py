from django.urls import path

from . import views

urlpatterns = [
    path("", views.email_settings, name="email_settings"),
    path("save/<str:backend_type>/", views.email_settings_save, name="email_settings_save"),
    path("test/<str:backend_type>/", views.email_settings_test, name="email_settings_test"),
]
