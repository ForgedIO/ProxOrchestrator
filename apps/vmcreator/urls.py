from django.urls import path

from . import views

urlpatterns = [
    path("", views.create, name="vmcreator_create"),
    path("<int:job_id>/configure/", views.configure, name="vmcreator_configure"),
    path("<int:job_id>/progress/", views.progress, name="vmcreator_progress"),
    path("<int:job_id>/status/", views.job_status, name="vmcreator_status"),
]
