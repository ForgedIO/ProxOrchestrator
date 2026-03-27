from django.urls import path

from . import views


urlpatterns = [
    path("<int:vmid>/", views.vm_detail, name="vm_detail"),
    path("<int:vmid>/console/", views.vm_console, name="vm_console"),
    path("<int:vmid>/delete/", views.vm_delete, name="vm_delete"),
]
