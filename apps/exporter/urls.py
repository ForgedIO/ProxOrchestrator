from django.urls import path

from . import views

urlpatterns = [
    # Export
    path("", views.export_index, name="export_index"),
    path("options/<int:vmid>/", views.export_options, name="export_options"),
    path("trigger/<int:vmid>/", views.export_trigger, name="export_trigger"),
    path("<int:job_id>/progress/", views.export_progress, name="export_progress"),
    path("<int:job_id>/status/", views.export_status, name="export_status"),
    path("<int:job_id>/download/", views.export_download, name="export_download"),
    path("<int:job_id>/delete/", views.export_delete_job, name="export_delete_job"),

    # .px Import
    path("import/", views.px_upload, name="px_upload"),
    path("import/<int:job_id>/configure/", views.px_configure, name="px_configure"),
    path("import/<int:job_id>/progress/", views.px_progress, name="px_progress"),
    path("import/<int:job_id>/status/", views.px_status, name="px_status"),
    path("import/<int:job_id>/delete/", views.px_delete_job, name="px_delete_job"),

    # LXC Export
    path("lxc/options/<int:vmid>/", views.lxc_export_options, name="lxc_export_options"),
    path("lxc/trigger/<int:vmid>/", views.lxc_export_trigger, name="lxc_export_trigger"),
    path("lxc/<int:job_id>/progress/", views.lxc_export_progress, name="lxc_export_progress"),
    path("lxc/<int:job_id>/status/", views.lxc_export_status, name="lxc_export_status"),
    path("lxc/<int:job_id>/download/", views.lxc_export_download, name="lxc_export_download"),
    path("lxc/<int:job_id>/delete/", views.lxc_export_delete_job, name="lxc_export_delete_job"),

    # LXC .px Import
    path("lxc/import/", views.lxc_px_upload, name="lxc_px_upload"),
    path("lxc/import/<int:job_id>/configure/", views.lxc_px_configure, name="lxc_px_configure"),
    path("lxc/import/<int:job_id>/progress/", views.lxc_px_progress, name="lxc_px_progress"),
    path("lxc/import/<int:job_id>/status/", views.lxc_px_status, name="lxc_px_status"),
    path("lxc/import/<int:job_id>/delete/", views.lxc_px_delete_job, name="lxc_px_delete_job"),
]
