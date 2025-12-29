from django.urls import path
from . import views

urlpatterns = [
      path("", views.home, name="home"),
      path("result/", views.result, name="result"),
      path('history/', views.history, name='history'),
      path('recheck/<int:entry_id>/', views.recheck, name='recheck'),
      path('delete/<int:entry_id>/', views.delete_entry, name='delete'),
      path('dashboard/',views.dashboard,name="dashboard"),
      path('scan-email/', views.scan_email_view, name='email_scanner'),
         path('scan-email-json/', views.scan_email_json, name='scan_email_json'),
           path("scan-attachment/", views.attachment_scan_view, name="attachments_scanner"),
    path("scan-attachment-json/", views.scan_attachment_json, name="scan_attachment_json"),

]


