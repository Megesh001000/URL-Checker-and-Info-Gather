from django.urls import path
from . import views

urlpatterns = [
      path("", views.home, name="home"),
      path("result/", views.result, name="result"),
      path('history/', views.history, name='history'),
      path('recheck/<int:pk>/', views.recheck, name='recheck'),
      path('delete/<int:pk>/', views.delete_entry, name='delete'),
      # path('dashboard/',views.dashboard,name="dashboard")
]
