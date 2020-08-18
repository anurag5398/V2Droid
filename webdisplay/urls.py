from django.urls import path
from webdisplay import views

urlpatterns = [
    path("", views.home, name = "home"),
]