from django.urls import path
from user.views import (
    LoginView,
    RegisterView,
    LogoutView,
)

app_name="user"

urlpatterns = [
    path("", LoginView.as_view(), name="user_login"),
    path("register/", RegisterView.as_view(), name="user_register"),
    path("logout/", LogoutView.as_view(), name="user_logout"),
]
