# myapp/urls.py
from django.urls import path
from .views import RegisterView, LoginView, LogoutView  # Remove ProtectedView from import
from .views import ProtectedView #Move ProtectedView to here.

urlpatterns = [
    path('register/', RegisterView.as_view(), name='register'),
    path('login/', LoginView.as_view(), name='login'),
    path('logout/', LogoutView.as_view(), name='logout'),
    
    path('protected/', ProtectedView.as_view(), name='protected')
]