from django.urls import path
from .views import home, profile, RegisterView, Fakemail1, Fakemail2, ContactView
from django.contrib.staticfiles.urls import staticfiles_urlpatterns
from . import views

urlpatterns = [
    path('', home, name='users-home'),
    path('register/', RegisterView, name='users-register'),
    path('fakemail1/', Fakemail1, name='users-fakemail1'),
    path('fakemail2/', Fakemail2, name='users-fakemail2'),
    path('contact/', ContactView, name='users-contact'),
    path('profile/', profile, name='users-profile'),
    path(
        'activate/(?P<uidb64>[0-9A-Za-z_\-]+)/(?P<token>[0-9A-Za-z]{1,13}-[0-9A-Za-z]{1,20})/', views.activate, name='activate'),
]

urlpatterns += staticfiles_urlpatterns()
