from django.contrib import admin
from django.urls import path, include, re_path
from users import views as user_views
from django.conf import settings
from django.conf.urls.static import static
from django.contrib.auth import views as auth_views
from users.views import CustomLoginView, ResetPasswordView, ChangePasswordView
from users.forms import LoginForm

urlpatterns = [
    path('admin/', admin.site.urls),

    path('', include('users.urls')),

    path('login/', CustomLoginView.as_view(redirect_authenticated_user=True, template_name='users/login.html',
                                           authentication_form=LoginForm), name='login'),

    path('logout/', auth_views.LogoutView.as_view(template_name='users/logout.html'), name='logout'),

    path('password-reset/', ResetPasswordView.as_view(), name='password_reset'),

    path('password-reset-confirm/<uidb64>/<token>/',
         auth_views.PasswordResetConfirmView.as_view(
             template_name='users/password_reset_confirm.html'),
         name='password_reset_confirm'),

    path('password-reset-complete/',
         auth_views.PasswordResetCompleteView.as_view(
             template_name='users/password_reset_complete.html'),
         name='password_reset_complete'),

    path('password-change/', ChangePasswordView.as_view(), name='password_change'),

    re_path(r'^oauth/', include('social_django.urls', namespace='social')),

    path('phishing1/', user_views.phishing1, name='phishing1'),
    path('phishing2/', user_views.phishing2, name='phishing2'),
    path('phishing3/', user_views.phishing3, name='phishing3'),

    path('vishing1/', user_views.vishing1, name='vishing1'),
    path('vishing2/', user_views.vishing2, name='vishing2'),
    path('vishing3/', user_views.vishing3, name='vishing3'),


    path('pretexting1/', user_views.pretexting1, name='pretexting1'),
    path('pretexting2/', user_views.pretexting2, name='pretexting2'),
    path('pretexting3/', user_views.pretexting3, name='pretexting3'),

    path('impersonating1/', user_views.impersonating1, name='impersonating1'),
    path('impersonating2/', user_views.impersonating2, name='impersonating2'),
    path('impersonating3/', user_views.impersonating3, name='impersonating3'),

    path('baiting1/', user_views.baiting1, name='baiting1'),
    path('baiting2/', user_views.baiting2, name='baiting2'),
    path('baiting3/', user_views.baiting3, name='baiting3'),
    path('baiting4/', user_views.baiting4, name='baiting4'),



    path('facebooklogin/', user_views.facebooklogin, name='facebooklogin'),
    path('googlelogin/', user_views.googlelogin, name='googlelogin'),
    path('hacked/', user_views.hacked, name='hacked'),

] + static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
