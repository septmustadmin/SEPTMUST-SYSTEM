from django.shortcuts import render, redirect
from django.urls import reverse_lazy
from django.contrib.auth.views import LoginView, PasswordResetView, PasswordChangeView
from django.contrib import messages
from django.contrib.messages.views import SuccessMessageMixin
from django.views import View
from django.contrib.auth.decorators import login_required
from django.http import HttpResponse, HttpResponseRedirect
from django.template import loader
from .forms import RegisterForm, LoginForm, UpdateUserForm, UpdateProfileForm, fakeemail, ContactForm
from django.contrib.sites.shortcuts import get_current_site
from django.utils.encoding import force_bytes, force_str
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.template.loader import render_to_string
from .token import account_activation_token
from django.contrib.auth.models import User
from django.core.mail import EmailMessage, send_mail, BadHeaderError


def base(request):
    template = loader.get_template('users/base.html')
    context = {}
    return HttpResponse(template.render(context, request))


def home(request):
    return render(request, 'users/home.html')


def logout(request):
    return render(request, 'users/logout.html')


def login(request):
    template = loader.get_template('users/login.html')
    context = {}
    return HttpResponse(template.render(context, request))


def successregister(request):
    return render(request, 'users/success_register.html')

# PHISHING


def phishing1(request):
    return render(request, 'phishing/phishing_module1.html')


def phishing2(request):
    return render(request, 'phishing/phishing_module2.html')


def phishing3(request):
    return render(request, 'phishing/phishing_module3.html')

# VISHING


def vishing1(request):
    return render(request, 'vishing/vishing_module1.html')


def vishing2(request):
    return render(request, 'vishing/vishing_module2.html')


def vishing3(request):
    return render(request, 'vishing/vishing_module3.html')

# PRETEXTING


def pretexting1(request):
    return render(request, 'pretexting/pretexting_module1.html')


def pretexting2(request):
    return render(request, 'pretexting/pretexting_module2.html')


def pretexting3(request):
    return render(request, 'pretexting/pretexting_module3.html')

# IMPERSONATING


def impersonating1(request):
    return render(request, 'impersonating/impersonating_module1.html')


def impersonating2(request):
    return render(request, 'impersonating/impersonating_module2.html')


def impersonating3(request):
    return render(request, 'impersonating/impersonating_module3.html')


# BAITING
def baiting1(request):
    return render(request, 'baiting/baiting_module1.html')


def baiting2(request):
    return render(request, 'baiting/baiting_module2.html')


def baiting3(request):
    return render(request, 'baiting/baiting_module3.html')


def baiting4(request):
    return render(request, 'baiting/baiting_module4.html')


def facebooklogin(request):
    return render(request, 'fakeweb/facebook_login.html')


def googlelogin(request):
    return render(request, 'fakeweb/google_login.html')


def hacked(request):
    return render(request, 'fakeweb/hacked.html')


def logincaptcha(request):
    if request.POST:
        form = LoginForm(request.POST)

        # Validate the form: the captcha field will automatically
        # check the input
        if form.is_valid():
            human = True
    else:
        form = LoginForm()

    return render(request, 'users/login.html', {'form': form})


def registercaptcha(request):
    if request.POST:
        form = RegisterForm(request.POST)

        # Validate the form: the captcha field will automatically
        # check the input
        if form.is_valid():
            human = True
    else:
        form = RegisterForm()

    return render(request, 'users/register.html', {'form': form})


def RegisterView(request):
    if request.method == 'POST':
        form = RegisterForm(request.POST)
        if form.is_valid():
            user = form.save(commit=False)
            user.is_active = False
            user.save()
            current_site = get_current_site(request)
            mail_subject = 'Activate your SEPTMUST account.'
            message = render_to_string('users/acc_active_email.html', {
                'user': user,
                'domain': current_site.domain,
                'uid': urlsafe_base64_encode(force_bytes(user.pk)),
                'token': account_activation_token.make_token(user),
            })
            to_email = form.cleaned_data.get('email')
            email = EmailMessage(
                mail_subject, message, to=[to_email]
            )
            email.send()
            messages.success(
                request, 'Activation Email has been send., Please check your email')
            return render(request, 'users/home.html')
    else:
        form = RegisterForm()
    return render(request, 'users/register.html', {'form': form})


def activate(request, uidb64, token):
    try:
        uid = force_str(urlsafe_base64_decode(uidb64))
        user = User.objects.get(pk=uid)
    except(TypeError, ValueError, OverflowError, User.DoesNotExist):
        user = None
    if user is not None and account_activation_token.check_token(user, token):
        user.is_active = True
        user.save()
        return render(request, 'users/success_register.html')
    else:
        messages.success(
            request, 'Activation link is invalid. Please register again.')
        return render(request, 'users/home.html')


def Fakemail1(request):
    if request.method == 'POST':
        form = fakeemail(request.POST)
        if form.is_valid():

            email = EmailMessage(
                "MAYBANK ACCOUNT NEED IMMIDIATE ACTION",
                "WARNING!!, Your Maybank account are compromised, please change your password here to prevent any unauthorized transaction being made on your bank account.""\n"
                "click the link below:""\n"
                "https://rb.gy/j9q5d""\n""\n"
                "If clicking the link above does not work, please copy and paste the URL in a new browser window instead.""\n""\n"
                "Sincerely,""\n"
                "MAYBANK ADMIN",
                "MAYBANK SECURITY<maybanksecurityy@gmail.com>",
                [form.data.get('email')])
            email.send()
        messages.success(
            request, 'Fake email has been send, Please check your email')
        return render(request, 'websitetest/phishing_test1.html', {'form': form})
    else:
        form = fakeemail()
    return render(request, 'websitetest/phishing_test1.html', {'form': form})


def Fakemail2(request):
    if request.method == 'POST':
        form = fakeemail(request.POST)
        if form.is_valid():

            email = EmailMessage(
                "STUDENT ACCOUNT ARE COMPROMISED",
                "BE AWARE!!, Your unikl student account are compromised, please change your password here to prevent any unauthorized action being made on your account.""\n"
                "please click the link below tu update your unikl student account password:""\n"
                "https://rb.gy/j9q5d""\n""\n"
                "If clicking the link above does not work, please copy and paste the URL in a new browser window instead.""\n""\n"
                "Sincerely,""\n"
                "UNIKL ADMIN",
                "UNIKL ADMIN<unikladmin@gmail.com>",
                [form.data.get('email')])
            email.send()
            messages.success(
                request, 'Fake email has been send, Please check your email')
        return render(request, 'websitetest/phishing_test2.html', {'form': form})
    else:
        form = fakeemail()
    return render(request, 'websitetest/phishing_test2.html', {'form': form})


def ContactView(request):
    if request.method == "GET":
        form = ContactForm()
    else:
        form = ContactForm(request.POST)
        if form.is_valid():
            subject = form.cleaned_data['subject']
            body = {
                'email': form.cleaned_data['from_email'],
                'message': form.cleaned_data['message'],
            }
            message = "\n".join(body.values())
        try:
            send_mail(subject, message, 'septmustsystem@gmail.com',
                      ["septmustsystem@gmail.com"])
        except BadHeaderError:
            messages.error(
                request, 'Your enquiry are not because there is and invalid headers. Kindly please try again')
            return render(request, "users/contact.html", {"form": form})
        messages.success(
            request, 'Your enquiry has been send to our admin. We will get back to you shortly.')
        return render(request, "users/contact.html", {"form": form})
    return render(request, "users/contact.html", {"form": form})


# Class based view that extends from the built in login view to add a remember me functionality
class CustomLoginView(LoginView):
    form_class = LoginForm

    def form_valid(self, form, ):
        remember_me = form.cleaned_data.get('remember_me')

        if not remember_me:
            # set session expiry to 0 seconds. So it will automatically close the session after the browser is closed.
            self.request.session.set_expiry(0)

            # Set session as modified to force data updates/cookie to be saved.
            self.request.session.modified = True

        # else browser session will be as long as the session cookie time "SESSION_COOKIE_AGE" defined in settings.py\
        return super(CustomLoginView, self).form_valid(form)


class ResetPasswordView(SuccessMessageMixin, PasswordResetView):
    template_name = 'users/password_reset.html'
    email_template_name = 'users/password_reset_email.html'
    subject_template_name = 'users/password_reset_subject'
    success_message = "We've emailed you instructions for setting your password, " \
                      "if an account exists with the email you entered. You should receive them shortly." \
                      " If you don't receive an email, " \
                      "please make sure you've entered the address you registered with, and check your spam folder."
    success_url = reverse_lazy('users-home')


class ChangePasswordView(SuccessMessageMixin, PasswordChangeView):
    template_name = 'users/change_password.html'
    success_message = "Successfully Changed Your Password"
    success_url = reverse_lazy('users-home')


@login_required
def profile(request):
    if request.method == 'POST':
        user_form = UpdateUserForm(request.POST, instance=request.user)
        profile_form = UpdateProfileForm(
            request.POST, request.FILES, instance=request.user.profile)

        if user_form.is_valid() and profile_form.is_valid():
            user_form.save()
            profile_form.save()
            messages.success(request, 'Your profile is updated successfully')
            return redirect(to='users-profile')
    else:
        user_form = UpdateUserForm(instance=request.user)
        profile_form = UpdateProfileForm(instance=request.user.profile)

    return render(request, 'users/profile.html', {'user_form': user_form, 'profile_form': profile_form})
