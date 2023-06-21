from django import forms
from django.contrib.auth.models import User
from django.contrib.auth.forms import UserCreationForm, AuthenticationForm
from django.contrib.auth.password_validation import validate_password, MinimumLengthValidator, CommonPasswordValidator, NumericPasswordValidator
from captcha.fields import ReCaptchaField
from captcha.widgets import ReCaptchaV2Checkbox
from .models import Profile
from input_sanitizer import sanitized_forms


class RegisterForm(UserCreationForm):
    # fields we want to include and customize in our form
    first_name = sanitized_forms.SanitizedCharField(max_length=100,
                                                    required=True,
                                                    widget=forms.TextInput(attrs={'placeholder': 'First Name',
                                                                                  'class': 'form-control',
                                                                                  }))
    last_name = sanitized_forms.SanitizedCharField(max_length=100,
                                                   required=True,
                                                   widget=forms.TextInput(attrs={'placeholder': 'Last Name',
                                                                                 'class': 'form-control',
                                                                                 }))
    username = sanitized_forms.SanitizedCharField(max_length=100,
                                                  required=True,
                                                  widget=forms.TextInput(attrs={'placeholder': 'Username',
                                                                                'class': 'form-control',
                                                                                }))
    email = forms.EmailField(required=True,
                             widget=forms.EmailInput(attrs={'placeholder': 'Email',
                                                            'class': 'form-control',
                                                            }))
    password1 = sanitized_forms.SanitizedCharField(label='Password',
                                                   max_length=50,
                                                   required=True,
                                                   widget=forms.PasswordInput(attrs={'placeholder': 'Password',
                                                                                     'class': 'form-control',
                                                                                     'data-toggle': 'password',
                                                                                     'id': 'password',
                                                                                     }))
    password2 = sanitized_forms.SanitizedCharField(label='Password Confirmation',
                                                   max_length=50,
                                                   required=True,
                                                   widget=forms.PasswordInput(attrs={'placeholder': 'Confirm Password',
                                                                                     'class': 'form-control',
                                                                                     'data-toggle': 'password',
                                                                                     'id': 'password',
                                                                                     }))
    captcha = ReCaptchaField(
        label='Complete the reCAPTCHA', widget=ReCaptchaV2Checkbox())

    class Meta:
        model = User
        fields = ['first_name', 'last_name', 'username',
                  'email', 'password1', 'password2']


class LoginForm(AuthenticationForm):
    username = sanitized_forms.SanitizedCharField(max_length=50,
                                                  required=True,
                                                  widget=forms.TextInput(attrs={'placeholder': 'Username',
                                                                                'class': 'form-control',
                                                                                }))
    password = sanitized_forms.SanitizedCharField(max_length=50,
                                                  required=True,
                                                  widget=forms.PasswordInput(attrs={'placeholder': 'Password',
                                                                                    'class': 'form-control',
                                                                                    'data-toggle': 'password',
                                                                                    'id': 'password',
                                                                                    'name': 'password',
                                                                                    }))
    remember_me = forms.BooleanField(required=False)
    captcha = ReCaptchaField(
        label='Complete the reCAPTCHA', widget=ReCaptchaV2Checkbox())

    class Meta:
        model = User
        fields = ['username', 'password', 'remember_me']


class UpdateUserForm(forms.ModelForm):
    first_name = sanitized_forms.SanitizedCharField(
        required=False,
        widget=forms.TextInput(attrs={'class': 'form-control', }))
    last_name = sanitized_forms.SanitizedCharField(
        required=False,
        widget=forms.TextInput(attrs={'class': 'form-control', }))

    username = sanitized_forms.SanitizedCharField(
        required=False,
        widget=forms.TextInput(attrs={'class': 'form-control'}))
    email = forms.EmailField(required=False,
                             widget=forms.EmailInput(attrs={'class': 'form-control'}))

    class Meta:
        model = User
        fields = ['first_name', 'last_name', 'username', 'email']


class fakeemail(forms.ModelForm):

    email = forms.EmailField(required=True,
                             widget=forms.EmailInput(attrs={'placeholder': 'Email', 'class': 'form-control'}))

    class Meta:
        model = User
        fields = ['email']


class ResetPassword(forms.ModelForm):

    email = forms.EmailField(required=True,
                             widget=forms.EmailInput(attrs={'class': 'form-control'}))

    class Meta:
        model = User
        fields = ['email']


class UpdateProfileForm(forms.ModelForm):
    avatar = forms.ImageField(widget=forms.FileInput(
        attrs={'class': 'form-control-file'}))
    bio = sanitized_forms.SanitizedCharField(
        widget=forms.Textarea(attrs={'class': 'form-control', 'rows': 5}))

    class Meta:
        model = Profile
        fields = ['avatar', 'bio']


class ContactForm(forms.Form):
    from_email = forms.EmailField(required=True,
                                  widget=forms.EmailInput(attrs={'placeholder': 'Email', 'class': 'form-control'}))
    subject = sanitized_forms.SanitizedCharField(
        required=False,
        widget=forms.TextInput(attrs={'placeholder': 'Subject', 'class': 'form-control', }))
    message = sanitized_forms.SanitizedCharField(
        required=True,
        widget=forms.Textarea(attrs={'placeholder': 'Message', 'class': 'form-control', }))
