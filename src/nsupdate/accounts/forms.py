# -*- coding: utf-8 -*-

from django import forms
from django.contrib.auth import get_user_model

from .models import UserProfile


class UserForm(forms.ModelForm):
    class Meta(object):
        model = get_user_model()
        fields = ['username', 'first_name', 'last_name', 'email']
        widgets = {
            'email': forms.widgets.TextInput(attrs=dict(autofocus=None)),
        }
    def __init__(self, *args, **kwargs):
        super(UserForm, self).__init__(*args, **kwargs)
        self.fields['username'].disabled = True
        self.fields['username'].help_text = None


class UserProfileForm(forms.ModelForm):
    class Meta(object):
        model = UserProfile
        fields = ['language', ]
