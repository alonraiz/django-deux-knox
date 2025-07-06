from __future__ import absolute_import, unicode_literals

from django.urls import re_path
from rest_framework.urlpatterns import format_suffix_patterns

from deux.authtoken import views

app_name = 'deux-authtoken'

urlpatterns = [
    re_path(r"^login/$", views.ObtainMFAAuthToken.as_view(),
            name="login"),
]

urlpatterns = format_suffix_patterns(urlpatterns)
