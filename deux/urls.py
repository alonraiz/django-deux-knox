from __future__ import absolute_import, unicode_literals

from django.urls import re_path
from rest_framework.urlpatterns import format_suffix_patterns

from deux import views

urlpatterns = [
    re_path(r"^$", views.MultiFactorAuthDetail.as_view(),
            name="multi_factor_auth-detail"),
    re_path(r"^sms/request/$", views.SMSChallengeRequestDetail.as_view(),
            name="sms_request-detail"),
    re_path(r"^sms/verify/$", views.SMSChallengeVerifyDetail.as_view(),
            name="sms_verify-detail"),
    re_path(r"^recovery/$", views.BackupCodeDetail.as_view(),
            name="backup_code-detail"),
]

urlpatterns = format_suffix_patterns(urlpatterns)
