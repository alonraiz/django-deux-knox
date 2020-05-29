from __future__ import absolute_import, unicode_literals

from django.contrib.auth.signals import user_logged_in
from rest_framework.authtoken.views import ObtainAuthToken
from rest_framework.serializers import DateTimeField
from rest_framework.response import Response
from knox.settings import knox_settings
from knox.models import AuthToken

from deux.authtoken.serializers import MFAAuthTokenSerializer


class ObtainMFAAuthToken(ObtainAuthToken):
    """
    class::ObtainMFAAuthToken()

    View for authenticating which extends the ``ObtainAuthToken`` from
    Django Rest Framework's Token Authentication.
    """
    serializer_class = MFAAuthTokenSerializer

    def post(self, request, *args, **kwargs):
        """
        function::post(self, request)

        Override ObtainAuthToken's post method for multifactor
        authentication.

        (1) When MFA is required, send the user a response
        indicating which challenge is required.
        (2) When authentication is successful return the auth token.

        :param request: Request object from the client.
        """
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        data = serializer.validated_data
        if "mfa_required" in data and data["mfa_required"]:
            return Response({
                "mfa_required": True,
                "mfa_type": serializer.validated_data["mfa_type"]
            })
        else:
            user = serializer.validated_data['user']
            token_ttl = self.get_token_ttl()
            instance, token = AuthToken.objects.create(user, token_ttl)
            user_logged_in.send(sender=request.user.__class__, request=request, user=user)

            datetime_format = knox_settings.EXPIRY_DATETIME_FORMAT

            return Response({
                'expiry': DateTimeField(format=datetime_format).to_representation(instance.expiry),
                'token': token
            })
