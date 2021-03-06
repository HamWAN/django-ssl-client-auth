from pprint import pformat
from django.http import HttpResponse
from django.views.generic import View
from django_ssl_auth.lotw import user_dict_from_dn


class Fineid(View):
    def get(self, request, **kwargs):
        ctx = dict(
            user_data=user_dict_from_dn(request.META[
                'SSL_CLIENT_S_DN']),
            authentication_status=request.META['SSL_CLIENT_VERIFY'],
            user=str(request.user))
        return HttpResponse(pformat(ctx), mimetype="text/plain")

class Test(View):
    def get(self, request, **kwargs):
        ctx = dict(
            user_dn=request.META[
                'SSL_CLIENT_S_DN'],
            authentication_status=request.META['SSL_CLIENT_VERIFY'],
            user=str(request.user))
        return HttpResponse(pformat(ctx), mimetype="text/plain")
