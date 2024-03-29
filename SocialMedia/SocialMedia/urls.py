import debug_toolbar
from django.contrib import admin
from django.urls import path, include, re_path
from drf_yasg import openapi
from drf_yasg.views import get_schema_view
from rest_framework import permissions

from SocialNetwork.admin import admin_site

schema_view = get_schema_view(
    openapi.Info(
        title="Alumni Media API",
        default_version='v1',
        description="APIs for Alumni Media",
        contact=openapi.Contact(email="2151010209loc@ou.edu.vn"),
        license=openapi.License(name="Huỳnh Hữu Lộc@2021"),
    ),
    public=True,
    permission_classes=(permissions.AllowAny,),
)

urlpatterns = [
    path('', include('SocialNetwork.urls')),
    path('admin/', admin_site.urls),
    path('o/', include('oauth2_provider.urls',
                       namespace='oauth2_provider')),
    re_path(r'^ckeditor/', include('ckeditor_uploader.urls')),
    path("__debug__/", include("debug_toolbar.urls")),
    re_path(r'^swagger(?P<format>\.json|\.yaml)$',
            schema_view.without_ui(cache_timeout=0),
            name='schema-json'),
    re_path(r'^swagger/$',
            schema_view.with_ui('swagger', cache_timeout=0),
            name='schema-swagger-ui'),
    re_path(r'^redoc/$',
            schema_view.with_ui('redoc', cache_timeout=0),
            name='schema-redoc')
]
