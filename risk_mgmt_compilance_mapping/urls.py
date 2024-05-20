from django.contrib import admin
from django.urls import path, include
from django.conf import settings
from django.conf.urls.static import static

urlpatterns = [
    path('admin/', admin.site.urls),
    path('', include("user.urls", namespace="user")),
    path('', include("dashboard.urls", namespace="dashboard")),
    path('', include("qa.urls", namespace="qa")),
] + static(settings.STATIC_URL, document_root=settings.STATIC_ROOT) + static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)


admin.site.site_title = "RMCMT site admin (DEV)"
admin.site.site_header = "RMCMT administration"
admin.site.index_title = "RMCMT administration"
