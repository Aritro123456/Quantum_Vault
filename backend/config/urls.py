from django.urls import path
from api import views
urlpatterns = [
    path('api/session', views.session),
    path('api/overview', views.overview),
    path('api/keys', views.keys),
    path('api/crypto/<str:action>', views.crypto),
    path('api/benchmarks', views.benchmarks),
    path('api/benchmarks/<str:run_id>', views.benchmark_detail),
    path('api/benchmarks/<str:run_id>/report', views.benchmark_report),
]
