from django.urls import path
from dashboard.views import (
    DashView,
    DashboardView,
    RiskAssessmentAttemptView,
    CommonThreatView,
    AssetsView,
    AssetsUploadView,
    ExportAssetsDataView,
    TrainingsView,
    ComplianceView,
    CompilanceQAAttemptView,
    AboutView,
    RiskRegisterView,
    RiskRegisterCreateView,
    RiskRegisterUpdateView,
    RiskRegisterDeleteView,
)

app_name="dashboard"

urlpatterns = [
    path("dashboard", DashView.as_view(), name="dash"),
    path("risk-assessment", DashboardView.as_view(), name="dashboard"),
    path("rist-assessment-attempt", RiskAssessmentAttemptView.as_view(), name="risk_assessment_attempt"),
    path("common-threat", CommonThreatView.as_view(), name="common_threat"),
    path("assets", AssetsView.as_view(), name="assets"),
    path("assets-upload", AssetsUploadView.as_view(), name="assets_upload"),
    path("assets-export", ExportAssetsDataView.as_view(), name="assets_export"),
    path("trainings", TrainingsView.as_view(), name="trainings"),
    path("compilance", ComplianceView.as_view(), name="compilance"),
    path("compilance-qa-attempt", CompilanceQAAttemptView.as_view(), name="compilance_qa_attempt"),
    path("about-us", AboutView.as_view(), name="about"),
    path("risk-register", RiskRegisterView.as_view(), name="risk_register"),
    path("risk-register-create", RiskRegisterCreateView.as_view(), name="risk_register_create"),
    path("risk-register/<int:pk>/update", RiskRegisterUpdateView.as_view(), name="risk_register_update"),
    path("risk-register/<int:pk>/delete", RiskRegisterDeleteView.as_view(), name="risk_register_delete"),
]
