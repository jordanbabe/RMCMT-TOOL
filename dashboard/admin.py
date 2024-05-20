from django.contrib import admin
from .models import About, Assets, RiskScale, RiskRegister

admin.site.register([About, Assets, RiskScale, RiskRegister])