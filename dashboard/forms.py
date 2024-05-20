from django import forms
from qa.models import UserAttempt
from .models import RiskRegister

class RiskAssessmentForm(forms.ModelForm):
    class Meta:
        model = UserAttempt
        fields = ["question", "selected_answer"]


class RiskRegisterForm(forms.ModelForm):
    class Meta:
        model = RiskRegister
        fields = ["risk_description", "impact_description", "impact_level", "probability_level", "migrations_notes", "owner"]
        widgets = {
            'risk_description': forms.Textarea(attrs={'rows': 1}),
            'impact_description': forms.Textarea(attrs={'rows': 1}),
            'migrations_notes': forms.Textarea(attrs={'rows': 1}),
            'owner': forms.Textarea(attrs={'rows': 1})
        }
    
    def __init__(self, *args, **kwargs):
        super(RiskRegisterForm, self).__init__(*args, **kwargs)
        if self.instance:
            self.fields['risk_description'].initial = self.instance.risk_description
            self.fields['impact_description'].initial = self.instance.impact_description
            self.fields['migrations_notes'].initial = self.instance.migrations_notes
            self.fields['owner'].initial = self.instance.owner

