# admin.py
from django.contrib import admin
from django.forms import BaseInlineFormSet
from .models import QuestionType, Question, Answer, UserAttempt

class MaxAnswersFormSet(BaseInlineFormSet):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.min_num = 4  # Set the maximum number of inline forms

class AnswerInline(admin.TabularInline):
    model = Answer
    extra = 0  # Start with no extra inline forms
    formset = MaxAnswersFormSet  # Use the custom formset

@admin.register(Question)
class QuestionAdmin(admin.ModelAdmin):
    inlines = [AnswerInline]

admin.site.register([QuestionType, UserAttempt])
