from django.db import models
from utils.models import AbstractTimeStampModel
from user.models import User

# Create your models here.

class QuestionType(AbstractTimeStampModel):
    type = models.CharField(max_length=100, verbose_name="Question Type")

    def __str__(self):
        return self.type

    class Meta:
        db_table = "question_type"



class Question(AbstractTimeStampModel):
    title = models.TextField(verbose_name="Question")
    question_type = models.ForeignKey(QuestionType, on_delete=models.CASCADE, related_name="question", verbose_name="Question Type")

    def __str__(self):
        return self.title
    
    class Meta:
        db_table = "question"


class Answer(AbstractTimeStampModel):
    ans = models.CharField(max_length=255, verbose_name="Answer")
    question = models.ForeignKey(Question, on_delete=models.CASCADE, related_name="answer", verbose_name="Question")
    is_correct = models.BooleanField(default=False, verbose_name="Is Correct")
    points = models.DecimalField(max_digits=10, decimal_places=2, verbose_name="Point", default=0.0)


    def __str__(self):
        return f"The question : {self.question} 's answer: {self.ans}"
    
    class Meta:
        db_table = "answer"


class UserAttempt(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name="user", verbose_name="User")
    question = models.ForeignKey(Question, on_delete=models.CASCADE, related_name="question", verbose_name="Questions")
    selected_answer = models.ManyToManyField(Answer, verbose_name="Selected Answers")
    points_earned = models.DecimalField(max_digits=10, decimal_places=2, verbose_name="Points Earned", default=0.0)
    all_question_attempted = models.BooleanField(default=False, verbose_name="All question Attempted")

    def __str__(self):
        return f"{self.user} attempts question: {self.question}"
    
    class Meta:
        db_table = "user_attempt"

    
