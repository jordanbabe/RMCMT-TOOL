from django.db import models
from utils.models import AbstractTimeStampModel
from user.models import User

class About(AbstractTimeStampModel):
    title = models.CharField(max_length=255)
    description = models.TextField()

    class Meta:
        verbose_name = "About"
        verbose_name_plural = "About"
        db_table = "about"

    def __str__(self):
        return self.title
    

class Assets(AbstractTimeStampModel):
    user = models.ForeignKey(User, verbose_name="User", on_delete=models.CASCADE)
    host_name = models.CharField(max_length=255, verbose_name="Host Name")
    ip_address = models.CharField(max_length=255, verbose_name="IP Address", null=True, blank=True)
    os = models.CharField(max_length=255, verbose_name="OS", null=True, blank=True)
    software = models.CharField(max_length=255, verbose_name="Software", null=True, blank=True)
    other = models.JSONField(default=dict, verbose_name="Other")
    
    class Meta:
        verbose_name = "Assets"
        verbose_name_plural = "Assets"
        db_table = "assets"

    def __str__(self):
        return self.host_name
    


class RiskScale(AbstractTimeStampModel):
    number = models.IntegerField(default=0, verbose_name="Number")
    color_code = models.CharField(max_length=20, verbose_name="Hex Color Code")
    other = models.JSONField(default=dict, verbose_name="Other", null=True, blank=True)

    class Meta:
        verbose_name = "RiskScale"
        verbose_name_plural = "RiskScale"
        db_table = "risk_scale"

    def __str__(self):
        return f"Number: {self.number} Color Code {self.color_code}"
    

class RiskRegister(AbstractTimeStampModel):
    LEVEL_CHOICES = [
        (1, 1),
        (2, 2),
        (3, 3),
        (4, 4),
        (5, 5),
    ]
    user = models.ForeignKey(User, verbose_name="User", on_delete=models.CASCADE)
    risk_description = models.TextField(verbose_name="Risk Description", help_text="Give a brief summary of the risk.")
    impact_description = models.TextField(verbose_name="Impact Description", help_text="What will happen if the risk is not mitigated or eliminated?.")
    impact_level = models.IntegerField(choices=LEVEL_CHOICES, verbose_name="Impact Level", help_text="Rate 1 (LOW) to 5 (HIGH).")
    probability_level = models.IntegerField(choices=LEVEL_CHOICES, verbose_name="Probability Level", help_text="Rate 1 (LOW) to 5 (HIGH).")
    migrations_notes = models.TextField(verbose_name="Migration Notes", help_text="What can be done to lower or eliminate the impact or probability?")
    owner = models.TextField(verbose_name="Owner", help_text="Who's responsible?")
    other = models.JSONField(default=dict, verbose_name="Other", null=True, blank=True)

    class Meta:
        verbose_name = "RiskRegister"
        verbose_name_plural = "RiskRegister"
        db_table = "risk_register"

    def __str__(self):
        return self.risk_description
