from django.db import models
from .manager import CustomManager


class DeleteAbstract(models.Model):
    is_deleted = models.BooleanField(
        default=False, help_text=("For soft delete purpose")
    )
    objects = CustomManager()

    class Meta:
        abstract = True



class AbstractTimeStampModel(DeleteAbstract):
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        abstract = True
        

class UserCreatedUpdatedBy(AbstractTimeStampModel):
    created_by = models.ForeignKey(
        "user.User",
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="%(app_label)s_%(class)s_created_by",
    )
    updated_by = models.ForeignKey(
        "user.User",
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="%(app_label)s_%(class)s_updated_by",
    )

    class Meta:
        abstract = True
