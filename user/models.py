from django.db import models
from django.contrib.auth.models import AbstractUser

from utils.models import AbstractTimeStampModel
from .manager import CustomUserManager


# Create your models here.

class User(AbstractUser, AbstractTimeStampModel):
    username = None
    first_name = models.CharField(verbose_name="first name",
        max_length=100,
        help_text="Required. 100 characters or fewer.",
    )
    last_name = models.CharField(verbose_name="last name", max_length=100,
        help_text="Required. 100 characters or fewer.",
    )
    email = models.EmailField( verbose_name="email address", unique=True)
    USERNAME_FIELD = "email"
    REQUIRED_FIELDS = ["first_name", "last_name"]

    objects = CustomUserManager()

    class Meta:
        db_table = "user"

