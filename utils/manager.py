from django.db import models


class CustomManager(models.Manager):
    def all(self):
        return super().all().exclude(is_deleted=True)

    def delete(self, *args, **kwargs):
        self.is_deleted = True
        self.save()

    def undelete(self):
        self.is_deleted = False
        self.save()

    def hard_delete(self, *args, **kwargs):
        super().delete(*args, **kwargs)
