# Generated by Django 5.0.3 on 2024-05-08 05:07

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('qa', '0001_initial'),
    ]

    operations = [
        migrations.AlterField(
            model_name='answer',
            name='points',
            field=models.DecimalField(decimal_places=2, default=0.0, max_digits=10, verbose_name='Point'),
        ),
        migrations.AlterField(
            model_name='userattempt',
            name='points_earned',
            field=models.DecimalField(decimal_places=2, default=0.0, max_digits=10, verbose_name='Points Earned'),
        ),
    ]