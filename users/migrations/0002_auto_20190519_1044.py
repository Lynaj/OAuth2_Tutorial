# Generated by Django 2.2.1 on 2019-05-19 10:44

from django.db import migrations, models
import uuid


class Migration(migrations.Migration):

    dependencies = [
        ('users', '0001_initial'),
    ]

    operations = [
        migrations.AlterField(
            model_name='user',
            name='token',
            field=models.CharField(default=uuid.uuid4, editable=False, max_length=30, verbose_name='Token'),
        ),
    ]
