# Generated by Django 2.1.3 on 2018-11-07 17:32

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('ivataraccount', '0011_auto_20181107_1550'),
    ]

    operations = [
        migrations.AddField(
            model_name='confirmedemail',
            name='access_count',
            field=models.BigIntegerField(default=0, editable=False),
        ),
        migrations.AddField(
            model_name='confirmedopenid',
            name='access_count',
            field=models.BigIntegerField(default=0, editable=False),
        ),
    ]
