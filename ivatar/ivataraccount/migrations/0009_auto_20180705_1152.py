# Generated by Django 2.0.6 on 2018-07-05 11:52

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('ivataraccount', '0008_userpreference'),
    ]

    operations = [
        migrations.AlterField(
            model_name='userpreference',
            name='theme',
            field=models.CharField(choices=[('default', 'Default theme'), ('clime', 'climes theme'), ('falko', 'falkos theme')], default='default', max_length=10),
        ),
    ]
