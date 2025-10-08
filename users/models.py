from django.db import models
from django.contrib.auth.models import AbstractUser

# Create your models here.

class Role(models.Model):
    class Meta:
        db_table = "Role"
    
    name = models.CharField(max_length=100)
    is_active = models.BooleanField(default=True)
        
class User(AbstractUser):
    class Meta:
        db_table = "User"
    
    name = models.CharField(max_length=100, null=True, blank=True)
    email = models.EmailField(null=True)
    role = models.ForeignKey(Role, on_delete=models.CASCADE, null=True, blank=True)
    password = models.CharField(max_length=128, null=True, blank=True)
    failed_login_attempts = models.PositiveIntegerField(default=0,null=True,blank=True)
    last_failed_login = models.DateTimeField(null=True, blank=True)
    link_expire_token = models.CharField(max_length=250,null=True,blank=True)
    
