from django.db import models
from django.contrib.auth.models import (
    BaseUserManager,
    AbstractBaseUser,
    PermissionsMixin
)



from django.db import models
from django.contrib.auth.models import BaseUserManager, AbstractBaseUser


class UserAccountManager(BaseUserManager):
    def create_user(self, email, password=None,**kwargs):
        if not email:
            raise ValueError("Users must have an email address")

        user = self.model(
            email=self.normalize_email(email),
            **kwargs
        )

        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, email,password=None,**kwargs):
        """
        Creates and saves a superuser with the given email, date of
        birth and password.
        """
        user = self.create_user(
            email,
            password=password,
            **kwargs
        )
        user.is_admin = True
        user.save(using=self._db)
        return user


class UserAccount(AbstractBaseUser):
    first_name= models.CharField(max_length=255)
    last_name= models.CharField(max_length=255)
    email = models.EmailField(unique=True,max_length=255)

    is_active = models.BooleanField(default=True)
    is_admin = models.BooleanField(default=False)
    is_superuser = models.BooleanField(default=False)

    objects = UserAccountManager()

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['first_name','last_name']

    def __str__(self):
        return self.email