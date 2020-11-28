from rest_framework import serializers
from django.contrib.auth.models import User
from . import models

class UserRegisterSerializer(serializers.ModelSerializer):
	email = serializers.EmailField(required=True)
	class Meta:
		model = User
		fields = [
			'username',
			'password',
			'email'
		]