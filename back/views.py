from django.shortcuts import render
from rest_framework import permissions, status, generics
from rest_framework.response import Response
from rest_framework.authtoken.models import Token
from django.contrib.auth.models import User
from rest_framework.decorators import api_view, permission_classes
from django.contrib.sites.shortcuts import get_current_site
from django.utils.encoding import force_bytes, force_text
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.template.loader import render_to_string
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.core.mail import EmailMultiAlternatives
from .serializers import UserRegisterSerializer, UserResetPasswordSerializer, UserPasswordSerializer
from django.utils.html import strip_tags
from django.contrib.auth.password_validation import validate_password
import six
import threading

class EmailTokenGenerator(PasswordResetTokenGenerator):
	def _make_hash_value(self, user, timestamp):
		return(six.text_type(user.pk) + six.text_type(timestamp) + six.text_type(user.is_active))

email_token_gen = EmailTokenGenerator()
password_token_gen = PasswordResetTokenGenerator()

@api_view(['POST'])
@permission_classes([~permissions.IsAuthenticated])
def UserRegisterAPIView(request):
	serializer = UserRegisterSerializer(data = request.data)
	if(serializer.is_valid()):
		data = serializer.validated_data
		if(User.objects.filter(username = data['username']).exists() or User.objects.filter(email = data['email']).exists()):
			return Response({'ok':False, 'error':'User already exists'}, status = status.HTTP_400_BAD_REQUEST)
		try:
			validate_password(data['password'])
		except Exception as errors:
			return Response({'ok':False, 'error':errors} ,status = status.HTTP_400_BAD_REQUEST)
		user = User.objects.create(username = data['username'], email = data['email'], is_active = False)
		user.set_password(data['password'])
		user.save()
		domain = get_current_site(request).domain
		mail_subject = 'Account activation'
		message = render_to_string('email_activtion.html',{
			'user':user,
			'domain': domain,
            'uidb64': urlsafe_base64_encode(force_bytes(user.pk)),
            'token': email_token_gen.make_token(user),
		})
		message_task = threading.Thread(target = async_email_send, args=( mail_subject, message, [data['email']] ))
		message_task.start()
		return Response({'ok':True}, status = status.HTTP_200_OK)
	return Response({'ok':False, 'error':serializer.errors},status = status.HTTP_400_BAD_REQUEST)

@api_view(['POST'])
@permission_classes([permissions.AllowAny])
def UserActivationAPIView(request, uidb64, token):
	uid = force_text(urlsafe_base64_decode(uidb64))
	user = User.objects.filter(id = uid)
	if(user.exists()):
		user = user.first()
		if(email_token_gen.check_token(user, token)):
			user.is_active = True
			user.save()
			return Response({'ok':True}, status = status.HTTP_200_OK)
	return Response({'ok':False, 'error':'Invalid activation link'}, status = status.HTTP_400_BAD_REQUEST)

@api_view(['POST'])
@permission_classes([~permissions.IsAuthenticated])
def UserResetPasswordRequestAPIView(request):
	serializer = UserResetPasswordSerializer(data = request.data)
	if(serializer.is_valid()):
		data = serializer.validated_data
		user = User.objects.filter(email = data['email'])
		if(user.exists()):
			user = user.first()
			domain = get_current_site(request).domain
			mail_subject = 'Password reset'
			message = render_to_string('password_reset.html',{
				'user':user,
				'domain': domain,
	            'uidb64': urlsafe_base64_encode(force_bytes(user.pk)),
	            'token': password_token_gen.make_token(user),
			})
			message_task = threading.Thread(target = async_email_send, args=( mail_subject, message, [data['email']] ))
			message_task.start()
			return Response({'ok':True}, status = status.HTTP_200_OK)
		return Response({'ok':False, 'error':'User does not exist'}, status = status.HTTP_400_BAD_REQUEST)
	return Response({'ok':False, 'error':serializer.errors}, status = status.HTTP_400_BAD_REQUEST)

@api_view(['POST'])
@permission_classes([~permissions.IsAuthenticated])
def UserResetPasswordAPIView(request, uidb64, token):
	serializer = UserPasswordSerializer(data = request.data)
	if(serializer.is_valid()):
		data = serializer.validated_data
		try:
			validate_password(data['password'])
		except Exception as errors:
			return Response({'ok':False, 'error':errors} ,status = status.HTTP_400_BAD_REQUEST)
		uid = force_text(urlsafe_base64_decode(uidb64))
		user = User.objects.filter(id = uid)
		if(user.exists()):
			user = user.first()
			if(password_token_gen.check_token(user, token)):
				user.set_password(data['password'])
				user.save()
				return Response({'ok':True}, status = status.HTTP_200_OK)
			return Response({'ok':False, 'error':'Invalid password reset link'} ,status = status.HTTP_400_BAD_REQUEST)
		return Response({'ok':False, 'error':'User does not exist'} ,status = status.HTTP_400_BAD_REQUEST)
	return Response({'ok':False, 'error':serializer.errors}, status = status.HTTP_400_BAD_REQUEST)

@api_view(['POST'])
@permission_classes([permissions.IsAuthenticated])
def UserLogoutAPIView(request):
	Token.objects.get(user = request).delete()
	return Response(status = status.HTTP_200_OK)

def async_email_send(mail_subject, message, to_email):
	mail_to_send = EmailMultiAlternatives(mail_subject, strip_tags(message), to=to_email)
	mail_to_send.attach_alternative(message, 'text/html')
	mail_to_send.send()