# django-project
# Django REST Framework and JWT imports
from rest_framework import status
from rest_framework.decorators import api_view, permission_classes
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated
from rest_framework_jwt.settings import api_settings

# Django imports
from django.contrib.auth.models import User, Group
from django.contrib.auth import authenticate, get_user_model, password_validation
from django.core.exceptions import ObjectDoesNotExist
from django.shortcuts import get_object_or_404

# JWT settings
jwt_payload_handler = api_settings.JWT_PAYLOAD_HANDLER
jwt_encode_handler = api_settings.JWT_ENCODE_HANDLER

# Sign Up API
@api_view(['POST'])
def sign_up(request):
    username = request.data.get('username')
    password = request.data.get('password')
    email = request.data.get('email')

    # Validate password
    try:
        password_validation.validate_password(password)
    except Exception as e:
        return Response(str(e), status=status.HTTP_400_BAD_REQUEST)

    # Create user
    user = User.objects.create_user(username=username, password=password, email=email)
    user.save()

    return Response("User created successfully.", status=status.HTTP_201_CREATED)

# Forgot Password API
@api_view(['POST'])
def forgot_password(request):
    username = request.data.get('username')

    try:
        user = User.objects.get(username=username)
    except User.DoesNotExist:
        return Response("User not found.", status=status.HTTP_404_NOT_FOUND)

    # Generate new password logic here

    return Response("New password sent successfully.", status=status.HTTP_200_OK)

# Teacher adds/list students API
@api_view(['POST', 'GET'])
@permission_classes([IsAuthenticated])
def teacher_students(request):
    if request.method == 'POST':
        # Get current teacher
        teacher = request.user

        # Get list of students from request data
        student_ids = request.data.get('students')

        # Add students to teacher's group
        group = Group.objects.get(name='Teacher')  # Assuming 'Teacher' is the group name for teachers
        group.user_set.add(*student_ids)

        return Response("Students added successfully.", status=status.HTTP_200_OK)

    elif request.method == 'GET':
        # Get current teacher
        teacher = request.user

        # Get students in the teacher's group
        group = Group.objects.get(name='Teacher')  # Assuming 'Teacher' is the group name for teachers
        students = group.user_set.all()

        # Return serialized student data
        serialized_students = UserSerializer(students, many=True)

        return Response(serialized_students.data, status=status.HTTP_200_OK)

# Admin adds/list all users API
@api_view(['POST', 'GET'])
@permission_classes([IsAuthenticated])
def admin_users(request):
    if request.method == 'POST':
        # Get current admin
        admin = request.user

        # Get list of users from request data
        user_ids = request.data.get('users')

        # Add users to admin's group
        group = Group.objects.get(name='Super-admin')  # Assuming 'Super-admin' is the group name for super-admins
        group.user_set.add(*user_ids)

        return Response("Users added successfully.", status=status.HTTP_200_OK)

    elif request.method == 'GET':
        # Get current admin
        admin = request.user

        # Get all users
        users = User.objects.all()

        # Return serialized user data
        serialized_users = UserSerializer(users, many=True)

        return Response(serialized_users.data, status=status.HTTP_200_OK)

# Student information API
@api_view(['GET'])
@permission_classes([IsAuthenticated])
def student_info(request):
    # Get current student
    student = request.user

    # Return serialized student data
    serialized_student = UserSerializer(student)

    return Response(serialized_student.data, status=status.HTTP_200_OK)

# Token-based authentication APIs
@api_view(['POST'])
def obtain_token(request):
    username = request.data.get('username')
    password = request.data.get('password')

    user = authenticate(request, username=username, password=password)

    if user is not None:
        # Generate token
        payload = jwt_payload_handler(user)
        token = jwt_encode_handler(payload)

        return Response({'token': token}, status=status.HTTP_200_OK)

    return Response("Invalid credentials.", status=status.HTTP_401_UNAUTHORIZED)
