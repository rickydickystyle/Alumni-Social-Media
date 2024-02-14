# Create your views here.
import json
import pdb
import random
from itertools import chain

from django.contrib.auth import authenticate
from django.conf import settings
from django.db import IntegrityError
from django.http import HttpResponse
from django.utils.decorators import method_decorator
from django.views.decorators.debug import sensitive_post_parameters
from oauth2_provider.views import TokenView
from rest_framework import viewsets, parsers, permissions, generics, status
from rest_framework.decorators import action
from rest_framework.response import Response

from . import serializers, perms, paginators, dao
from .models import User, AlumniProfile, Post, Comment, Reaction, Survey, Group, Question, Answer, Invitation


class LoginView(TokenView):

    @method_decorator(sensitive_post_parameters("password"))
    def post(self, request, *args, **kwargs):
        data = json.loads(request.body.decode("utf-8"))
        username = data.get("username")
        password = data.get("password")
        role = data.get("role")
        user = authenticate(username=username, password=password)
        if user and user.role == role:
            request.POST = request.POST.copy()
            # pdb.set_trace()

            # Add application credientials
            request.POST.update({
                'grant_type': 'password',
                'username': username,
                'password': password,
                'client_id': settings.CLIENT_ID,
                'client_secret': settings.CLIENT_SECRET
            })
            return super().post(request)
        return HttpResponse(content="Khong tim thay tai khoan", status=status.HTTP_401_UNAUTHORIZED)


class RegisterView(generics.CreateAPIView):
    serializer_class = serializers.UserSerializer
    permission_classes = [permissions.AllowAny]
    parser_classes = [parsers.MultiPartParser]

    def create(self, request, *args, **kwargs):
        data = request.data

        avatar = data.get('avatar')
        user_data = {
            'first_name': data.get('first_name'),
            'last_name': data.get('last_name'),
            'username': data.get('username'),
            'password': data.get('password'),
            'email': data.get('email'),
            'avatar': avatar
        }
        user_serializer = self.get_serializer(data=user_data)
        if user_serializer.is_valid():
            user = user_serializer.save()
            try:
                alumni_profile = AlumniProfile.objects.create(user=user, student_id=request.data.get('student_id'))
            except IntegrityError as e:
                user.delete()
                return Response(data={'message': f'Student ID {request.data.get("student_id")} is duplicated'},
                                status=status.HTTP_400_BAD_REQUEST)
            return Response(serializers.AlumniSerializer(alumni_profile).data, status=status.HTTP_201_CREATED)
        return Response(user_serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class UserViewSet(viewsets.ViewSet,
                  generics.UpdateAPIView,
                  generics.DestroyAPIView,
                  generics.RetrieveAPIView):
    queryset = User.objects.filter(is_active=True).all()
    serializer_class = serializers.UserUpdateDetailSerializer
    parser_classes = [parsers.MultiPartParser, parsers.FileUploadParser]
    permission_classes = [permissions.IsAuthenticated()]

    def get_permissions(self):
        if self.action in ['change_password', 'destroy', "add_posts"]:
            return [perms.IsOwner()]
        if self.action in ['add_surveys', 'add_invitations']:
            return [permissions.IsAdminUser()]
        return self.permission_classes

    def update(self, request, *args, **kwargs):
        partial = kwargs.pop('partial', False)
        instance = self.get_object()
        serializer = self.get_serializer(instance, data=request.data, partial=partial)

        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def retrieve(self, request, *args, **kwargs):
        return Response(self.get_serializer(self.get_object()).data, status=status.HTTP_200_OK)

    @action(methods=['get'], url_path='current-user', url_name='current-user', detail=False)
    def current_user(self, request):
        return Response(self.get_serializer(request.user).data, status=status.HTTP_200_OK)

    @action(methods=['post'], url_path='change_password', detail=True)
    def change_password(self, request, pk):
        password_serializer = serializers.PasswordSerializer(data=request.data)
        if password_serializer.is_valid():
            if not request.user.check_password(password_serializer.old_password):
                return Response({'message': 'Incorrect old password'}, status=status.HTTP_400_BAD_REQUEST)
            # set new password
            request.user.set_password(password_serializer.new_password)
            request.user.save()
        return Response(status=status.HTTP_200_OK)

    @action(methods=['post'], detail=True, url_path='posts')
    def add_posts(self, request, pk):
        post = Post.objects.create(user=self.get_object(), content=request.data.get('content'))

        return Response(serializers.PostSerializer(post).data, status=status.HTTP_201_CREATED)

    @action(methods=['post'], detail=True, url_path='surveys')
    def add_surveys(self, request, pk):
        survey_data = request.data
        survey_serializer = serializers.SurveySerializer(data=survey_data)
        if survey_serializer.is_valid():
            survey = survey_serializer.save(user=self.get_object())
            return Response(survey_serializer.data, status=status.HTTP_201_CREATED)
        return Response(survey_serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    @action(methods=['post'], detail=True, url_path='invitations')
    def add_invitations(self, request, pk):
        invitation_data = request.data
        invitation_serializer = serializers.InvitationSerializer(data=invitation_data)
        if invitation_serializer.is_valid():
            invitation = invitation_serializer.save(user=self.get_object())
            return Response(invitation_serializer.data, status=status.HTTP_201_CREATED)
        return Response(invitation_serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    @action(methods=['GET'], detail=False, url_path='search')
    def search(self, request):
        users = dao.search_people(params=request.GET)

        return Response(serializers.UserInteractionSerializer(users, many=True).data,
                        status=status.HTTP_200_OK)


class PostViewSet(viewsets.ViewSet,
                  generics.ListAPIView,
                  generics.UpdateAPIView,
                  generics.RetrieveAPIView,
                  generics.DestroyAPIView):
    queryset = Post.objects.filter(active=True).all()
    serializer_class = serializers.PostDetailSerializer
    permission_classes = [permissions.IsAuthenticated()]
    pagination_class = paginators.PostPaginator

    def get_permissions(self):
        if self.action in ['update', 'block_comments_post']:
            return [perms.IsOwner()]
        if self.action.__eq__('destroy'):
            return [perms.IsOwner(), permissions.IsAdminUser()]
        return self.permission_classes

    def list(self, request, *args, **kwargs):
        user_id = request.GET.get('userId')
        user = User.objects.get(id=user_id)
        if user is not None:
            posts = user.post_set.filter(active=True).order_by('-created_date').all()
            serializer = self.get_serializer(posts, many=True, context={'request': request})
            return Response(serializer.data, status=status.HTTP_200_OK)

        return super().list(request, *args, **kwargs)

    @action(methods=['get'], detail=False, url_path="list-random-posts")
    def list_random_posts(self, request):
        posts = self.queryset
        return Response(self.serializer_class(posts, many=True).data, status=status.HTTP_200_OK)

    @action(methods=['post'], detail=True, url_path='comments')
    def add_comments(self, request, pk):
        c = Comment.objects.create(user=request.user, post=self.get_object(), content=request.data.get('content'))

        return Response(serializers.CommentSerializer(c).data, status=status.HTTP_201_CREATED)

    @action(methods=['post'], detail=True, url_path='reacts')
    def react_posts(self, request, pk):
        act = int(request.data.get('act'))
        reaction, created = Reaction.objects.get_or_create(user=request.user, post=self.get_object(),
                                                           type=act)
        if not created:
            reaction.active = not reaction.active
            reaction.save()
        post_detail_serializer = self.get_serializer(self.get_object(), context={'request': request})
        return Response(post_detail_serializer.data, status=status.HTTP_204_NO_CONTENT)

    @action(methods=['get'], detail=True)
    def list_comments(self, request, pk):
        comments = self.get_object().comment_set.filter(active=True)

        return Response(serializers.CommentSerializer(comments, many=True, context={'request': request}).data,
                        status=status.HTTP_200_OK)

    @action(methods=['get'], detail=True)
    def list_reactions(self, request, pk):
        reactions = self.get_object().reaction_set.filter(active=True)
        return Response(serializers.ReactionSerializer(reactions, many=True, context={'request': request}).data,
                        status=status.HTTP_200_OK)

    @action(methods=['post'], detail=True, url_path='block_comment')
    def block_comments_post(self, request, pk):
        post = self.get_object()
        post.comment_blocked = not post.comment_blocked
        post.save()

        return Response(status=status.HTTP_200_OK)

    @action(methods=['POST'], detail=True)
    def share_post(self, request, pk):
        post_shared = Post.objects.create(user=request.user, content=request.data.get('content'),
                                          shared_post=self.get_object())

        return Response(self.serializer_class(post_shared).data, status=status.HTTP_201_CREATED)


class CommentViewSet(viewsets.ViewSet,
                     generics.UpdateAPIView,
                     generics.DestroyAPIView):
    queryset = Comment.objects.filter(active=True).all()
    serializer_class = serializers.CommentSerializer
    permission_classes = [perms.IsOwner]

    def get_permissions(self):
        if self.action.__eq__('destroy'):
            return [perms.IsCommentAuthorOrPostAuthor()]
        return self.permission_classes


class GroupViewSet(viewsets.ModelViewSet):
    queryset = Group.objects.all()
    serializer_class = serializers.GroupSerializer

    def create(self, request, *args, **kwargs):
        group_name = request.data.get('group_name')
        users_data = request.data.get('users', [])

        group = Group.objects.create(name=group_name)

        for user_data in users_data:
            user = User.objects.get(pk=user_data['id'])
            group.users.add(user)

        serializer = self.get_serializer(group)
        return Response(serializer.data, status=status.HTTP_201_CREATED)

    def update(self, request, *args, **kwargs):
        instance = self.get_object()
        users_data = request.data.get('users', [])

        instance.users.clear()

        for user_data in users_data:
            user = User.objects.get(pk=user_data['id'])
            instance.users.add(user)

        serializer = self.get_serializer(instance)
        return Response(serializer.data)

    def destroy(self, request, *args, **kwargs):
        instance = self.get_object()
        instance.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)


class SurveyViewSet(viewsets.ViewSet,
                    generics.ListAPIView,
                    generics.UpdateAPIView,
                    generics.RetrieveAPIView):
    queryset = Survey.objects.filter(active=True).all()
    serializer_class = serializers.SurveySerializer
    permission_classes = [permissions.IsAdminUser]

    @action(methods=['POST'], detail=True, url_path='questions')
    def add_questions(self, request, pk):
        question = Question.objects.create(survey=self.get_object(), content=request.data.get('content'))

        return Response(serializers.QuestionSerializer(question).data, status=status.HTTP_201_CREATED)


class QuestionViewSet(viewsets.ViewSet,
                      generics.UpdateAPIView,
                      generics.DestroyAPIView):
    queryset = Question.objects.all()
    serializer_class = serializers.QuestionSerializer
    permission_classes = [permissions.IsAdminUser]

    @action(methods=['post'], detail=True, url_path='answers')
    def answers(self, request, pk):
        answer, created = Answer.objects.get_or_create(user=request.user, question=self.get_object(),
                                                       content=request.data.get('content'))

        if created:
            answer.delete()
            return Response(status=status.HTTP_204_NO_CONTENT)
        return Response(status=status.HTTP_201_CREATED)


class InvitationViewSet(viewsets.ViewSet,
                        generics.ListAPIView,
                        generics.RetrieveUpdateDestroyAPIView):
    queryset = Invitation.objects.filter(active=True).all()
    serializer_class = serializers.InvitationSerializer
    permission_classes = [permissions.IsAdminUser]
