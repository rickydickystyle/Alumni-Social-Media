"""
Django settings for SocialMedia project.

Generated by 'django-admin startproject' using Django 4.2.6.

For more information on this file, see
https://docs.djangoproject.com/en/4.2/topics/settings/

For the full list of settings and their values, see
https://docs.djangoproject.com/en/4.2/ref/settings/
"""

from pathlib import Path

# Build paths inside the project like this: BASE_DIR / 'subdir'.
BASE_DIR = Path(__file__).resolve().parent.parent


# Quick-start development settings - unsuitable for production
# See https://docs.djangoproject.com/en/4.2/howto/deployment/checklist/

# SECURITY WARNING: keep the secret key used in production secret!
SECRET_KEY = 'django-insecure-$!t-2&8($o79kiej3!v#4@=2rxrdgzj_8c_=l%#t-tj@yg8g6_'

# SECURITY WARNING: don't run with debug turned on in production!
DEBUG = True

ALLOWED_HOSTS = []


# Application definition

INSTALLED_APPS = [
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    'SocialNetwork.apps.SocialnetworkConfig',
    'ckeditor',
    'ckeditor_uploader',
    'cloudinary',
    'debug_toolbar',
    'rest_framework',
    'drf_yasg',
    'oauth2_provider',
    'corsheaders',
]

MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
    'debug_toolbar.middleware.DebugToolbarMiddleware',
    'oauth2_provider.middleware.OAuth2TokenMiddleware',
    'corsheaders.middleware.CorsMiddleware',
    'SocialNetwork.middleware.PasswordChangeLecturerMiddleware',
]

ROOT_URLCONF = 'SocialMedia.urls'

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.debug',
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
            ],
        },
    },
]

WSGI_APPLICATION = 'SocialMedia.wsgi.application'

import pymysql

pymysql.install_as_MySQLdb()

# Database
# https://docs.djangoproject.com/en/4.2/ref/settings/#databases

DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.mysql',
        'NAME': 'socialmediadb',
        'USER': 'root',
        'PASSWORD': 'lockhung0123456789',
        'HOST': ''
    }
}


# Password validation
# https://docs.djangoproject.com/en/4.2/ref/settings/#auth-password-validators

AUTH_PASSWORD_VALIDATORS = [
    {
        'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator',
    },
]

# Cloudinary
import cloudinary

cloudinary.config(
    cloud_name="dciqygjtr",
    api_key="586832175499627",
    api_secret="vvnxzWXMhesqDFseP_f5BJicn5E"
)

OAUTH2_PROVIDER = {
    #'OAUTH2_BACKEND_CLASS': 'oauth2_provider.oauth2_backends.JSONOAuthLibCore',
}

REST_FRAMEWORK = {
    'DEFAULT_AUTHENTICATION_CLASSES': (
        'oauth2_provider.contrib.rest_framework.OAuth2Authentication',
    ),

}

# Internationalization
# https://docs.djangoproject.com/en/4.2/topics/i18n/

LANGUAGE_CODE = 'en-us'

TIME_ZONE = 'UTC'

USE_I18N = True

USE_TZ = True

# Static files (CSS, JavaScript, Images)
# https://docs.djangoproject.com/en/4.2/howto/static-files/

STATIC_URL = 'static/'

AUTH_USER_MODEL = 'SocialNetwork.User'

MEDIA_ROOT = '%s/SocialNetwork/static/' % BASE_DIR

CKEDITOR_UPLOAD_PATH = "ckeditor/images/"

# Default primary key field type
# https://docs.djangoproject.com/en/4.2/ref/settings/#default-auto-field

DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'

# Email
EMAIL_BACKEND = 'django.core.mail.backends.smtp.EmailBackend'
EMAIL_HOST = 'smtp.gmail.com'
EMAIL_PORT = 587
EMAIL_HOST_USER = "lochuynh2510@gmail.com"
EMAIL_HOST_PASSWORD = "isrf jwvj qydl atae"
EMAIL_USE_TLS = True
EMAIL_USE_SSL = False

PASSWORD_LECTURER_DEFAULT = "ou@123"

CLIENT_ID = "y153aErkGXjHnQxSpAMBFrIlwiBnBLioItysTOMt"
CLIENT_SECRET = "H1KvWv3v1DipU5UbLRwD4pyMSQPOVp7zCZDX5RO8yVNPb2CVReEbJepWQnK1WWZugpbWq8SUHfB7X6ie8L5gtuKQAfe4OIfrFenXqULSvyntQpGhhWZE1ZpjBcpX8aFs"
