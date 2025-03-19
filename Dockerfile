FROM ubuntu:20.04


# Set timezone here or apache installation will stop there
ENV TZ=Africa/Douala
RUN ln -snf /usr/share/zoneinfo/$TZ /etc/localtime && echo $TZ > /etc/timezone

RUN apt-get update --fix-missing
RUN apt-get install -y pkg-config

RUN apt-get update --fix-missing

# Apache install
RUN apt-get install -y apache2 libcairo2-dev

# Python installs
RUN apt-get install -y python
RUN apt-get install -y python3-pip
RUN apt-get install -y libapache2-mod-wsgi-py3

# Install mysqlclient dev lib
RUN apt-get install -y libmysqlclient-dev

# Install necessary python3 packages
RUN pip install Pillow==8.1.2
RUN pip install mysql-connector-python==8.0.23
RUN pip install mysqlclient==2.0.3
RUN pip install requests==2.25.1
RUN pip install pywebpush==1.11.0
RUN pip install websockets==9.1
RUN pip install pymemcache==3.5.2
RUN pip install trml2pdf==0.6
RUN pip install markdown==3.3.4
RUN pip install uritemplate==3.0.1
RUN pip install pygments==2.8.1
RUN pip install pymongo==3.12.0
RUN pip install python-decouple==3.4
RUN pip install unipath==1.1
RUN pip install djangorestframework-simplejwt==5.3.0

# Install django related packages
RUN pip install django==3.2.5
RUN pip install django-import-export==2.5.0
RUN pip install django-user-agents==0.4.0
RUN pip install django-currencies==0.10.1

RUN pip install django-tracking-analyzer==1.1.1
RUN pip install djangorestframework==3.12.2
RUN pip install django-filter==2.4.0
RUN pip install django-guardian==2.3.0

RUN pip install dj-database-url==0.5.0

RUN pip install ajaxuploader==0.3.8

RUN pip install django-parler==2.3
RUN pip install django-cors-headers==4.3.1
RUN pip install icmplib==3.0.3
RUN pip install drf-yasg
RUN pip install sentry-sdk
# Deactivate the default .conf file
RUN unlink /etc/apache2/sites-enabled/000-default.conf

COPY USERS USERS

RUN chown -R root:www-data /USERS/

# Enable the virtual host in apache
RUN ln -sf /USERS/apache_docker.conf /etc/apache2/sites-enabled/users.conf

# Enable headers module
RUN a2enmod headers

WORKDIR /USERS

EXPOSE 80

# Run apache2 as foreground process
CMD ["/usr/sbin/apache2ctl", "-DFOREGROUND"]
