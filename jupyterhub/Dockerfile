# Designed to be run as 
# docker build -t jupyterhub-oauth .
# docker run -it -p 11000:8000 --mount type=bind,source=D:/Dev/docker/jupyterhub/oauthenticator/examples/full,target=/srv/oauthenticator --env-file=env jupyterhub-oauth

FROM jupyterhub/jupyterhub

# Install oauthenticator from git
RUN python3 -m pip install oauthenticator
RUN python3 -m pip install jupyterlab

# Create oauthenticator directory and put necessary files in it
RUN mkdir /srv/oauthenticator
WORKDIR /srv/oauthenticator
ENV OAUTHENTICATOR_DIR /srv/oauthenticator
#ADD jupyterhub_config.py jupyterhub_config.py
#ADD addusers.sh /srv/oauthenticator/addusers.sh
#ADD userlist /srv/oauthenticator/userlist
#ADD ssl /srv/oauthenticator/ssl
RUN chmod 700 /srv/oauthenticator
RUN apt-get update -y
RUN apt-get install -y nano
RUN apt-get install -y vim
RUN useradd -m -s /bin/bash kai.kang@nexr.com
RUN useradd -m -s /bin/bash admin

#RUN ["sh", "/srv/oauthenticator/addusers.sh"]
