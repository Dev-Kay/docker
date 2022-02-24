# Configuration file for Jupyter Hub

c = get_config()

c.Application.log_level = 'DEBUG'
c.Spawner.default_url = '/lab'
from oauthenticator.generic import GenericOAuthenticator

keycloak_frontend_url = 'http://192.168.100.84:33333/auth'
keycloak_backend_url = 'http://192.168.100.84:63333/auth'
keycloak_realm = 'my'
c.JupyterHub.shutdown_on_logout = True

c.JupyterHub.authenticator_class = GenericOAuthenticator
c.GenericOAuthenticator.client_id = 'jupyterhub'
#c.GenericOAuthenticator.client_secret = 'ea4db38f-0633-434e-b160-b673842505d0'
c.GenericOAuthenticator.client_secret = 'b9b011f9-91b7-4e84-b920-a227fdd8f822'
c.GenericOAuthenticator.authorize_url = f'{keycloak_frontend_url}/realms/{keycloak_realm}/protocol/openid-connect/auth'
c.GenericOAuthenticator.token_url = f'{keycloak_backend_url}/realms/{keycloak_realm}/protocol/openid-connect/token'
c.GenericOAuthenticator.userdata_url = f'{keycloak_backend_url}/realms/{keycloak_realm}/protocol/openid-connect/userinfo'
c.GenericOAuthenticator.oauth_callback_url = 'http://172.19.201.89:11000/hub/oauth_callback'
c.GenericOAuthenticator.userdata_params = {'state': 'state'}
# the next can be a callable as well, e.g.: lambda t: t.get('complex').get('structure').get('username')
c.GenericOAuthenticator.username_key = 'preferred_username'
c.GenericOAuthenticator.login_service = 'keycloak'
# c.GenericOAuthenticator.scope = ['openid', 'profile', 'roles']
# The next settings are responsible for enabling authorization
# the next can be a callable as well, e.g.: lambda t: t.get('complex').get('structure').get('roles')
# c.GenericOAuthenticator.claim_groups_key = 'roles'
# # users with `staff` role will be allowed
# c.GenericOAuthenticator.allowed_groups = ['user']
# users with `administrator` role will be marked as admin
c.GenericOAuthenticator.admin_groups = ['administrator']

c.Authenticator.whitelist = {'me', 'you', 'other', 'kai.kang@nexr.com', 'sungany@naver.com'}

c.OAuthenticator.tls_verify = False # https 연결을 위해

c.Authenticator.allowed_users = allowed_users = set()
c.JupyterHub.admin_users = admin = set()

c.Spawner.default_url = '/lab'

c.Authenticator.admin_users = {'admin'}
# c.Authenticator.login_url = '/'
c.Authenticator.auto_login = True
c.JupyterHub.tornado_settings = {'headers': {'Content-Security-Policy': "frame-ancestors * 'self' " ,'Access-Control-Allow-Origin': '*','Access-Control-Allow-Methods':'*','Access-Control-Allow-Headers':'*','Access-Control-Allow-Credentials':'true'}}
c.JupyterHub.cookie_max_age_days = 1
c.Authenticator.refresh_pre_spawn = True  # 인증값을 다시 확인 한다?
c.Authenticator.auth_refresh_age = 60 # 인증 refresh interval??
import os
import sys

join = os.path.join

here = os.path.dirname(__file__)
root = os.environ.get('OAUTHENTICATOR_DIR', here)
sys.path.insert(0, root)

with open(join(root, 'userlist')) as f:
    for line in f:
        if not line:
            continue
        parts = line.split()
        name = parts[0]
        allowed_users.add(name)
        if len(parts) > 1 and parts[1] == 'admin':
            admin.add(name)

# c.GenericOAuthenticator.oauth_callback_url = os.environ['OAUTH_CALLBACK_URL']

# ssl config
# ssl = join(root, 'ssl')
# keyfile = join(ssl, 'ssl.key')
# certfile = join(ssl, 'ssl.cert')
# if os.path.exists(keyfile):
#     c.JupyterHub.ssl_key = keyfile
# if os.path.exists(certfile):
#     c.JupyterHub.ssl_cert = certfile

# ldap
# c.JupyterHub.authenticator_class = 'ldapauthenticator.LDAPAuthenticator'
# c.LDAPAuthenticator.server_address = '192.168.100.84'
# c.LDAPAuthenticator.lookup_dn = False
# c.LDAPAuthenticator.bind_dn_template = [
#     "cn={username},cn=kbsys,dc=example,dc=com",
# ]
