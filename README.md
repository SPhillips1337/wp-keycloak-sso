# wp-keycloak-sso
* Plugin Name: WP Keycloak SSO
* Description: Integrate Keycloak SSO with WordPress.
* Version: 0.1
* Date: 20/08/2024
* Author: Stephen Phillips
* Licence: GPL-3.0 license

A simple plugin to facilitate OpenID connect SSO logins in wordpress using a KeyCloak SSO server
Replacing the standard WordPress login with Keycloak Single Sign-On (SSO)

Work in progress, Login works, need to write registration code next

#Installation
1. Setup Keycloak SSO server, see https://cloudinfrastructureservices.co.uk/install-keycloak-sso-on-ubuntu-20-04/ (Loosely based on this although the plugin uses OpenId Connect not SAML for the client connection and login see settings here for an idea https://cloudinfrastructureservices.co.uk/wordpress-sso-single-sign-on/wordpress-sso-using-keycloak-as-saml-idp/)
2. Download and install plugin wp-keycloak-sso in wordpress and activate (easy part!)
3. Navigate to the settings page and enter the required fields (Auth Server URL, Realm, Client Id, Client Secret) these settings can be easily found in the KeyCloak admin area on your server as described in the articles linked to above, Don't forget to save the settings.
4. Make sure to create a wordpress user with same email as your SSO user account (required currently until I add user account registration via SSO later) the resulting response token from the Keycloak is mapped to a user in wordpress with same email.
5. Log out, and you will see a new "SSO Login" button on the login form, click that to sign in!

#Configuring the client secret in Keycloak involves a few steps within the admin dashboard. Let’s walk through it:

Access the Keycloak Admin Console:
Log in to your Keycloak admin console. Typically, you can access it at http://your-keycloak-domain/auth/admin.
Navigate to Clients:
In the left sidebar, click on “Clients.”
You’ll see a list of existing clients or the option to create a new one.
Select or Create a Client:
If you already have a client (e.g., the admin-cli client), find it in the list and click on its name.
If not, create a new client by clicking the “Create” button and providing the necessary details (e.g., client ID, client protocol).
Configure the Client:
Once you’re in the client configuration, make sure the following settings are correctly configured:
Access Type: Set it to “Confidential.” This enables the use of a client secret.
Service Accounts Enabled: Enable this option. It allows the client to use client credentials (i.e., client ID and secret) for authentication.
Client Authenticator: Ensure it’s set to “Client Id and Secret.”
Credentials Tab: Here’s where you’ll set the actual client secret. You can either generate a secret or provide your own.
Generate or Set the Client Secret:
If you want Keycloak to generate a secret for you, click the “Regenerate Secret” button.
If you have your own secret, enter it in the “Secret” field.
Save Changes:
Don’t forget to save your changes!