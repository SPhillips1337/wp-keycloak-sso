<?php
/**
 * Plugin Name: WP Keycloak SSO
 * Description: Integrate Keycloak SSO with WordPress.
 * Version: 0.1
 * Date: 20/08/2024
 * Author: Stephen Phillips
 * Licence: GPL-3.0 license
 */

// Add your plugin initialization code here (if needed).

// Define Keycloak configuration (replace with your actual values)
/*
Example options
'auth_server_url' => 'http://[keycloak_server]:8080/auth'
'realm' => 'realm1'
'client_id' => 'http://[wp_website_domain]',
'client_secret' => '[client_secret from keycloak]',
'redirect_uri' => site_url('/keycloak-sso-callback'), // Fixed plugin callback URL path
];
*/
// Handle login initiation
function initiate_keycloak_login() {
    $options = get_keycloak_config();
    $auth_url = "{$options['auth_server_url']}/realms/{$options['realm']}/protocol/openid-connect/auth";
    $params = [
        'client_id' => $options['client_id'],
        'redirect_uri' => $options['redirect_uri'],
        'response_type' => 'code',
        'scope' => 'openid', // Adjust scopes as needed
    ];
    $login_url = add_query_arg($params, $auth_url);
    wp_redirect($login_url);
    exit;
}

// Register a custom endpoint for handling the Keycloak callback
function register_keycloak_callback_endpoint() {
    add_rewrite_endpoint('keycloak-sso-callback', EP_ROOT);
}
add_action('init', 'register_keycloak_callback_endpoint');

function exchange_code_for_tokens($code) {
    $options = get_keycloak_config();
    $token_endpoint = $options['auth_server_url'] . '/realms/' . $options['realm'] . '/protocol/openid-connect/token';

    $body = array(
        'client_id' => $options['client_id'],
        'client_secret' => $options['client_secret'],
        'code' => $code,
        'grant_type' => 'authorization_code',
        'redirect_uri' =>  $options['redirect_uri']
    );

    $args = array(
        'body' => $body,
        'method' => 'POST',
        'sslverify' => false // Consider enabling SSL verification for production
    );

    $response = wp_remote_post($token_endpoint, $args);

    if (is_wp_error($response)) {
        // Handle error
        return false;
    }

    $body = wp_remote_retrieve_body($response);
    $tokens = json_decode($body, true);

    if (isset($tokens['access_token']) && isset($tokens['id_token'])) {
        return $tokens;
    } else {
        // Handle error: invalid response
        return false;
    }
}

// Callback after successful login
function handle_keycloak_callback() {
    if (isset($_GET['code'])) {
        $code = $_GET['code'];
        // Exchange authorization code for tokens
        $tokens = exchange_code_for_tokens($code);
        if ($tokens) {
            // Parse the ID token to get user information (e.g., email)
            $id_token = $tokens['id_token'];
            $user_info = extract_user_info_from_id_token($id_token);
            // Check if the user exists in WordPress
            $user = get_user_by('email', $user_info['email']);
            if ($user) {
                // Log in the existing user
                wp_set_auth_cookie($user->ID);
                wp_redirect(admin_url());
                exit;
            } else {
                // TODO: Create a new user account (you'll need to implement this logic)
                // Redirect to an appropriate page (e.g., dashboard)
                die('new user creation');
            }
        }
    } else {
        // Handle error (user denied access or other issues).
        // check if we have an SSO login request and redirect to SSO login server
        if (isset($_GET['keycloak_sso_login']) && $_GET['keycloak_sso_login'] === 'true') {
            // initiate call to SSO login
            initiate_keycloak_login();
        }
        else{
        // TODO: Redirect to an error page.
        }
    }
}

function extract_user_info_from_id_token($id_token) {
    // Split the token into parts
    $token_parts = explode('.', $id_token);
    $payload = $token_parts[1];

    // Decode the payload (URL-safe base64 decoding)
    $payload_decoded = base64_decode(str_replace('_', '/', str_replace('-', '+', $payload)) . '=');
    $payload_json = json_decode($payload_decoded, true);

    // Extract user information
    $user_info = array(
        'email' => $payload_json['email'],
        'name' => $payload_json['name'],
        // TODO: Add other desired fields
    );

    return $user_info;
}

add_action( 'login_form', 'my_login_shortcode_button' );
function my_login_shortcode_button() {
    if (isset($_GET['keycloak_sso_login']) && $_GET['keycloak_sso_login'] === 'true') {
        // call our SSO handler
        handle_keycloak_callback();
    }    
    echo '<p class="submit"><a href="/wp-login.php?keycloak_sso_login=true" id="keycloak-sso-login-button" class="button button-primary button-large" style="margin-left:4px;">SSO Login</a></p>';
}

// Register hooks

add_action('template_redirect', 'handle_keycloak_callback');

// admin menu functions for settings and options

function keycloak_sso_register_settings() {
    register_setting( 'keycloak_sso_settings', 'keycloak_sso_settings' );

    add_settings_section(
        'keycloak_sso_basic_settings',
        __('Basic Settings', 'keycloak-sso'),
        'keycloak_sso_basic_settings_callback',
        'keycloak_sso_settings'
    );

    add_settings_field(
        'auth_server_url',
        __('Auth Server URL', 'keycloak-sso'),                      
        'keycloak_sso_auth_server_url_callback',
        'keycloak_sso_settings',
        'keycloak_sso_basic_settings'
    );

    add_settings_field(
        'realm',
        __('Realm', 'keycloak-sso'),                        
        'keycloak_sso_realm_callback',
        'keycloak_sso_settings',
        'keycloak_sso_basic_settings'
    );

    add_settings_field(
        'client_id',
        __('Client Id', 'keycloak-sso'),                      
        'keycloak_sso_realm_client_id',
        'keycloak_sso_settings',
        'keycloak_sso_basic_settings'
    );

    add_settings_field(
        'client_secret',
        __('Client Secret', 'keycloak-sso'),                        
        'keycloak_sso_realm_client_secret',
        'keycloak_sso_settings',
        'keycloak_sso_basic_settings'
    );            

    // Add more settings fields as needed
}
add_action('admin_init', 'keycloak_sso_register_settings');

function keycloak_sso_basic_settings_callback() {
    // No output required for this section
}

function keycloak_sso_auth_server_url_callback() {
    $options = get_option('keycloak_sso_settings');
    echo '<input type="text" name="keycloak_sso_settings[auth_server_url]" value="' . esc_attr($options['auth_server_url']) . '" size="80" />'; 
}
function keycloak_sso_realm_callback() {
    $options = get_option('keycloak_sso_settings');
    echo '<input type="text" name="keycloak_sso_settings[realm]" value="' . esc_attr($options['realm']) . '" />';
}
function keycloak_sso_realm_client_id() {
    $options = get_option('keycloak_sso_settings');
    echo '<input type="text" name="keycloak_sso_settings[client_id]" value="' . esc_attr($options['client_id']) . '" />';
}
function keycloak_sso_realm_client_secret() {
    $options = get_option('keycloak_sso_settings');
    echo '<input type="text" name="keycloak_sso_settings[client_secret]" value="' . esc_attr($options['client_secret']) . '" size="80" />';
}

function keycloak_sso_settings_page() {
    ?>
    <div class="wrap">
        <h1>Keycloak SSO Settings</h1>
        <form action="options.php" method="POST">
            <?php settings_fields('keycloak_sso_settings'); ?>
            <?php do_settings_sections('keycloak_sso_settings'); ?>
            <?php submit_button(); ?>
        </form>
    </div>
    <?php
}

function keycloak_sso_menu() {
    add_options_page('Keycloak SSO Settings', 'Keycloak SSO', 'manage_options', 'keycloak-sso-settings', 'keycloak_sso_settings_page');
}
add_action('admin_menu', 'keycloak_sso_menu');

function get_keycloak_config() {
    $options = get_option('keycloak_sso_settings');
    // hardcoded callback uri
    $options['redirect_uri'] = site_url('/keycloak-sso-callback');
    return $options;
}
