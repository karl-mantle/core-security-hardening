<?php
/**
 * Main, loaded by core-security-hardening.php
 */

namespace KarlMantle\CoreSecurityHardening;

if (!defined('ABSPATH')) {
    exit;
}

const OPTION = 'core_security_hardening';
const CONSTANT_PREFIX = 'CORE_SECURITY_HARDENING_';

// remember whether DISALLOW_FILE_EDIT came from config (bedrock sets it) before this plugin defines it
define(__NAMESPACE__ . '\FILE_EDIT_IN_CONFIG', defined('DISALLOW_FILE_EDIT'));

function features()
{
    return [
        'xmlrpc' => [
            'label' => 'Disable XML-RPC',
            'description' => 'Blocks every request to xmlrpc.php, including pingbacks and system.multicall, and removes the X-Pingback header and RSD link. Jetpack and the old mobile apps need XML-RPC.',
            'default' => true,
        ],
        'author_enumeration' => [
            'label' => 'Block username enumeration',
            'description' => 'Redirects author archives and ?author= queries to the home page, removes users from the sitemap and oEmbed data, and hides the REST API users endpoints from logged-out visitors.',
            'default' => true,
        ],
        'rest_auth' => [
            'label' => 'Require login for the REST API',
            'description' => 'Logged-out visitors get a 401 from every REST API route. Contact forms and WooCommerce blocks need some public routes; allow them with the core_security_hardening_rest_public_routes filter.',
            'default' => true,
        ],
        'comments' => [
            'label' => 'Disable comments',
            'description' => 'Closes comments and pingbacks, hides existing comments, and removes comments from the admin and feeds.',
            'default' => true,
        ],
        'generator' => [
            'label' => 'Hide WordPress version',
            'description' => 'Removes the generator tag from the page head and feeds.',
            'default' => true,
        ],
        'login_errors' => [
            'label' => 'Generic login errors',
            'description' => 'Shows the same error for a wrong username or a wrong password, so the login form doesn\'t confirm which usernames exist.',
            'default' => true,
        ],
        'security_headers' => [
            'label' => 'Send security headers',
            'description' => 'Adds X-Content-Type-Options, Referrer-Policy, X-Frame-Options and Permissions-Policy headers to front-end pages.',
            'default' => true,
        ],
        'file_edit' => [
            'label' => 'Disable the file editor',
            'description' => 'Defines DISALLOW_FILE_EDIT to remove the theme and plugin file editors. Bedrock already sets this in config/application.php.',
            'default' => true,
        ],
        'head_cleanup' => [
            'label' => 'Clean up the page head',
            'description' => 'Removes the shortlink and REST API discovery links from the page head and response headers.',
            'default' => true,
        ],
        'application_passwords' => [
            'label' => 'Disable application passwords',
            'description' => 'Turns off application passwords. Leave this unticked if anything signs in to the REST API with one.',
            'default' => false,
        ],
    ];
}

// name of the constant that locks a feature, or null if it can be changed in the admin
function locked_by($key)
{
    if ($key === 'file_edit' && FILE_EDIT_IN_CONFIG) {
        return 'DISALLOW_FILE_EDIT';
    }
    $constant = CONSTANT_PREFIX . strtoupper($key);
    return defined($constant) ? $constant : null;
}

function is_enabled($key)
{
    $constant = locked_by($key);
    if ($constant !== null) {
        return (bool) constant($constant);
    }
    $saved = get_option(OPTION);
    if (is_array($saved) && isset($saved[$key])) {
        return (bool) $saved[$key];
    }
    return features()[$key]['default'];
}

// the requested REST route, lowercased because core matches routes case-insensitively
function current_rest_route()
{
    $route = isset($GLOBALS['wp']->query_vars['rest_route']) ? $GLOBALS['wp']->query_vars['rest_route'] : '';
    return is_string($route) ? '/' . trim(strtolower($route), '/') : '/';
}

/*
 * Settings > General > Hardening
 */

add_action('admin_init', function () {
    register_setting('general', OPTION, [
        'type' => 'array',
        'sanitize_callback' => __NAMESPACE__ . '\sanitize',
        'show_in_rest' => false,
    ]);

    add_settings_section(OPTION, 'Hardening', function () {
        echo '<p>Turn individual security features on or off. A feature locked from config shows which constant sets it.</p>';
    }, 'general');

    foreach (features() as $key => $feature) {
        add_settings_field(OPTION . '_' . $key, $feature['label'], __NAMESPACE__ . '\render_field', 'general', OPTION, [
            'key' => $key,
            'label_for' => OPTION . '_' . $key,
        ]);
    }
});

function render_field($args)
{
    $key = $args['key'];
    $constant = locked_by($key);
    printf(
        '<label><input type="checkbox" id="%1$s" name="%2$s[%3$s]" value="1"%4$s%5$s> %6$s</label>',
        esc_attr($args['label_for']),
        esc_attr(OPTION),
        esc_attr($key),
        checked(is_enabled($key), true, false),
        disabled($constant !== null, true, false),
        esc_html(features()[$key]['description'])
    );
    if ($constant !== null) {
        printf('<p class="description">Locked by <code>%s</code> in config.</p>', esc_html($constant));
    }
}

function sanitize($input)
{
    $input = is_array($input) ? $input : [];
    $saved = get_option(OPTION);
    $saved = is_array($saved) ? $saved : [];
    $clean = [];
    foreach (features() as $key => $feature) {
        // locked checkboxes are disabled so aren't submitted; keep what was saved before
        if (locked_by($key) !== null) {
            if (isset($saved[$key])) {
                $clean[$key] = (bool) $saved[$key];
            }
            continue;
        }
        $clean[$key] = !empty($input[$key]);
    }
    return $clean;
}

/*
 * Features
 */

// disable XML-RPC completely, including pingback.ping and system.multicall
if (is_enabled('xmlrpc')) {
    if (defined('XMLRPC_REQUEST') && XMLRPC_REQUEST) {
        status_header(403);
        exit('XML-RPC is disabled.');
    }
    add_filter('xmlrpc_enabled', '__return_false');
    add_filter('wp_headers', function ($headers) {
        unset($headers['X-Pingback']);
        return $headers;
    });
    remove_action('wp_head', 'rsd_link');
}

// block the ways usernames leak out: author archives, sitemaps, oEmbed and the REST users endpoints
if (is_enabled('author_enumeration')) {
    // priority 1 runs before core's redirect_canonical turns ?author=1 into /author/<username>/
    add_action('template_redirect', function () {
        if (is_author()) {
            wp_safe_redirect(home_url(), 301);
            exit;
        }
    }, 1);
    add_filter('wp_sitemaps_add_provider', function ($provider, $name) {
        return $name === 'users' ? false : $provider;
    }, 10, 2);
    add_filter('oembed_response_data', function ($data) {
        unset($data['author_name'], $data['author_url']);
        return $data;
    });
    // removing the routes also stops ?_embed leaking user slugs through post responses
    add_filter('rest_endpoints', function ($endpoints) {
        if (is_user_logged_in()) {
            return $endpoints;
        }
        foreach (array_keys($endpoints) as $route) {
            if (strpos($route, '/wp/v2/users') === 0) {
                unset($endpoints[$route]);
            }
        }
        return $endpoints;
    });
}

// restrict the public REST API to authenticated users, apart from routes allowed by filter
if (is_enabled('rest_auth')) {
    add_filter('rest_authentication_errors', function ($result) {
        if (!empty($result) || is_user_logged_in()) {
            return $result;
        }

        /**
         * Route prefixes logged-out visitors may still use, e.g. '/contact-form-7/v1' or '/wc/store'.
         *
         * @param string[] $routes
         */
        $public_routes = apply_filters('core_security_hardening_rest_public_routes', []);
        $route = current_rest_route();
        foreach ((array) $public_routes as $public_route) {
            $public_route = '/' . trim(strtolower($public_route), '/');
            if ($route === $public_route || strpos($route, $public_route . '/') === 0) {
                return $result;
            }
        }

        return new \WP_Error(
            'rest_not_logged_in',
            'Authentication required.',
            ['status' => 401]
        );
    });
}

// disable comments and pingbacks globally, and hide what's left of them
if (is_enabled('comments')) {
    add_filter('comments_open', '__return_false', 20);
    add_filter('pings_open', '__return_false', 20);
    add_filter('comments_array', '__return_empty_array', 20);
    add_filter('get_comments_number', '__return_zero', 20);
    add_filter('feed_links_show_comments_feed', '__return_false');
    add_filter('wp_insert_post_data', function ($data) {
        $data['comment_status'] = 'closed';
        $data['ping_status'] = 'closed';
        return $data;
    });

    // late, so post types registered by themes and plugins are included
    add_action('init', function () {
        foreach (get_post_types() as $post_type) {
            remove_post_type_support($post_type, 'comments');
            remove_post_type_support($post_type, 'trackbacks');
        }
    }, 100);

    add_action('template_redirect', function () {
        if (is_comment_feed()) {
            wp_die('Comments are disabled.', '', ['response' => 404]);
        }
    }, 1);

    add_action('admin_menu', function () {
        remove_menu_page('edit-comments.php');
    });
    add_action('admin_init', function () {
        global $pagenow;
        if ($pagenow === 'edit-comments.php') {
            wp_safe_redirect(admin_url());
            exit;
        }
    });
    add_action('admin_bar_menu', function ($admin_bar) {
        $admin_bar->remove_node('comments');
    }, 100);
}

// remove the WordPress version from the page head and feeds
if (is_enabled('generator')) {
    add_filter('the_generator', '__return_empty_string');
}

// replace "unknown username" and "wrong password" errors with one generic message
if (is_enabled('login_errors')) {
    add_filter('authenticate', function ($user) {
        $leaky_codes = ['invalid_username', 'invalid_email', 'incorrect_password'];
        if (is_wp_error($user) && array_intersect($user->get_error_codes(), $leaky_codes)) {
            return new \WP_Error(
                'invalid_credentials',
                '<strong>Error:</strong> The username or password is incorrect.'
            );
        }
        return $user;
    }, 100);
}

// add common security headers to front-end responses, without overriding ones already set
if (is_enabled('security_headers')) {
    add_filter('wp_headers', function ($headers, $wp) {
        $headers += [
            'X-Content-Type-Options' => 'nosniff',
            'Referrer-Policy' => 'strict-origin-when-cross-origin',
            'Permissions-Policy' => 'camera=(), microphone=(), geolocation=()',
        ];
        // embed pages are meant to be framed by other sites
        if (empty($wp->query_vars['embed']) && !isset($headers['X-Frame-Options'])) {
            $headers['X-Frame-Options'] = 'SAMEORIGIN';
        }
        return $headers;
    }, 10, 2);
}

// disable the theme and plugin file editors
if (is_enabled('file_edit') && !defined('DISALLOW_FILE_EDIT')) {
    define('DISALLOW_FILE_EDIT', true);
}

// remove discovery links that aren't needed on most sites
if (is_enabled('head_cleanup')) {
    remove_action('wp_head', 'wp_shortlink_wp_head', 10);
    remove_action('template_redirect', 'wp_shortlink_header', 11);
    remove_action('wp_head', 'rest_output_link_wp_head', 10);
    remove_action('template_redirect', 'rest_output_link_header', 11);
}

if (is_enabled('application_passwords')) {
    add_filter('wp_is_application_passwords_available', '__return_false');
}
