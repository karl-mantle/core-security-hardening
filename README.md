# Core Security Hardening

A must-use WordPress plugin that turns off features most sites don't use. Works on standard WordPress and Bedrock.

## What it does

Each feature can be turned off under Settings -> General -> Hardening.

| Feature                            | Constant                                        | Default |
| ---------------------------------- | ----------------------------------------------- | ------- |
| Disable XML-RPC                    | `CORE_SECURITY_HARDENING_XMLRPC`                | On      |
| Block username enumeration         | `CORE_SECURITY_HARDENING_AUTHOR_ENUMERATION`    | On      |
| Require login for the REST API     | `CORE_SECURITY_HARDENING_REST_AUTH`             | On      |
| Disable comments                   | `CORE_SECURITY_HARDENING_COMMENTS`              | On      |
| Hide version numbers               | `CORE_SECURITY_HARDENING_GENERATOR`             | On      |
| Generic login errors               | `CORE_SECURITY_HARDENING_LOGIN_ERRORS`          | On      |
| Send security headers              | `CORE_SECURITY_HARDENING_SECURITY_HEADERS`      | On      |
| Send HSTS header                   | `CORE_SECURITY_HARDENING_HSTS`                  | Off     |
| Restrict unfiltered HTML to admins | `CORE_SECURITY_HARDENING_UNFILTERED_HTML`       | On      |
| Disable the file editor            | `CORE_SECURITY_HARDENING_FILE_EDIT`             | On      |
| Clean up the page head             | `CORE_SECURITY_HARDENING_HEAD_CLEANUP`          | On      |
| Disable application passwords      | `CORE_SECURITY_HARDENING_APPLICATION_PASSWORDS` | Off     |

## Installation

### Standard WordPress

Copy this folder into `wp-content/mu-plugins/core-security-hardening/`. WordPress doesn't load must-use plugins from subfolders on its own, so also create `wp-content/mu-plugins/core-security-hardening.php` containing:

```php
<?php
require_once __DIR__ . '/core-security-hardening/core-security-hardening.php';
```

Or install it as a regular plugin: copy the folder into `wp-content/plugins/` and activate it. It can then be deactivated from the admin.

### Bedrock

```bash
composer require karlmantle/core-security-hardening
```

It installs into `web/app/mu-plugins/`, where Bedrock's autoloader picks it up.

## Configuration

Overrides the setting in the admin, and the checkbox shows as locked.

```php
// wp-config.php
define('CORE_SECURITY_HARDENING_REST_AUTH', false);

// Bedrock: config/application.php
Config::define('CORE_SECURITY_HARDENING_REST_AUTH', false);
```

If your web server already sends security headers (for example with `add_header` in nginx), turn off the plugin's versions so they aren't sent twice:

```php
// wp-config.php
define('CORE_SECURITY_HARDENING_SECURITY_HEADERS', false);
define('CORE_SECURITY_HARDENING_HSTS', false);

// Bedrock: config/application.php
Config::define('CORE_SECURITY_HARDENING_SECURITY_HEADERS', false);
Config::define('CORE_SECURITY_HARDENING_HSTS', false);
```

With the REST API locked down, some plugins (contact forms 7, WooCommerce blocks) need public routes. Allow them with a filter:

```php
add_filter('core_security_hardening_rest_public_routes', function ($routes) {
    $routes[] = '/contact-form-7/v1';
    return $routes;
});
```

## Licence

MIT. See [LICENSE](LICENSE).
