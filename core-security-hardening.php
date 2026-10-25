<?php
/**
 * Plugin Name: Core Security Hardening
 * Description: Disables various seldom used features of WordPress to improve security.
 *              Works for standard and bedrock WordPress installs.
 *              Each feature can be toggled under Settings > General > Hardening,
 *              or locked from config with a CORE_SECURITY_HARDENING_<FEATURE> constant.
 * Version: 1.1.0
 * Author: Karl Mantle
 * License: MIT
 */

if (!defined('ABSPATH')) {
    exit;
}

require_once __DIR__ . '/src/plugin.php';
