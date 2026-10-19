<?php
/**
 * Configuration loader.
 *
 * Secrets and deployment-specific values are never hardcoded in the code
 * (OWASP: Secrets Management). They are read, in order of priority, from:
 *
 *   1. Real environment variables (set in your hosting control panel,
 *      an Apache "SetEnv" directive, or the server's environment).
 *   2. A settings file, the first one found of:
 *      a. the path in the NYANDIOR_ENV_FILE environment variable
 *      b. "nyandior.env" in the folder ABOVE the website's root folder
 *         (on Hostinger: domains/nyandiorpads.org/nyandior.env, next to
 *         public_html). Recommended for production: files outside the web
 *         root can never be downloaded, even if .htaccess stops working.
 *      c. private/.env (convenient for local development; the web server is
 *         configured never to serve it, see private/.htaccess and dev-router.php)
 *
 * See private/.env.example for every supported setting.
 */

if (!defined('NYANDIOR_APP')) {
    // This file must only be included by our own scripts, never requested directly
    http_response_code(404);
    exit;
}

/**
 * Parse a simple KEY=VALUE .env file. Blank lines and lines starting with #
 * are ignored; values may be wrapped in single or double quotes.
 */
function nyandior_parse_env_file(string $path): array
{
    if (!is_file($path) || !is_readable($path)) {
        return [];
    }

    $values = [];
    foreach (file($path, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) as $line) {
        $line = trim($line);
        if ($line === '' || $line[0] === '#' || strpos($line, '=') === false) {
            continue;
        }
        [$key, $value] = array_map('trim', explode('=', $line, 2));
        if (!preg_match('/^[A-Z][A-Z0-9_]*$/', $key)) {
            continue;
        }
        if (strlen($value) >= 2 && ($value[0] === '"' || $value[0] === "'") && substr($value, -1) === $value[0]) {
            $value = substr($value, 1, -1);
        }
        $values[$key] = $value;
    }
    return $values;
}

/**
 * Read a setting. Real environment variables always win over the .env file.
 */
function env(string $key, ?string $default = null): ?string
{
    static $file_values = null;

    if ($file_values === null) {
        $file_values = [];
        $candidates = [
            getenv('NYANDIOR_ENV_FILE') ?: null,
            dirname(__DIR__, 2) . '/nyandior.env',   // outside the web root
            __DIR__ . '/.env',                         // private/.env
        ];
        foreach (array_filter($candidates) as $env_file) {
            if (is_file($env_file)) {
                $file_values = nyandior_parse_env_file($env_file);
                break;
            }
        }
    }

    foreach ([getenv($key), $_SERVER[$key] ?? false, $_ENV[$key] ?? false] as $value) {
        if ($value !== false && $value !== '') {
            return (string) $value;
        }
    }
    return $file_values[$key] ?? $default;
}

/**
 * Read an integer setting, falling back to the default if it is missing or invalid.
 */
function env_int(string $key, int $default): int
{
    $value = env($key);
    return ($value !== null && ctype_digit($value)) ? (int) $value : $default;
}
