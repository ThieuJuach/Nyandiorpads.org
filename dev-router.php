<?php
/**
 * Router for PHP's built-in development server, which ignores .htaccess.
 * It applies the same protections locally:
 *
 *   php -S localhost:8000 dev-router.php
 *
 * - blocks the private/ folder, hidden files (.env, .htaccess) and dev files
 * - sends the same security headers as .htaccess
 *
 * Not used in production (Apache uses .htaccess, which also denies access to this file).
 */

if (PHP_SAPI !== 'cli-server') {
    http_response_code(404);
    exit;
}

define('NYANDIOR_APP', true);
require_once __DIR__ . '/private/config.php';
require_once __DIR__ . '/private/security.php';

$path = rawurldecode(parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH) ?? '/');
$segments = array_filter(explode('/', str_replace('\\', '/', $path)), 'strlen');

$blocked = false;
foreach ($segments as $segment) {
    // Hidden files/folders, and anything inside private/
    if ($segment[0] === '.' || strcasecmp($segment, 'private') === 0) {
        $blocked = true;
    }
}
$file = end($segments) ?: '';
if (strcasecmp($file, 'dev-router.php') === 0 || preg_match('/\.(md|example|log|json|ini|sh|bak)$/i', $file)) {
    $blocked = true;
}

if ($blocked) {
    send_security_headers();
    http_response_code(404);
    echo 'Not Found';
    return true;
}

// PHP scripts run normally (they send their own security headers)
if (preg_match('/\.php$/i', $file)) {
    return false;
}

// Static files are served here, because the built-in server drops any headers
// set by the router when it serves a file itself
$target = realpath(__DIR__ . '/' . ($path === '/' ? 'index.html' : ltrim($path, '/')));
if ($target === false || !is_file($target) || strpos($target, __DIR__ . DIRECTORY_SEPARATOR) !== 0) {
    send_security_headers();
    http_response_code(404);
    echo 'Not Found';
    return true;
}

$types = [
    'html' => 'text/html; charset=utf-8', 'css' => 'text/css; charset=utf-8',
    'js' => 'text/javascript; charset=utf-8', 'png' => 'image/png', 'jpg' => 'image/jpeg',
    'jpeg' => 'image/jpeg', 'gif' => 'image/gif', 'svg' => 'image/svg+xml',
    'webp' => 'image/webp', 'ico' => 'image/x-icon', 'mp4' => 'video/mp4',
];
$extension = strtolower(pathinfo($target, PATHINFO_EXTENSION));

send_security_headers();
header('Content-Type: ' . ($types[$extension] ?? 'application/octet-stream'));
header('Content-Length: ' . filesize($target));
readfile($target);
return true;
