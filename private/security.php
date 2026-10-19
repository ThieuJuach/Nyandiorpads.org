<?php
/**
 * Shared security helpers: HTTP security headers, client IP detection and
 * friendly error responses.
 */

if (!defined('NYANDIOR_APP')) {
    http_response_code(404);
    exit;
}

/**
 * Content Security Policy (OWASP: Content Security Policy Cheat Sheet).
 * Only our own files plus the exact third parties the site uses may load:
 *   - Google Fonts (stylesheet + font files)
 *   - Font Awesome from cdnjs (stylesheet + icon font)
 *   - The Google Maps embed on the contact page
 * Inline scripts are not allowed, which blocks most XSS payloads.
 *
 * KEEP IN SYNC with the Content-Security-Policy header in /.htaccess.
 */
const NYANDIOR_CSP = "default-src 'self'; "
    . "script-src 'self'; "
    . "style-src 'self' https://fonts.googleapis.com https://cdnjs.cloudflare.com; "
    . "font-src 'self' https://fonts.gstatic.com https://cdnjs.cloudflare.com; "
    . "img-src 'self' data:; "
    . "frame-src https://www.google.com; "
    . "connect-src 'self'; "
    . "object-src 'none'; "
    . "base-uri 'self'; "
    . "form-action 'self'; "
    . "frame-ancestors 'self'";

/**
 * Send the standard security headers (OWASP: HTTP Headers Cheat Sheet).
 * KEEP IN SYNC with /.htaccess.
 */
function send_security_headers(): void
{
    header_remove('X-Powered-By');                      // don't advertise the PHP version
    header('Content-Security-Policy: ' . NYANDIOR_CSP);
    header('X-Content-Type-Options: nosniff');          // stop browsers guessing file types
    header('X-Frame-Options: SAMEORIGIN');              // clickjacking protection (older browsers)
    header('Referrer-Policy: strict-origin-when-cross-origin');
    header('Permissions-Policy: camera=(), microphone=(), geolocation=(), payment=()');
    header('Cross-Origin-Opener-Policy: same-origin');

    // HSTS only makes sense over HTTPS; sending it over plain HTTP is ignored anyway
    if (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') {
        header('Strict-Transport-Security: max-age=31536000; includeSubDomains');
    }
}

/**
 * The client's IP address.
 *
 * X-Forwarded-For can be set to anything by the client, so it is only trusted
 * when the request really comes from one of our own proxies / load balancers
 * (listed in TRUSTED_PROXIES). Otherwise an attacker could dodge rate limits by
 * sending a different fake IP with every request.
 */
function client_ip(): string
{
    $remote = $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';
    $trusted = array_filter(array_map('trim', explode(',', env('TRUSTED_PROXIES', '') ?? '')));

    if ($trusted && in_array($remote, $trusted, true) && !empty($_SERVER['HTTP_X_FORWARDED_FOR'])) {
        // Walk the chain from the right; the first address that isn't our own proxy is the client
        $chain = array_reverse(array_map('trim', explode(',', $_SERVER['HTTP_X_FORWARDED_FOR'])));
        foreach ($chain as $ip) {
            if (filter_var($ip, FILTER_VALIDATE_IP) && !in_array($ip, $trusted, true)) {
                return $ip;
            }
        }
    }
    return $remote;
}

/**
 * True if the client asked for JSON (e.g. a fetch() call) rather than an HTML page.
 */
function wants_json(): bool
{
    return stripos($_SERVER['HTTP_ACCEPT'] ?? '', 'application/json') !== false;
}

/**
 * End the request with an error status and a friendly message, as JSON or as
 * a small page styled like the rest of the site. Used for 405, 413, 415 and 429.
 */
function send_error_response(int $status, string $title, string $message, int $retry_after = 0): void
{
    http_response_code($status);
    if ($retry_after > 0) {
        header('Retry-After: ' . $retry_after);
    }
    header('Cache-Control: no-store');

    if (wants_json()) {
        header('Content-Type: application/json; charset=utf-8');
        echo json_encode(array_filter([
            'error' => $title,
            'message' => $message,
            'retry_after' => $retry_after ?: null,
        ]));
        exit;
    }

    header('Content-Type: text/html; charset=utf-8');
    $title_html = htmlspecialchars($title, ENT_QUOTES, 'UTF-8');
    $message_html = htmlspecialchars($message, ENT_QUOTES, 'UTF-8');
    echo <<<HTML
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<meta name="robots" content="noindex">
<title>{$title_html} | Nyandior Pads Initiative</title>
<link rel="stylesheet" href="style.css">
<link href="https://fonts.googleapis.com/css?family=Poppins:100,200,300,400,600,700&display=swap" rel="stylesheet">
</head>
<body>
    <section class="course">
        <h1>{$title_html}</h1>
        <p>{$message_html}</p>
        <p><a href="contact.html" class="hero-btn red-btn">Back to Contact Page</a></p>
        <p>Need us urgently? <a href="https://wa.me/254790454212">Message us on WhatsApp</a>.</p>
    </section>
</body>
</html>
HTML;
    exit;
}

/**
 * Describe a wait time in words, e.g. "about 7 minutes".
 */
function describe_wait(int $seconds): string
{
    if ($seconds < 90) {
        return 'a minute';
    }
    if ($seconds < 5400) {
        return 'about ' . (int) ceil($seconds / 60) . ' minutes';
    }
    return 'about ' . (int) ceil($seconds / 3600) . ' hours';
}
