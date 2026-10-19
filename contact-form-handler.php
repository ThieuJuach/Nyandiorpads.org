<?php
/**
 * Contact form endpoint: the site's only public endpoint that accepts input.
 *
 * Request pipeline (each step follows OWASP guidance):
 *   1. Only POST is accepted; anything else is sent back to the contact page.
 *   2. Request shape: size limit, form encoding only, no file uploads.
 *   3. Origin check: the form must be submitted from this site (CSRF defence).
 *   4. Rate limit per IP address.
 *   5. Schema validation of every field (allowlist, types, lengths, UTF-8).
 *   6. Honeypot: bots are given a fake "success" and nothing is sent.
 *   7. Rate limit per sender email address (the closest thing to a "user"
 *      on a site without accounts).
 *   8. Send a plain-text email. Configuration comes from environment
 *      variables (see private/.env.example), never from this file.
 *
 * Outcomes for the visitor (unchanged from before):
 *   success -> contact.html?status=success
 *   invalid -> contact.html?status=invalid   (validation failed)
 *   failure -> contact.html?status=error     (email could not be sent)
 *   too many requests -> HTTP 429 page with a Retry-After header
 */

// Never show PHP errors (file paths, code details) to visitors; they still go to the server log
ini_set('display_errors', '0');
ini_set('log_errors', '1');

defined('NYANDIOR_APP') || define('NYANDIOR_APP', true);
require_once __DIR__ . '/private/config.php';
require_once __DIR__ . '/private/security.php';
require_once __DIR__ . '/private/Validator.php';
require_once __DIR__ . '/private/RateLimiter.php';

send_security_headers();
header('Cache-Control: no-store');

// ---------------------------------------------------------------------------
// Settings (all overridable through environment variables)
// ---------------------------------------------------------------------------

// Maximum accepted request body. The real form is well under 6 KB.
const MAX_BODY_BYTES = 16384;

// Fields the contact form may send, and the rules for each.
// Limits match the maxlength attributes in contact.html.
const CONTACT_SCHEMA = [
    'name'    => ['type' => 'string', 'required' => true, 'min' => 2, 'max' => 100,  'single_line' => true],
    'email'   => ['type' => 'email',  'required' => true, 'min' => 6, 'max' => 254,  'single_line' => true],
    'subject' => ['type' => 'string', 'required' => true, 'min' => 2, 'max' => 150,  'single_line' => true],
    'message' => ['type' => 'string', 'required' => true, 'min' => 2, 'max' => 5000],
    'website' => ['type' => 'honeypot'],
];

function redirect_to_contact(string $status): void
{
    header('Location: contact.html?status=' . rawurlencode($status), true, 303);
    exit;
}

// ---------------------------------------------------------------------------
// 1. Method
// ---------------------------------------------------------------------------
if (($_SERVER['REQUEST_METHOD'] ?? '') !== 'POST') {
    // Opening the handler directly in a browser just shows the contact page
    header('Location: contact.html');
    exit;
}

// ---------------------------------------------------------------------------
// 2. Request shape
// ---------------------------------------------------------------------------
if ((int) ($_SERVER['CONTENT_LENGTH'] ?? 0) > MAX_BODY_BYTES) {
    send_error_response(413, 'Message too large', 'Your message is too long to send. Please shorten it and try again.');
}

// The form sends normal URL-encoded data. Multipart requests (file uploads)
// and anything else are refused, and uploaded files are never accepted.
$content_type = strtolower(trim(explode(';', $_SERVER['CONTENT_TYPE'] ?? '')[0]));
if ($content_type !== 'application/x-www-form-urlencoded' || !empty($_FILES)) {
    send_error_response(415, 'Unsupported request', 'This form only accepts text. File uploads are not allowed.');
}

// ---------------------------------------------------------------------------
// 3. Origin check (OWASP CSRF Prevention: verify origin with standard headers)
// ---------------------------------------------------------------------------
// Browsers send Origin on form POSTs. If it is present it must match this site.
$origin = $_SERVER['HTTP_ORIGIN'] ?? '';
if ($origin !== '' && $origin !== 'null') {
    $origin_host = parse_url($origin, PHP_URL_HOST);
    $own_host = parse_url('http://' . ($_SERVER['HTTP_HOST'] ?? ''), PHP_URL_HOST);
    if (!$origin_host || !$own_host || strcasecmp($origin_host, $own_host) !== 0) {
        send_error_response(403, 'Request blocked', 'This form can only be submitted from the Nyandior Pads website.');
    }
}

// ---------------------------------------------------------------------------
// 4. Rate limit per IP
// ---------------------------------------------------------------------------
$rate_limit_secret = env('RATE_LIMIT_SECRET');
if ($rate_limit_secret === null) {
    // Still works, but stored keys are easier to reverse; set RATE_LIMIT_SECRET in production
    error_log('contact-form: RATE_LIMIT_SECRET is not set');
    $rate_limit_secret = __DIR__;
}
$limiter = new RateLimiter(
    env('RATE_LIMIT_DIR', __DIR__ . '/private/storage/ratelimit'),
    $rate_limit_secret
);

// Defaults: 5 submissions per 10 minutes and 20 per day from one IP address.
// Generous for real people, but stops floods and scripted abuse.
$ip_retry = $limiter->hit('ip:' . client_ip(), [
    [env_int('RATE_LIMIT_IP_SHORT_MAX', 5), env_int('RATE_LIMIT_IP_SHORT_WINDOW', 600)],
    [env_int('RATE_LIMIT_IP_DAILY_MAX', 20), 86400],
]);
if ($ip_retry > 0) {
    send_error_response(
        429,
        'Too many messages',
        'You have sent several messages in a short time. Please wait ' . describe_wait($ip_retry) . ' and try again.',
        $ip_retry
    );
}

// ---------------------------------------------------------------------------
// 5. Validation
// ---------------------------------------------------------------------------
$validator = new Validator(CONTACT_SCHEMA);
if (!$validator->validate($_POST)) {
    // Log which fields failed (never their contents) to help spot abuse or bugs
    error_log('contact-form: rejected input in fields: ' . implode(', ', array_keys($validator->errors)));
    redirect_to_contact('invalid');
}

// ---------------------------------------------------------------------------
// 6. Honeypot
// ---------------------------------------------------------------------------
if ($validator->is_bot) {
    // Pretend it worked so the bot has no reason to try again
    redirect_to_contact('success');
}

$name = $validator->data['name'];
$visitor_email = $validator->data['email'];
$subject = $validator->data['subject'];
$message = $validator->data['message'];

// ---------------------------------------------------------------------------
// 7. Rate limit per sender email (default: 3 per hour, 10 per day)
// ---------------------------------------------------------------------------
$email_retry = $limiter->hit('email:' . strtolower($visitor_email), [
    [env_int('RATE_LIMIT_EMAIL_HOURLY_MAX', 3), 3600],
    [env_int('RATE_LIMIT_EMAIL_DAILY_MAX', 10), 86400],
]);
if ($email_retry > 0) {
    send_error_response(
        429,
        'Too many messages',
        'We have already received several messages from this email address. Please wait '
            . describe_wait($email_retry) . ' before sending another.',
        $email_retry
    );
}

// ---------------------------------------------------------------------------
// 8. Send
// ---------------------------------------------------------------------------
$email_to = env('CONTACT_TO_EMAIL');
// Sent from an address on the site's own domain so the email isn't rejected
// as spoofed; replies still go to the visitor through Reply-To
$email_from = env('CONTACT_FROM_EMAIL');

if (!filter_var($email_to, FILTER_VALIDATE_EMAIL) || !filter_var($email_from, FILTER_VALIDATE_EMAIL)) {
    // Fail closed: never fall back to a hardcoded address
    error_log('contact-form: CONTACT_TO_EMAIL / CONTACT_FROM_EMAIL are missing or invalid');
    redirect_to_contact('error');
}

$email_subject = "Contact Form: $subject";
$email_body = "You received a new message:\n\n" .
              "Name: $name\n" .
              "Email: $visitor_email\n" .
              "Subject: $subject\n\n" .
              "Message:\n$message\n";

// Every value used in a header has passed single-line validation above
$headers = "From: Nyandior Pads Website <$email_from>\r\n";
$headers .= "Reply-To: $visitor_email\r\n";
$headers .= "Content-Type: text/plain; charset=UTF-8\r\n";

if (mail($email_to, '=?UTF-8?B?' . base64_encode($email_subject) . '?=', $email_body, $headers)) {
    redirect_to_contact('success');
} else {
    redirect_to_contact('error');
}
