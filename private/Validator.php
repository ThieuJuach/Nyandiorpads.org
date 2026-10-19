<?php
/**
 * Schema-based input validation (OWASP: Input Validation Cheat Sheet).
 *
 * Every public form declares a schema listing exactly which fields it accepts
 * and the rules for each. Input is validated against an allowlist:
 *   - fields that are not in the schema are rejected
 *   - every value must be a plain string (arrays such as name[]=x are rejected)
 *   - text must be valid UTF-8 with no control characters
 *   - lengths are checked in characters, not bytes
 *   - single-line fields may not contain line breaks (prevents email header injection)
 *   - emails must be syntactically valid
 *
 * Rules per field:
 *   type        'string' | 'email' | 'honeypot'
 *   required    true if the field must be present and non-empty
 *   min, max    length limits in characters
 *   single_line true to reject line breaks
 */

if (!defined('NYANDIOR_APP')) {
    http_response_code(404);
    exit;
}

final class Validator
{
    /** Valid input, keyed by field name (honeypot fields are excluded). */
    public array $data = [];

    /** Human-readable problems, keyed by field name. */
    public array $errors = [];

    /** True if a honeypot field was filled in, i.e. the sender is almost certainly a bot. */
    public bool $is_bot = false;

    public function __construct(private array $schema)
    {
    }

    public function validate(array $input): bool
    {
        $this->data = [];
        $this->errors = [];
        $this->is_bot = false;

        // Reject fields we don't expect instead of silently ignoring them
        foreach (array_keys($input) as $field) {
            if (!array_key_exists($field, $this->schema)) {
                $this->errors['_form'] = 'Unexpected field submitted.';
                return false;
            }
        }

        foreach ($this->schema as $field => $rules) {
            $value = $input[$field] ?? '';

            if (!is_string($value)) {
                $this->errors[$field] = 'Invalid value.';
                continue;
            }

            if (($rules['type'] ?? 'string') === 'honeypot') {
                // Hidden from people, so anything in it came from a bot
                if ($value !== '') {
                    $this->is_bot = true;
                }
                continue;
            }

            $clean = $this->sanitize($value, !empty($rules['single_line']));
            if ($clean === null) {
                $this->errors[$field] = 'Contains invalid characters.';
                continue;
            }

            if ($clean === '') {
                if (!empty($rules['required'])) {
                    $this->errors[$field] = 'This field is required.';
                }
                $this->data[$field] = '';
                continue;
            }

            $length = mb_strlen($clean, 'UTF-8');
            if (isset($rules['min']) && $length < $rules['min']) {
                $this->errors[$field] = "Must be at least {$rules['min']} characters.";
                continue;
            }
            if (isset($rules['max']) && $length > $rules['max']) {
                $this->errors[$field] = "Must be at most {$rules['max']} characters.";
                continue;
            }

            if (($rules['type'] ?? 'string') === 'email' && filter_var($clean, FILTER_VALIDATE_EMAIL) === false) {
                $this->errors[$field] = 'Must be a valid email address.';
                continue;
            }

            $this->data[$field] = $clean;
        }

        return $this->errors === [];
    }

    /**
     * Normalise and sanitise one text value. Returns null if it cannot be made safe.
     */
    private function sanitize(string $value, bool $single_line): ?string
    {
        if (!mb_check_encoding($value, 'UTF-8')) {
            return null;
        }

        // Normalise line endings, then reject line breaks where they aren't allowed.
        // This is what stops "Name\r\nBcc: someone@example.com" header injection.
        $value = str_replace(["\r\n", "\r"], "\n", $value);
        if ($single_line && strpos($value, "\n") !== false) {
            return null;
        }

        // Remove HTML tags, then any remaining control characters
        // (tabs and newlines are kept in multi-line text)
        $value = strip_tags($value);
        $value = preg_replace('/[^\P{C}\n\t]/u', '', $value);

        return trim($value);
    }
}
