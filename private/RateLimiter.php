<?php
/**
 * File-based sliding-window rate limiter (OWASP: Denial of Service and
 * Automated Threats guidance). Needs no database, so it works on basic shared hosting.
 *
 * Each "key" (for example an IP address or an email address) gets one small
 * file holding the timestamps of its recent requests. A key is limited by one
 * or more rules, e.g. "5 per 10 minutes AND 20 per day".
 *
 * Privacy: keys are hashed with a secret (HMAC-SHA256) before being used as
 * file names, so IP and email addresses are never written to disk.
 *
 * Fails open: if the storage folder can't be written, the request is allowed
 * and the problem is logged, so a server misconfiguration doesn't take the
 * contact form down.
 */

if (!defined('NYANDIOR_APP')) {
    http_response_code(404);
    exit;
}

final class RateLimiter
{
    public function __construct(
        private string $storage_dir,
        private string $secret
    ) {
    }

    /**
     * Record one attempt for $key and check it against $rules.
     *
     * @param string $key   identifier, e.g. "ip:203.0.113.5" or "email:a@b.org"
     * @param array  $rules list of [max_attempts, window_seconds]
     * @return int 0 if allowed, otherwise the number of seconds until the caller may retry
     */
    public function hit(string $key, array $rules): int
    {
        try {
            return $this->record($key, $rules);
        } catch (\Throwable $e) {
            // Fail open: a storage problem must not take the contact form down
            error_log('RateLimiter: ' . $e->getMessage());
            return 0;
        }
    }

    private function record(string $key, array $rules): int
    {
        if (!$this->ensureStorage()) {
            return 0;
        }

        $now = time();
        $longest_window = max(array_column($rules, 1));
        $path = $this->storage_dir . DIRECTORY_SEPARATOR . hash_hmac('sha256', $key, $this->secret) . '.json';

        $handle = @fopen($path, 'c+');
        if ($handle === false) {
            error_log('RateLimiter: cannot open storage file');
            return 0;
        }

        try {
            // Exclusive lock so simultaneous requests can't both slip under the limit
            flock($handle, LOCK_EX);

            $timestamps = json_decode(stream_get_contents($handle) ?: '[]', true);
            if (!is_array($timestamps)) {
                $timestamps = [];
            }

            // Forget attempts older than the longest window
            $timestamps = array_values(array_filter(
                $timestamps,
                fn ($t) => is_int($t) && $t > $now - $longest_window
            ));

            $retry_after = 0;
            foreach ($rules as [$max, $window]) {
                $in_window = array_values(array_filter($timestamps, fn ($t) => $t > $now - $window));
                if (count($in_window) >= $max) {
                    // The caller may retry once the oldest attempt in this window expires
                    $retry_after = max($retry_after, $in_window[count($in_window) - $max] + $window - $now);
                }
            }

            // Blocked attempts are not recorded, so a blocked client isn't locked out for longer
            if ($retry_after === 0) {
                $timestamps[] = $now;
            }

            ftruncate($handle, 0);
            rewind($handle);
            fwrite($handle, json_encode($timestamps));
            fflush($handle);

            return max(0, $retry_after);
        } finally {
            flock($handle, LOCK_UN);
            fclose($handle);
            $this->maybeCleanUp($longest_window);
        }
    }

    private function ensureStorage(): bool
    {
        if (is_dir($this->storage_dir) || @mkdir($this->storage_dir, 0700, true)) {
            if (is_writable($this->storage_dir)) {
                return true;
            }
        }
        error_log('RateLimiter: storage directory is not writable: ' . $this->storage_dir);
        return false;
    }

    /**
     * Occasionally delete files for keys that have been idle for a day or longer,
     * so the storage folder doesn't grow forever.
     */
    private function maybeCleanUp(int $longest_window): void
    {
        if (random_int(1, 100) !== 1) {
            return;
        }
        $cutoff = time() - max($longest_window, 86400);
        foreach (glob($this->storage_dir . DIRECTORY_SEPARATOR . '*.json') ?: [] as $file) {
            if (@filemtime($file) < $cutoff) {
                @unlink($file);
            }
        }
    }
}
