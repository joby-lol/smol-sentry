<?php

/**
 * smolSentry
 * https://github.com/joby-lol/smol-sentry
 * (c) 2026 Joby Elliott code@joby.lol
 * MIT License https://opensource.org/licenses/MIT
 */

namespace Joby\Smol\Sentry;

readonly class Score
{

    public int $time;

    /**
     * @param string $ip The IP/range string for this score
     * @param bool $range Whether this score is for a range, rather than an individual IP
     * @param int $score The abuse confidence score, or rough aggregate for a range
     * @param int $checked_at When this score was retrieved from the AbuseIPDB API
     * @param int $refresh_at The time at which this score should be considered stale enough to refresh if quota exists
     * @param int $ignore_at The time at which this score should be considered so stale that it is no longer valid
     * @param int|null $time The time that should be considered "now"
     */
    public function __construct(
        public string $ip,
        public bool $range,
        public int $score,
        public int $checked_at,
        public int $refresh_at,
        public int $ignore_at,
        int|null $time = null,
    )
    {
        $this->time = $time ?? time();
    }

    /**
     * Whether or not this result is stale enough that it should be considered for a refresh from the API.
     * @return bool
     */
    public function stale(): bool
    {
        return $this->time >= $this->refresh_at;
    }

    /**
     * Whether this result is so old that it should be considered entirely invalid.
     * @return bool
     */
    public function expired(): bool
    {
        return $this->time >= $this->ignore_at;
    }

}
