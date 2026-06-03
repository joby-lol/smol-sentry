<?php

/**
 * smolSentry
 * https://github.com/joby-lol/smol-sentry
 * (c) 2026 Joby Elliott code@joby.lol
 * MIT License https://opensource.org/licenses/MIT
 */

namespace Joby\Smol\Sentry;

use InvalidArgumentException;
use Joby\Smol\Query\DB;
use Joby\Smol\Query\Migrator;
use SensitiveParameter;

class AbuseIpDb implements ReputationSourceInterface
{

    /**
     * @param DB $db the database to cache data in
     * @param string $api_key set to an API key to enable AbuseIPDB score lookups
     * @param int $challenge_threshold the threshold at which an AbuseIPDB score should result in a challenge
     * @param int $ban_threshold the threshold at which an AbuseIPDB score should result in a ban
     * @param int $cache_ttl the amount of time to cache an AbuseIPDB API result before it may be refreshed.
     * @param int $max_stale_ttl the maximum amount of time an AbuseIPDB score may be continued to be used, even if it is stale, to preserve API quota or if your API quota is exhausted.
     * @param int $ip_daily_refreshes the maximum number of daily refreshes the system will perform from AbuseIPDB for previously-looked-up IPs. Setting this lower than your API quota allows you to reserve the rest of your quota for completely new and unknown IPs.
     * @param int $range_daily_refreshes the maximum number of daily refreshes the system will perform from AbuseIPDB for previously-looked-up IP ranges. Setting this lower than your API quota allows you to reserve the rest of your quota for completely new and unknown IPs.
     * @param int $report_days the number of days of reports to ask AbuseIPDB to consider in API requests.
     */
    public function __construct(
        public readonly DB $db,
        #[SensitiveParameter]
        protected readonly string $api_key,
        public readonly int $challenge_threshold = 70,
        public readonly int $ban_threshold = 90,
        public readonly int $cache_ttl = 86400,
        public readonly int $max_stale_ttl = 86400 * 30,
        public readonly int $ip_daily_refreshes = 1500,
        public readonly int $range_daily_refreshes = 500,
        public readonly int $report_days = 30,
    ) {}

    /**
     * Check the given IP and its /24 or /48 block (IPv4/IPv6, respectively), and return an Outcome if it passes either the ban or challenge threshold, or null if it does not or the API is rate limited or non-functional.
     */
    public function check(string $ip_normalized): Outcome|null
    {
        // get current non-expired range score if possible
        $range_normalized = $this->rangeFromIp($ip_normalized);
        $range_score = $this->rangeScore($range_normalized);
        // attempt to refresh range score if it's stale or doesn't exist
        if ($range_score === null || $range_score->stale())
            $range_score = $this->refreshRangeScore($range_normalized, $range_score !== null)
                ?? $range_score;
        // if range is clean (exists with zero score), return null
        if ($range_score?->score === 0)
            return null;
        // attempt to look up individual IP
        $ip_score = $this->ipScore($ip_normalized);
        // attempt to refresh IP score if it's stale or doesn't exist
        if ($ip_score === null || $ip_score->stale())
            $ip_score = $this->refreshIpScore($ip_normalized, $ip_score !== null)
                ?? $ip_score;
        // if there is an IP score, return its outcome
        if ($ip_score)
            return $this->scoreToOutcome($ip_score);
        // otherwise we failed to look up or refresh any scores, so we have no opinion
        return null;
    }

    /**
     * Convert a score into an outcome
     */
    protected function scoreToOutcome(Score $score): Outcome|null
    {
        if ($score->score >= $this->ban_threshold)
            return Outcome::Ban;
        elseif ($score->score >= $this->challenge_threshold)
            return Outcome::Challenge;
        else
            return null;
    }

    /**
     * Attempt to refresh an individual IP address's score. Will only update if IP requests are not rate limited, and if this IP is already cached and the daily refresh rate has not been reached.
     */
    protected function refreshIpScore(string $ip_normalized, bool $exists_already): Score|null
    {
        // if we're rate limited return null
        if ($this->ipRateLimited())
            return null;
        // if this result already exists in the cache and we've exhausted our 24 hour limit return null
        if ($exists_already && $this->ipRefreshLimitReached())
            return null;
        // otherwise try to make an API request
        return $this->ipApiRequest($ip_normalized);
    }

    /**
     * Attempt to refresh a range's scores. Will only update if range requests are not rate limited, and if this range is already cached and the refresh rate has not been reached.
     */
    protected function refreshRangeScore(string $range_normalized, bool $exists_already): Score|null
    {
        // if we're rate limited return null
        if ($this->rangeRateLimited())
            return null;
        // if this result already exists in the cache and we've exhausted our 24 hour limit return null
        if ($exists_already && $this->rangeRefreshLimitReached())
            return null;
        // otherwise try to make an API request
        return $this->rangeApiRequest($range_normalized);
    }

    /**
     * Check whether we have reached the rolling 24-hour limit on refreshes of stale but not expired records for ranges.
     */
    protected function rangeRefreshLimitReached(): bool
    {
        return $this->db->select('abuseipdb_blocks')
            ->where('checked_at > ?', time() - 86400)
            ->count() >= $this->range_daily_refreshes;
    }

    /**
     * Check whether we have reached the rolling 24-hour limit on refreshes of stale but not expired records for individual IPs.
     */
    protected function ipRefreshLimitReached(): bool
    {
        return $this->db->select('abuseipdb')
            ->where('checked_at > ?', time() - 86400)
            ->count() >= $this->ip_daily_refreshes;
    }

    /**
     * Attempt to retrieve a non-expired score for a given IP range.
     */
    protected function rangeScore(string $range_normalized): Score|null
    {
        $score = $this->db->select('abuseipdb_blocks')
            ->where('ip', $range_normalized)
            ->hydrate(
                fn(array $row): Score => new Score(
                    $range_normalized,
                    true,
                    $row['score'],// @phpstan-ignore-line shape is right
                    $row['checked_at'],// @phpstan-ignore-line shape is right
                    $this->refreshAtTime($row['checked_at']),// @phpstan-ignore-line shape is right
                    $this->ignoreAtTime($row['checked_at']),// @phpstan-ignore-line shape is right
                )
            )
            ->fetch();
        if ($score && $score->expired())
            return null;
        return $score;
    }

    /**
     * Attempt to retrieve a non-expired score for a given individual IP.
     */
    protected function ipScore(string $ip_normalized): Score|null
    {
        $score = $this->db->select('abuseipdb')
            ->where('ip', $ip_normalized)
            ->hydrate(
                fn(array $row): Score => new Score(
                    $ip_normalized,
                    true,
                    $row['score'],// @phpstan-ignore-line shape is right
                    $row['checked_at'],// @phpstan-ignore-line shape is right
                    $this->refreshAtTime($row['checked_at']),// @phpstan-ignore-line shape is right
                    $this->ignoreAtTime($row['checked_at']),// @phpstan-ignore-line shape is right
                )
            )
            ->fetch();
        if ($score && $score->expired())
            return null;
        return $score;
    }

    /**
     * Determine the time at which a record set at $checked_at should be refreshed if possible.
     */
    protected function refreshAtTime(int $checked_at): int
    {
        return $checked_at + $this->cache_ttl;
    }

    /**
     * Determine the time at which a record set at $checked_at is so old it should be entirely ignored.
     */
    protected function ignoreAtTime(int $checked_at): int
    {
        return $checked_at + $this->max_stale_ttl;
    }

    /**
     * Return CIDR notation of the /24 block for IPv4 addresses or /48 block for IPv6 addresses
     */
    public static function rangeFromIp(string $ip_normalized): string
    {
        // IPv4: use /24
        $parts = explode('.', $ip_normalized);
        if (count($parts) === 4) {
            return $parts[0] . '.' . $parts[1] . '.' . $parts[2] . '.0/24';
        }
        // IPv6: use /48
        $binary = inet_pton($ip_normalized);
        if ($binary === false || strlen($binary) !== 16)
            throw new InvalidArgumentException("Could not get block of IP: $ip_normalized");
        $masked = substr($binary, 0, 6) . str_repeat("\x00", 10);
        return inet_ntop($masked) . '/48';
    }

    /**
     * Set a given individual IP's score in the internal cache. Should be a well-formed ipv4 or ipv6 address (ipv6 should be lower case). You can use Sentry::normalizeIp() to ensure it is well formatted.
     */
    public function setIpScore(string $ip_normalized, int $score): void
    {
        $this->db->upsert('abuseipdb')
            ->conflictColumns('ip')
            ->row([
                'ip'         => $ip_normalized,
                'score'      => $score,
                'checked_at' => time(),
            ])
            ->execute();
    }

    /**
     * Set a given IP range's score in the internal cache. Input should be a well-formed ipv4 /24 or ipv6 /48 block in CIDR notation. You can use Sentry::normalizeIp and AbuseIpDb::rangeFromIp() to ensure it is well formatted.
     */
    protected function setRangeScore(string $range_normalized, int $score): void
    {
        $this->db->upsert('abuseipdb_blocks')
            ->conflictColumns('ip')
            ->row([
                'ip'         => $range_normalized,
                'score'      => $score,
                'checked_at' => time(),
            ])
            ->execute();
    }

    /**
     * Attempt to update a range's records from the API, and return the resulting score if successful.
     */
    protected function rangeApiRequest(string $range_normalized): Score|null
    {
        $url = 'https://api.abuseipdb.com/api/v2/check-block?' . http_build_query([
            'network'      => $range_normalized,
            'maxAgeInDays' => $this->report_days,
        ]);
        // prepare resquest
        $context = stream_context_create([
            'http' => [
                'method'        => 'GET',
                'header'        => implode("\r\n", [
                    'Key: ' . $this->api_key,
                    'Accept: application/json',
                ]),
                'ignore_errors' => true,
            ],
        ]);
        // fetch response
        $response = @file_get_contents($url, false, $context);
        // check for rate limit
        foreach ($http_response_header as $header) {
            // if response was 429, then rate limit
            if (str_starts_with($header, 'HTTP/') && str_contains($header, '429')) {
                $this->setRangeRateLimited();
                return null;
            }
        }
        // check if response failed otherwise
        if ($response === false)
            return null;
        // decode data
        $data = json_decode($response, true);
        if (!is_array($data))
            return null;
        if (!isset($data['data']))
            return null;
        if (!is_array($data['data']))
            return null;
        // write all individual IP scores to database
        assert(is_array($data['data']['reportedAddress']) || is_null($data['data']['reportedAddress']));
        foreach ($data['data']['reportedAddress'] ?? [] as $reported) {
            if (!is_array($reported))
                continue;
            if (!is_string($reported['ipAddress']))
                continue;
            if (!filter_var($reported['ipAddress'], FILTER_VALIDATE_IP))
                continue;
            if (!is_int($reported['abuseConfidenceScore']))
                continue;
            $this->setIpScore($reported['ipAddress'], $reported['abuseConfidenceScore']);
        }
        // compute a score and write to database
        assert(is_int($data['data']['numPossibleHosts']));
        assert($data['data']['numPossibleHosts'] > 0);
        $score = new Score(
            $range_normalized,
            true,
            (int) ceil(count($data['data']['reportedAddress'] ?? []) / $data['data']['numPossibleHosts']),
            time(),
            $this->refreshAtTime(time()),
            $this->ignoreAtTime(time()),
        );
        $this->setRangeScore($range_normalized, $score->score);
        // return score object
        return $score;
    }

    /**
     * Attempt to update an individual IP's records from the API, and return the resulting score if successful.
     */
    protected function ipApiRequest(string $ip_normalized): Score|null
    {
        $url = 'https://api.abuseipdb.com/api/v2/check?' . http_build_query([
            'ipAddress'    => $ip_normalized,
            'maxAgeInDays' => $this->report_days,
        ]);
        // prepare resquest
        $context = stream_context_create([
            'http' => [
                'method'        => 'GET',
                'header'        => implode("\r\n", [
                    'Key: ' . $this->api_key,
                    'Accept: application/json',
                ]),
                'ignore_errors' => true,
            ],
        ]);
        // fetch response
        $response = @file_get_contents($url, false, $context);
        // check for rate limit
        foreach ($http_response_header as $header) {
            // if response was 429, then rate limit
            if (str_starts_with($header, 'HTTP/') && str_contains($header, '429')) {
                $this->setIpRateLimited();
                return null;
            }
        }
        // check if response failed otherwise
        if ($response === false)
            return null;
        // decode data
        $data = json_decode($response, true);
        if (!is_array($data))
            return null;
        if (!isset($data['data']))
            return null;
        if (!is_array($data['data']))
            return null;
        // compute a score and write to database
        assert(is_int($data['data']['abuseConfidenceScore']));
        assert($data['data']['abuseConfidenceScore'] >= 0);
        $score = new Score(
            $ip_normalized,
            false,
            intval($data['data']['abuseConfidenceScore']),
            time(),
            $this->refreshAtTime(time()),
            $this->ignoreAtTime(time()),
        );
        $this->setIpScore($ip_normalized, $score->score);
        // return score object
        return $score;
    }

    /**
     * Whether range API requests are rate-limited (30 minute cooldown)
     */
    protected function rangeRateLimited(): bool
    {
        return $this->db->select('abuseipdb_ratelimited_blocks')
            ->where('time', time() - 1800, '>')
            ->count() > 0;
    }

    /**
     * Set flag indicating range API requests are rate-limited (30 minute cooldown)
     */
    protected function setRangeRateLimited(): void
    {
        $this->db->insert('abuseipdb_ratelimited_blocks')
            ->row(['time' => time()])
            ->execute();
    }

    /**
     * Whether individual IP API requests are rate-limited (30 minute cooldown)
     */
    protected function ipRateLimited(): bool
    {
        return $this->db->select('abuseipdb_ratelimited')
            ->where('time', time() - 1800, '>')
            ->count() > 0;
    }

    /**
     * Set flag indicating individual IP API requests are rate-limited (30 minute cooldown)
     */
    protected function setIpRateLimited(): void
    {
        $this->db->insert('abuseipdb_ratelimited')
            ->row(['time' => time()])
            ->execute();
    }

    /**
     * Run any necessary database migrations
     */
    public function migrateDB(): void
    {
        $migrator = new Migrator(
            $this->db->filename,
            '_migrations_smolsentry_abuseipdb',
        );
        $migrator->addMigrationDirectory(__DIR__ . '/../migrations/abuseipdb');
        $migrator->migrate();
    }

    /**
     * Run database cleanup processes, such as clearing old records
     */
    public function cleanupDB(): void
    {
        // clean up IP data
        $this->db->delete('abuseipdb')
            ->where('checked_at', time() - $this->max_stale_ttl, '<')
            ->execute();
        // clean up range data
        $this->db->delete('abuseipdb_blocks')
            ->where('checked_at', time() - $this->max_stale_ttl, '<')
            ->execute();
        // clean up rate limiting data
        $this->db->delete('abuseipdb_ratelimited')
            ->where('time', time() - 86400, '<')
            ->execute();
        // clean up rate limiting data
        $this->db->delete('abuseipdb_ratelimited_blocks')
            ->where('time', time() - 86400, '<')
            ->execute();
    }

}
