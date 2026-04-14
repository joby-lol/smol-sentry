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
     * @param int $range_pass_threshold the threshold at which a range (/24 for IPv4 and /48 for IPv6) is considered trustworthy enough to skip checking individual IPs from it
     * @param int $ttl the amount of time to cache an AbuseIPDB score before it may be refreshed.
     * @param int $max_stale the maximum amount of time an AbuseIPDB score may be continued to be used, even if it is stale, to preserve API quota or if your API quota is exhausted.
     * @param int $daily_refreshes the maximum number of daily refreshes the system will perform from AbuseIPDB for previously-looked-up IPs. Setting this lower than your API quota allows you to reserve the rest of your quota for completely new and unknown IPs.
     * @param int $report_days the number of days of reports to ask AbuseIPDB to consider in API requests.
     */
    public function __construct(
        public readonly DB $db,
        #[SensitiveParameter]
        protected readonly string $api_key,
        public readonly int $challenge_threshold = 70,
        public readonly int $ban_threshold = 90,
        public readonly int $range_pass_threshold = 0,
        public readonly int $ttl = 86400,
        public readonly int $max_stale = 86400 * 14,
        public readonly int $daily_refreshes = 500,
        public readonly int $report_days = 30,
    ) {}

    public function migrateDB(): void
    {
        $migrator = new Migrator(
            $this->db->filename,
            '_migrations_smolsentry_abuseipdb',
        );
        $migrator->addMigrationDirectory(__DIR__ . '/../migrations/abuseipdb');
        $migrator->migrate();
    }

    public function cleanupDB(): void
    {
        // clean up IP data
        $this->db->delete('abuseipdb')
            ->where('checked_at', time() - $this->max_stale, '<')
            ->execute();
        // clean up rate limiting data
        $this->db->delete('abuseipdb_ratelimited')
            ->where('time', time() - 600, '<')
            ->execute();
    }

    /**
     * Check the given IP and its /24 or /48 block (IPv4/IPv6, respectively), and return an Outcome if it passes either the ban or challenge threshold, or null if it does not.
     */
    public function check(string $ip_normalized): Outcome|null
    {
        $range_outcome = $this->doCheck($this->rangeFromIp($ip_normalized), true);
        if ($range_outcome === true)
            return null;
        elseif ($range_outcome !== null)
            return $range_outcome;
        else
            return $this->doCheck($ip_normalized);
    }

    /**
     * Summary of doCheck
     * @param string $ip_normalized
     * @param bool $checking_block
     * @return ($checking_block is true ? Outcome|true|null : Outcome|null)
     */
    protected function doCheck(string $ip_normalized, bool $checking_block = false): Outcome|true|null
    {
        $cached = $this->getCached($ip_normalized);
        $age = $cached ? time() - $cached['checked_at'] : null;

        if ($cached && $age < $this->ttl) {
            // fresh cache hit — use it
            return $this->scoreToOutcome($cached['score'], $checking_block);
        }

        if ($cached && $age < $this->max_stale) {
            // stale but usable — try to refresh if quota allows
            if ($this->countDailyRefreshes() < $this->daily_refreshes) {
                $score = $this->fetchFromApi($ip_normalized);
                if ($score !== null) {
                    $this->updateCache($ip_normalized, $score);
                    return $this->scoreToOutcome($score, $checking_block);
                }
            }
            // quota exhausted or API failed — use stale data
            return $this->scoreToOutcome($cached['score'], $checking_block);
        }

        if ($cached) {
            // too stale to trust — try API, skip if fails
            $score = $this->fetchFromApi($ip_normalized);
            if ($score !== null) {
                $this->updateCache($ip_normalized, $score);
                return $this->scoreToOutcome($score, $checking_block);
            }
            return null;
        }

        // no cache entry at all — always try API
        $score = $this->fetchFromApi($ip_normalized);
        if ($score !== null) {
            $this->updateCache($ip_normalized, $score);
            return $this->scoreToOutcome($score, $checking_block);
        }
        return null;
    }

    /**
     * Return CIDR notation of the /24 block for IPv4 addresses or /48 block for IPv6 addresses
     */
    public function rangeFromIp(string $ip_normalized): string
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
     * Return the Outcome configured for a given int score, based on ban_threshold and challenge_threshold
     * 
     * @return ($checking_block is true ? Outcome|true|null : Outcome|null)
     */
    protected function scoreToOutcome(int $score, bool $checking_block): Outcome|true|null
    {
        if ($checking_block && $score <= $this->range_pass_threshold)
            return true;
        if ($score >= $this->ban_threshold)
            return Outcome::Ban;
        if ($score >= $this->challenge_threshold)
            return Outcome::Challenge;
        return null;
    }

    /**
     * Get the cached row from the database, if it exists.
     * 
     * @return array{ip:string,score:int,checked_at:int}|null
     */
    protected function getCached(string $ip): array|null
    {
        // @phpstan-ignore-next-line it's the right array format
        return $this->db->select('abuseipdb')
            ->where('ip', $ip)
            ->fetch();
    }

    protected function updateCache(string $ip, int $score): void
    {
        $this->db->upsert('abuseipdb')
            ->conflictColumns('ip')
            ->row([
                'ip'         => $ip,
                'score'      => $score,
                'checked_at' => time(),
            ])
            ->execute();
    }

    protected function countDailyRefreshes(): int
    {
        return $this->db->select('abuseipdb')
            ->where('checked_at', time() - 86400, '>')
            ->count();
    }

    protected function fetchFromApi(string $ip): int|null
    {
        // short-circuit if rate limited
        if ($this->isRateLimited())
            return null;
        return $this->doFetchFromApi($ip);
    }

    /**
     * @codeCoverageIgnore this can't really be tested easily
     */
    protected function doFetchFromApi(string $ip): int|null
    {
        // otherwise build request
        $is_range = str_contains($ip, '/');
        $url = $is_range
            ? 'https://api.abuseipdb.com/api/v2/check-block?' . http_build_query([
                'network' => $ip,
            ])
            : 'https://api.abuseipdb.com/api/v2/check?' . http_build_query([
                'ipAddress'    => $ip,
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
        if ($response === false)
            return null;
        // decode data
        $data = json_decode($response, true);
        if (!is_array($data) || !isset($data['data']))
            return null;
        // check for rate limit
        foreach ($http_response_header as $header) {
            // if response was 429, then rate limit
            if (str_starts_with($header, 'HTTP/') && str_contains($header, '429')) {
                $this->recordRateLimit();
                return null;
            }
        }
        // for ranges, return the percent of IPs that have been reported
        if ($is_range)
            return intval($data['data']['percentDistinct'] ?? 0); // @phpstan-ignore-line
        // for individual IPs just return the score
        return intval($data['data']['abuseConfidenceScore']); // @phpstan-ignore-line
    }

    protected function isRateLimited(): bool
    {
        return $this->db->select('abuseipdb_ratelimited')
            ->where('time', time() - 600, '>')
            ->count() > 0;
    }

    protected function recordRateLimit(): void
    {
        $this->db->insert('abuseipdb_ratelimited')
            ->row(['time' => time()])
            ->execute();
    }

}
