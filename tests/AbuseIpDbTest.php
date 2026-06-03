<?php

/**
 * smolSentry
 * https://github.com/joby-lol/smol-sentry
 * (c) 2026 Joby Elliott code@joby.lol
 * MIT License https://opensource.org/licenses/MIT
 */

namespace Joby\Smol\Sentry;

use Joby\Smol\Query\DB;
use PHPUnit\Framework\TestCase;

class TestableAbuseIpDb extends AbuseIpDb
{

    public int|null $next_ip_api_response = null;

    /**
     * List of IP strings and score ints to simulate a range API request
     * @var array<string,int>|null
     */
    public array|null $next_range_api_response = null;

    public int $ip_api_call_count = 0;

    public int $range_api_call_count = 0;

    /**
     * @inheritDoc
     */
    protected function doIpApiRequest(string $ip_normalized): array|null
    {
        $this->ip_api_call_count++;
        $response_score = $this->next_ip_api_response;
        $this->next_ip_api_response = null;
        if (is_null($response_score))
            return null;
        // return array like the actual endpoint would
        return [
            "ipAddress"            => $ip_normalized,
            "abuseConfidenceScore" => $response_score,
        ];
    }

    /**
     * @inheritDoc
     */
    protected function doRangeApiRequest(string $range_normalized): array|null
    {
        $this->range_api_call_count++;
        $ip_list = $this->next_range_api_response;
        $this->next_range_api_response = null;
        if ($ip_list === null)
            return null;
        // return an array like what the actual endpoint would
        $result = [
            'numPossibleHosts' => 100,
            'reportedAddress'  => [],
        ];
        foreach ($ip_list as $ip => $score) {
            $result['reportedAddress'][] = [
                'ipAddress'            => $ip,
                'abuseConfidenceScore' => $score,
            ];
        }
        return $result;
    }

}

class AbuseIpDbTest extends TestCase
{

    protected DB $db;

    protected TestableAbuseIpDb $source;

    protected string $db_file;

    protected function setUp(): void
    {
        $this->db_file = tempnam(sys_get_temp_dir(), 'smol_sentry_abuseipdb_test_');
        $this->db = new DB($this->db_file);
        $this->source = new TestableAbuseIpDb($this->db, 'test-api-key');
        $this->source->migrateDB();
    }

    protected function tearDown(): void
    {
        unset($this->db);
        unset($this->source);
        unlink($this->db_file);
    }

    // rangeFromIp()

    public function test_range_from_ipv4(): void
    {
        $this->assertEquals('1.2.3.0/24', $this->source->rangeFromIp('1.2.3.4'));
    }

    public function test_range_from_ipv4_preserves_first_three_octets(): void
    {
        $this->assertEquals('192.168.1.0/24', $this->source->rangeFromIp('192.168.1.100'));
    }

    public function test_range_from_ipv6_returns_48_block(): void
    {
        $range = $this->source->rangeFromIp('2001:db8::1');
        $this->assertStringEndsWith('/48', $range);
    }

    public function test_range_from_ipv6_zeroes_correct_bytes(): void
    {
        $a = $this->source->rangeFromIp('2001:db8:1::1');
        $b = $this->source->rangeFromIp('2001:db8:1::2');
        $this->assertEquals($a, $b);
    }

    public function test_range_from_ipv6_different_48_blocks_differ(): void
    {
        $a = $this->source->rangeFromIp('2001:db8:1::1');
        $b = $this->source->rangeFromIp('2001:db8:2::1');
        $this->assertNotEquals($a, $b);
    }

    // Threshold / scoreToOutcome (tested via check() with seeded cache)

    public function test_score_below_challenge_threshold_returns_null(): void
    {
        $this->seedCache('1.2.3.4', 69, false);
        $this->assertNull($this->source->check('1.2.3.4'));
    }

    public function test_score_at_challenge_threshold_returns_challenge(): void
    {
        $this->seedCache('1.2.3.4', 70, false);
        $this->assertEquals(Outcome::Challenge, $this->source->check('1.2.3.4'));
    }

    public function test_score_between_thresholds_returns_challenge(): void
    {
        $this->seedCache('1.2.3.4', 89, false);
        $this->assertEquals(Outcome::Challenge, $this->source->check('1.2.3.4'));
    }

    public function test_score_at_ban_threshold_returns_ban(): void
    {
        $this->seedCache('1.2.3.4', 90, false);
        $this->assertEquals(Outcome::Ban, $this->source->check('1.2.3.4'));
    }

    public function test_score_above_ban_threshold_returns_ban(): void
    {
        $this->seedCache('1.2.3.4', 100, false);
        $this->assertEquals(Outcome::Ban, $this->source->check('1.2.3.4'));
    }

    // Cache behavior

    public function test_fresh_cache_hit_skips_api(): void
    {
        $this->seedCache('1.2.3.4', 95, false);
        $this->seedCache('1.2.3.0/24', 90, true);
        $this->source->check('1.2.3.4');
        $this->assertEquals(0, $this->source->ip_api_call_count);
    }

    public function test_no_cache_entry_calls_api(): void
    {
        $this->source->next_ip_api_response = 50;
        $this->source->check('1.2.3.4');
        $this->assertGreaterThan(0, $this->source->ip_api_call_count);
    }

    public function test_api_result_is_cached(): void
    {
        $this->source->next_ip_api_response = 95;
        $this->source->check('1.2.3.4');
        // reset call count, check again
        $this->source->ip_api_call_count = 0;
        $this->source->check('1.2.3.4');
        $this->assertEquals(0, $this->source->ip_api_call_count);
    }

    public function test_stale_cache_within_max_stale_uses_stale_on_api_failure(): void
    {
        $this->seedCache('1.2.3.4', 95, false, time() - ($this->source->cache_ttl + 1));
        $this->source->next_ip_api_response = null; // API fails
        $result = $this->source->check('1.2.3.4');
        $this->assertEquals(Outcome::Ban, $result);
    }

    public function test_stale_cache_within_max_stale_refreshes_when_quota_allows(): void
    {
        $this->seedCache('1.2.3.4', 50, false, time() - ($this->source->cache_ttl + 1));
        $this->source->next_ip_api_response = 95;
        $result = $this->source->check('1.2.3.4');
        $this->assertEquals(Outcome::Ban, $result);
        $this->assertGreaterThan(0, $this->source->ip_api_call_count);
    }

    public function test_stale_cache_within_max_stale_uses_stale_when_quota_exhausted(): void
    {
        // seed daily refresh quota
        $this->seedManyRefreshes(1500);
        $this->seedCache('1.2.3.0/24', 10, true);
        $this->seedCache('1.2.3.4', 95, false, time() - ($this->source->cache_ttl + 1));
        $this->source->next_ip_api_response = 0;
        $result = $this->source->check('1.2.3.4');
        $this->assertEquals(Outcome::Ban, $result); // uses stale score of 95
        $this->assertEquals(0, $this->source->ip_api_call_count);
    }

    public function test_too_stale_cache_returns_null_on_api_failure(): void
    {
        $this->seedCache('1.2.3.0/24', 10, true, time() - ($this->source->max_stale_ttl + 1));
        $this->seedCache('1.2.3.4', 95, false, time() - ($this->source->max_stale_ttl + 1));
        $this->source->next_ip_api_response = null;
        $result = $this->source->check('1.2.3.4');
        $this->assertNull($result);
    }

    public function test_too_stale_cache_refreshes_on_api_success(): void
    {
        $this->seedCache('1.2.3.4', 0, false, time() - ($this->source->max_stale_ttl + 1));
        $this->source->next_ip_api_response = 95;
        $result = $this->source->check('1.2.3.4');
        $this->assertEquals(Outcome::Ban, $result);
    }

    // Rate limiting

    public function test_rate_limited_skips_api(): void
    {
        $this->db->insert('abuseipdb_ratelimited')->row(['time' => time()])->execute();
        $this->source->next_ip_api_response = 95;
        $this->source->check('1.2.3.4');
        $this->assertEquals(0, $this->source->ip_api_call_count);
    }

    public function test_rate_limited_returns_stale_cache_if_available(): void
    {
        $this->db->insert('abuseipdb_ratelimited')->row(['time' => time()])->execute();
        $this->seedCache('1.2.3.4', 95, false, time() - ($this->source->cache_ttl + 1));
        $result = $this->source->check('1.2.3.4');
        $this->assertEquals(Outcome::Ban, $result);
    }

    public function test_expired_rate_limit_allows_api_call(): void
    {
        $this->db->insert('abuseipdb_ratelimited')->row(['time' => time() - 1801])->execute();
        $this->source->next_ip_api_response = 50;
        $this->source->check('1.2.3.4');
        $this->assertGreaterThan(0, $this->source->ip_api_call_count);
    }

    // Range lookup

    public function test_individual_ip_checked_when_range_is_relatively_clean(): void
    {
        $this->seedCache('1.2.3.0/24', 5, true);
        $this->seedCache('1.2.3.4', 95, false);
        $result = $this->source->check('1.2.3.4');
        $this->assertEquals(Outcome::Ban, $result);
    }

    public function test_clean_range_record_prevents_individual_api_call(): void
    {
        $this->seedCache('1.2.3.0/24', 0, true);
        $this->source->check('1.2.3.4');
        $this->assertEquals(0, $this->source->ip_api_call_count);
    }

    // cleanupDB()

    public function test_cleanup_removes_stale_cache_entries(): void
    {
        $this->seedCache('1.2.3.4', 95, false, time() - ($this->source->max_stale_ttl + 1));
        $this->source->cleanupDB();
        $this->assertNull($this->db->select('abuseipdb')->where('ip', '1.2.3.4')->fetch());
    }

    public function test_cleanup_keeps_fresh_cache_entries(): void
    {
        $this->seedCache('1.2.3.4', 95, false);
        $this->source->cleanupDB();
        $this->assertNotNull($this->db->select('abuseipdb')->where('ip', '1.2.3.4')->fetch());
    }

    public function test_cleanup_removes_old_rate_limit_entries(): void
    {
        $this->db->insert('abuseipdb_ratelimited')->row(['time' => time() - 86401])->execute();
        $this->source->cleanupDB();
        $this->assertEquals(0, $this->db->select('abuseipdb_ratelimited')->count());
    }

    public function test_cleanup_removes_old_blocks_rate_limit_entries(): void
    {
        $this->db->insert('abuseipdb_ratelimited_blocks')->row(['time' => time() - 86401])->execute();
        $this->source->cleanupDB();
        $this->assertEquals(0, $this->db->select('abuseipdb_ratelimited_blocks')->count());
    }

    public function test_cleanup_keeps_recent_rate_limit_entries(): void
    {
        $this->db->insert('abuseipdb_ratelimited')->row(['time' => time()])->execute();
        $this->source->cleanupDB();
        $this->assertEquals(1, $this->db->select('abuseipdb_ratelimited')->count());
    }

    public function test_cleanup_keeps_recent_blocks_rate_limit_entries(): void
    {
        $this->db->insert('abuseipdb_ratelimited_blocks')->row(['time' => time()])->execute();
        $this->source->cleanupDB();
        $this->assertEquals(1, $this->db->select('abuseipdb_ratelimited_blocks')->count());
    }

    // Test range API request result handling

    public function test_range_api_request_sets_scores_for_range_and_individual_ips(): void
    {
        $this->source->next_range_api_response = [
            '10.0.0.1' => '0',
            '10.0.0.2' => $this->source->challenge_threshold,
            '10.0.0.3' => $this->source->ban_threshold,
        ];
        $this->assertNull($this->source->check('10.0.0.1'));
        $this->assertEquals(Outcome::Challenge, $this->source->check('10.0.0.2'));
        $this->assertEquals(Outcome::Ban, $this->source->check('10.0.0.3'));
        // should have gotten all this from a single range api request
        $this->assertEquals(1, $this->source->range_api_call_count);
        $this->assertEquals(0, $this->source->ip_api_call_count);
    }

    // Helpers

    /**
     * Seed the cache with a given ip/range and score/time
     */
    protected function seedCache(string $ip, int $score, bool $block, int $checked_at = null): void
    {
        $this->db->upsert($block ? 'abuseipdb_blocks' : 'abuseipdb')
            ->conflictColumns('ip')
            ->row([
                'ip'         => $ip,
                'score'      => $score,
                'checked_at' => $checked_at ?? time(),
            ])
            ->execute();
    }

    /**
     * Seed many 10.0.x.x IP records with zero score
     */
    protected function seedManyRefreshes(int $count): void
    {
        for ($i = 0; $i < $count; $i++) {
            $this->db->upsert('abuseipdb')
                ->conflictColumns('ip')
                ->row([
                    'ip'         => "10.0." . intdiv($i, 255) . "." . ($i % 255),
                    'score'      => 0,
                    'checked_at' => time(),
                ])
                ->execute();
        }
    }

    /**
     * Seed many 10.0.x.x/24 block records with zero score to consume range refresh quota
     */
    protected function seedManyBlockRefreshes(int $count): void
    {
        for ($i = 0; $i < $count; $i++) {
            $this->db->upsert('abuseipdb_blocks')
                ->conflictColumns('ip')
                ->row([
                    'ip'         => "10.0." . intdiv($i, 255) . "." . ($i % 255) . "/24",
                    'score'      => 0,
                    'checked_at' => time(),
                ])
                ->execute();
        }
    }

}
