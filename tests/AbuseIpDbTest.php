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

    public int|null $next_api_response = null;

    public int $api_call_count = 0;

    protected function doFetchFromApi(string $ip): int|null
    {
        $this->api_call_count++;
        return $this->next_api_response;
    }

    public function ttl(): int
    {
        return $this->ttl;
    }

    public function maxStale(): int
    {
        return $this->max_stale;
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
        $this->seedCache('1.2.3.4', 69);
        $this->assertNull($this->source->check('1.2.3.4'));
    }

    public function test_score_at_challenge_threshold_returns_challenge(): void
    {
        $this->seedCache('1.2.3.4', 70);
        $this->assertEquals(Outcome::Challenge, $this->source->check('1.2.3.4'));
    }

    public function test_score_between_thresholds_returns_challenge(): void
    {
        $this->seedCache('1.2.3.4', 89);
        $this->assertEquals(Outcome::Challenge, $this->source->check('1.2.3.4'));
    }

    public function test_score_at_ban_threshold_returns_ban(): void
    {
        $this->seedCache('1.2.3.4', 90);
        $this->assertEquals(Outcome::Ban, $this->source->check('1.2.3.4'));
    }

    public function test_score_above_ban_threshold_returns_ban(): void
    {
        $this->seedCache('1.2.3.4', 100);
        $this->assertEquals(Outcome::Ban, $this->source->check('1.2.3.4'));
    }

    // Cache behavior

    public function test_fresh_cache_hit_skips_api(): void
    {
        $this->seedCache('1.2.3.4', 95);
        $this->seedCache('1.2.3.0/24', 90);
        $this->source->check('1.2.3.4');
        $this->assertEquals(0, $this->source->api_call_count);
    }

    public function test_no_cache_entry_calls_api(): void
    {
        $this->source->next_api_response = 50;
        $this->source->check('1.2.3.4');
        $this->assertGreaterThan(0, $this->source->api_call_count);
    }

    public function test_api_result_is_cached(): void
    {
        $this->source->next_api_response = 95;
        $this->source->check('1.2.3.4');
        // reset call count, check again
        $this->source->api_call_count = 0;
        $this->source->check('1.2.3.4');
        $this->assertEquals(0, $this->source->api_call_count);
    }

    public function test_stale_cache_within_max_stale_uses_stale_on_api_failure(): void
    {
        $this->seedCache('1.2.3.4', 95, time() - ($this->source->ttl() + 1));
        $this->source->next_api_response = null; // API fails
        $result = $this->source->check('1.2.3.4');
        $this->assertEquals(Outcome::Ban, $result);
    }

    public function test_stale_cache_within_max_stale_refreshes_when_quota_allows(): void
    {
        $this->seedCache('1.2.3.4', 50, time() - ($this->source->ttl() + 1));
        $this->source->next_api_response = 95;
        $result = $this->source->check('1.2.3.4');
        $this->assertEquals(Outcome::Ban, $result);
        $this->assertGreaterThan(0, $this->source->api_call_count);
    }

    public function test_stale_cache_within_max_stale_uses_stale_when_quota_exhausted(): void
    {
        // seed daily refresh quota
        $this->seedManyRefreshes(500);
        $this->seedCache('1.2.3.0/24', 10);
        $this->seedCache('1.2.3.4', 95, time() - ($this->source->ttl() + 1));
        $this->source->next_api_response = 0;
        $result = $this->source->check('1.2.3.4');
        $this->assertEquals(Outcome::Ban, $result); // uses stale score of 95
        $this->assertEquals(0, $this->source->api_call_count);
    }

    public function test_too_stale_cache_returns_null_on_api_failure(): void
    {
        $this->seedCache('1.2.3.0/24', 10, time() - ($this->source->maxStale() + 1));
        $this->seedCache('1.2.3.4', 95, time() - ($this->source->maxStale() + 1));
        $this->source->next_api_response = null;
        $result = $this->source->check('1.2.3.4');
        $this->assertNull($result);
    }

    public function test_too_stale_cache_refreshes_on_api_success(): void
    {
        $this->seedCache('1.2.3.4', 0, time() - ($this->source->maxStale() + 1));
        $this->source->next_api_response = 95;
        $result = $this->source->check('1.2.3.4');
        $this->assertEquals(Outcome::Ban, $result);
    }

    // Rate limiting

    public function test_rate_limited_skips_api(): void
    {
        $this->db->insert('abuseipdb_ratelimited')->row(['time' => time()])->execute();
        $this->source->next_api_response = 95;
        $this->source->check('1.2.3.4');
        $this->assertEquals(0, $this->source->api_call_count);
    }

    public function test_rate_limited_returns_stale_cache_if_available(): void
    {
        $this->db->insert('abuseipdb_ratelimited')->row(['time' => time()])->execute();
        $this->seedCache('1.2.3.4', 95, time() - ($this->source->ttl() + 1));
        $result = $this->source->check('1.2.3.4');
        $this->assertEquals(Outcome::Ban, $result);
    }

    public function test_expired_rate_limit_allows_api_call(): void
    {
        $this->db->insert('abuseipdb_ratelimited')->row(['time' => time() - 601])->execute();
        $this->source->next_api_response = 50;
        $this->source->check('1.2.3.4');
        $this->assertGreaterThan(0, $this->source->api_call_count);
    }

    // Range lookup

    public function test_range_checked_before_individual_ip(): void
    {
        // seed range cache with ban score, individual with clean score
        $this->seedCache('1.2.3.0/24', 95);
        $this->seedCache('1.2.3.4', 0);
        $result = $this->source->check('1.2.3.4');
        $this->assertEquals(Outcome::Ban, $result);
    }

    public function test_individual_ip_checked_when_range_is_relatively_clean(): void
    {
        $this->seedCache('1.2.3.0/24', 5);
        $this->seedCache('1.2.3.4', 95);
        $result = $this->source->check('1.2.3.4');
        $this->assertEquals(Outcome::Ban, $result);
    }

    public function test_range_ban_prevents_individual_api_call(): void
    {
        $this->seedCache('1.2.3.0/24', 95);
        $this->source->check('1.2.3.4');
        $this->assertEquals(0, $this->source->api_call_count);
    }

    // cleanupDB()

    public function test_cleanup_removes_stale_cache_entries(): void
    {
        $this->seedCache('1.2.3.4', 95, time() - ($this->source->maxStale() + 1));
        $this->source->cleanupDB();
        $this->assertNull($this->db->select('abuseipdb')->where('ip', '1.2.3.4')->fetch());
    }

    public function test_cleanup_keeps_fresh_cache_entries(): void
    {
        $this->seedCache('1.2.3.4', 95);
        $this->source->cleanupDB();
        $this->assertNotNull($this->db->select('abuseipdb')->where('ip', '1.2.3.4')->fetch());
    }

    public function test_cleanup_removes_old_rate_limit_entries(): void
    {
        $this->db->insert('abuseipdb_ratelimited')->row(['time' => time() - 601])->execute();
        $this->source->cleanupDB();
        $this->assertEquals(0, $this->db->select('abuseipdb_ratelimited')->count());
    }

    public function test_cleanup_keeps_recent_rate_limit_entries(): void
    {
        $this->db->insert('abuseipdb_ratelimited')->row(['time' => time()])->execute();
        $this->source->cleanupDB();
        $this->assertEquals(1, $this->db->select('abuseipdb_ratelimited')->count());
    }

    // Helpers

    protected function seedCache(string $ip, int $score, int $checked_at = null): void
    {
        $this->db->upsert('abuseipdb')
            ->conflictColumns('ip')
            ->row([
                'ip'         => $ip,
                'score'      => $score,
                'checked_at' => $checked_at ?? time(),
            ])
            ->execute();
    }

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

    public function test_range_pass_threshold_default_is_zero(): void
    {
        $this->assertEquals(0, $this->source->range_pass_threshold);
    }

    public function test_range_below_pass_threshold_skips_individual_check(): void
    {
        $source = new TestableAbuseIpDb($this->db, 'test-api-key', range_pass_threshold: 30);
        $source->migrateDB();
        $this->seedCache('1.2.3.0/24', 10);
        $source->next_api_response = 95;
        $result = $source->check('1.2.3.4');
        $this->assertNull($result);
    }

    public function test_range_below_pass_threshold_makes_no_api_call(): void
    {
        $source = new TestableAbuseIpDb($this->db, 'test-api-key', range_pass_threshold: 30);
        $source->migrateDB();
        $this->seedCache('1.2.3.0/24', 10);
        $source->check('1.2.3.4');
        $this->assertEquals(0, $source->api_call_count);
    }

    public function test_range_at_pass_threshold_skips_individual_check(): void
    {
        $source = new TestableAbuseIpDb($this->db, 'test-api-key', range_pass_threshold: 30);
        $source->migrateDB();
        $this->seedCache('1.2.3.0/24', 30);
        $this->seedCache('1.2.3.4', 95);
        $result = $source->check('1.2.3.4');
        $this->assertNull($result);
    }

    public function test_range_above_pass_threshold_does_not_skip_individual_check(): void
    {
        $source = new TestableAbuseIpDb($this->db, 'test-api-key', range_pass_threshold: 30);
        $source->migrateDB();
        $this->seedCache('1.2.3.0/24', 50);
        $this->seedCache('1.2.3.4', 95);
        $result = $source->check('1.2.3.4');
        $this->assertEquals(Outcome::Ban, $result);
    }

    public function test_range_pass_threshold_only_applies_when_range_cache_is_fresh(): void
    {
        $source = new TestableAbuseIpDb($this->db, 'test-api-key', range_pass_threshold: 30);
        $source->migrateDB();
        $this->seedCache('1.2.3.0/24', 10, time() - ($source->max_stale + 1));
        $source->next_api_response = 95;
        $source->check('1.2.3.4');
        $this->assertGreaterThan(0, $source->api_call_count);
    }

}
