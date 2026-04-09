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

class SentryTest extends TestCase
{

    protected DB $db;

    protected Sentry $sentry;

    protected string $db_file;

    protected function setUp(): void
    {
        $this->db_file = tempnam(sys_get_temp_dir(), 'smol_sentry_test_');
        $this->db = new DB($this->db_file);
        $this->sentry = new Sentry($this->db);
        $this->sentry->migrateDB();
    }

    protected function tearDown(): void
    {
        unset($this->db);
        unset($this->sentry);
        unlink($this->db_file);
    }

    // IP normalization (verified via DB contents)

    public function test_ipv4_stored_in_canonical_form(): void
    {
        $this->sentry->signal('test', Severity::Suspicious, '1.2.3.4', silent: true);
        $row = $this->db->select('signals')->fetch();
        $this->assertEquals('1.2.3.4', $row['ip']);
    }

    public function test_ipv6_stored_in_canonical_form(): void
    {
        $this->sentry->signal('test', Severity::Suspicious, '2001:0db8:0000:0000:0000:0000:0000:0001', silent: true);
        $row = $this->db->select('signals')->fetch();
        $this->assertEquals('2001:db8::', $row['ip']);
    }

    public function test_ipv6_addresses_in_same_64_block_stored_identically(): void
    {
        $this->sentry->signal('test', Severity::Suspicious, '2001:db8::1', silent: true);
        $this->sentry->signal('test', Severity::Suspicious, '2001:db8::2', silent: true);
        $rows = [...$this->db->select('signals')->fetchAll()];
        $this->assertEquals($rows[0]['ip'], $rows[1]['ip']);
    }

    public function test_ipv6_addresses_in_different_64_blocks_stored_differently(): void
    {
        $this->sentry->signal('test', Severity::Suspicious, '2001:db8:1::1', silent: true);
        $this->sentry->signal('test', Severity::Suspicious, '2001:db8:2::1', silent: true);
        $rows = [...$this->db->select('signals')->fetchAll()];
        $this->assertNotEquals($rows[0]['ip'], $rows[1]['ip']);
    }

    public function test_ipv4_mapped_ipv6_normalized_to_ipv4(): void
    {
        $this->sentry->signal('test', Severity::Suspicious, '::ffff:1.2.3.4', silent: true);
        $row = $this->db->select('signals')->fetch();
        $this->assertEquals('1.2.3.4', $row['ip']);
    }

    // Rule triggered()

    public function test_rule_not_triggered_with_no_signals(): void
    {
        $rule = new Rule(Outcome::Ban, 1, 3600, 86400);
        $this->assertFalse($rule->triggered($this->db, '1.2.3.4'));
    }

    public function test_rule_triggered_at_threshold(): void
    {
        $rule = new Rule(Outcome::Ban, 3, 3600, 86400);
        for ($i = 0; $i < 3; $i++) {
            $this->db->insert('signals')->row([
                'ip'        => '1.2.3.4',
                'type'      => 'test',
                'malicious' => 0,
                'time'      => time(),
            ])->execute();
        }
        $this->assertTrue($rule->triggered($this->db, '1.2.3.4'));
    }

    public function test_rule_not_triggered_below_threshold(): void
    {
        $rule = new Rule(Outcome::Ban, 3, 3600, 86400);
        for ($i = 0; $i < 2; $i++) {
            $this->db->insert('signals')->row([
                'ip'        => '1.2.3.4',
                'type'      => 'test',
                'malicious' => 0,
                'time'      => time(),
            ])->execute();
        }
        $this->assertFalse($rule->triggered($this->db, '1.2.3.4'));
    }

    public function test_rule_ignores_signals_outside_window(): void
    {
        $rule = new Rule(Outcome::Ban, 2, 3600, 86400);
        for ($i = 0; $i < 3; $i++) {
            $this->db->insert('signals')->row([
                'ip'        => '1.2.3.4',
                'type'      => 'test',
                'malicious' => 0,
                'time'      => time() - 7200,
            ])->execute();
        }
        $this->assertFalse($rule->triggered($this->db, '1.2.3.4'));
    }

    public function test_rule_filters_by_signal_type(): void
    {
        $rule = new Rule(Outcome::Ban, 2, 3600, 86400, 'dangerous_url');
        for ($i = 0; $i < 3; $i++) {
            $this->db->insert('signals')->row([
                'ip'        => '1.2.3.4',
                'type'      => 'login_failure',
                'malicious' => 0,
                'time'      => time(),
            ])->execute();
        }
        $this->assertFalse($rule->triggered($this->db, '1.2.3.4'));
    }

    public function test_rule_type_filter_matches_correct_type(): void
    {
        $rule = new Rule(Outcome::Ban, 2, 3600, 86400, 'dangerous_url');
        for ($i = 0; $i < 2; $i++) {
            $this->db->insert('signals')->row([
                'ip'        => '1.2.3.4',
                'type'      => 'dangerous_url',
                'malicious' => 0,
                'time'      => time(),
            ])->execute();
        }
        $this->assertTrue($rule->triggered($this->db, '1.2.3.4'));
    }

    public function test_rule_filters_by_severity_malicious(): void
    {
        $rule = new Rule(Outcome::Ban, 2, 3600, 86400, null, Severity::Malicious);
        for ($i = 0; $i < 3; $i++) {
            $this->db->insert('signals')->row([
                'ip'        => '1.2.3.4',
                'type'      => 'test',
                'malicious' => 0,
                'time'      => time(),
            ])->execute();
        }
        $this->assertFalse($rule->triggered($this->db, '1.2.3.4'));
    }

    public function test_rule_filters_by_severity_suspicious(): void
    {
        $rule = new Rule(Outcome::Ban, 2, 3600, 86400, null, Severity::Suspicious);
        for ($i = 0; $i < 3; $i++) {
            $this->db->insert('signals')->row([
                'ip'        => '1.2.3.4',
                'type'      => 'test',
                'malicious' => 1,
                'time'      => time(),
            ])->execute();
        }
        $this->assertFalse($rule->triggered($this->db, '1.2.3.4'));
    }

    public function test_rule_wildcard_severity_matches_both(): void
    {
        $rule = new Rule(Outcome::Ban, 2, 3600, 86400);
        $this->db->insert('signals')->row(['ip' => '1.2.3.4', 'type' => 'test', 'malicious' => 0, 'time' => time()])->execute();
        $this->db->insert('signals')->row(['ip' => '1.2.3.4', 'type' => 'test', 'malicious' => 1, 'time' => time()])->execute();
        $this->assertTrue($rule->triggered($this->db, '1.2.3.4'));
    }

    // resolve()

    public function test_resolve_allows_clean_ip(): void
    {
        $this->expectNotToPerformAssertions();
        $this->sentry->resolve('1.2.3.4');
    }

    public function test_resolve_throws_banned_exception(): void
    {
        $this->db->insert('verdicts')->row([
            'ip'      => '1.2.3.4',
            'ban'     => 1,
            'reason'  => 'test',
            'time'    => time(),
            'expires' => time() + 3600,
        ])->execute();
        // need a signal so fast-path doesn't short-circuit
        $this->db->insert('signals')->row(['ip' => '1.2.3.4', 'type' => 'test', 'malicious' => 0, 'time' => time()])->execute();
        $this->expectException(BannedException::class);
        $this->sentry->resolve('1.2.3.4');
    }

    public function test_resolve_allows_expired_ban(): void
    {
        $this->expectNotToPerformAssertions();
        $this->db->insert('signals')->row(['ip' => '1.2.3.4', 'type' => 'test', 'malicious' => 0, 'time' => time()])->execute();
        $this->db->insert('verdicts')->row([
            'ip'      => '1.2.3.4',
            'ban'     => 1,
            'reason'  => 'test',
            'time'    => time() - 7200,
            'expires' => time() - 3600,
        ])->execute();
        $this->sentry->resolve('1.2.3.4');
    }

    public function test_resolve_allows_released_ban(): void
    {
        $this->expectNotToPerformAssertions();
        $this->db->insert('signals')->row(['ip' => '1.2.3.4', 'type' => 'test', 'malicious' => 0, 'time' => time()])->execute();
        $this->db->insert('verdicts')->row([
            'ip'       => '1.2.3.4',
            'ban'      => 1,
            'reason'   => 'test',
            'time'     => time(),
            'expires'  => time() + 3600,
            'released' => time(),
        ])->execute();
        $this->sentry->resolve('1.2.3.4');
    }

    public function test_resolve_throws_challenged_exception(): void
    {
        $this->db->insert('signals')->row(['ip' => '1.2.3.4', 'type' => 'test', 'malicious' => 0, 'time' => time()])->execute();
        $this->db->insert('verdicts')->row([
            'ip'      => '1.2.3.4',
            'ban'     => 0,
            'reason'  => 'test',
            'time'    => time(),
            'expires' => time() + 3600,
        ])->execute();
        $this->expectException(ChallengedException::class);
        $this->sentry->resolve('1.2.3.4');
    }

    public function test_resolve_allows_released_challenge(): void
    {
        $this->expectNotToPerformAssertions();
        $this->db->insert('signals')->row(['ip' => '1.2.3.4', 'type' => 'test', 'malicious' => 0, 'time' => time()])->execute();
        $this->db->insert('verdicts')->row([
            'ip'       => '1.2.3.4',
            'ban'      => 0,
            'reason'   => 'test',
            'time'     => time(),
            'expires'  => time() + 3600,
            'released' => time(),
        ])->execute();
        $this->sentry->resolve('1.2.3.4');
    }

    public function test_resolve_ban_takes_priority_over_challenge(): void
    {
        $this->db->insert('signals')->row([
            'ip'        => '1.2.3.4',
            'type'      => 'test',
            'malicious' => 0,
            'time'      => time(),
        ])->execute();
        $this->db->insert('verdicts')->row([
            'ip'      => '1.2.3.4',
            'ban'     => 1,
            'reason'  => 'test',
            'time'    => time(),
            'expires' => time() + 3600
        ])->execute();
        $this->db->insert('verdicts')->row([
            'ip'      => '1.2.3.4',
            'ban'     => 0,
            'reason'  => 'test',
            'time'    => time(),
            'expires' => time() + 3600
        ])->execute();
        $this->expectException(BannedException::class);
        $this->sentry->resolve('1.2.3.4');
    }

    public function test_resolve_finds_verdict_regardless_of_signal_age(): void
    {
        // active ban but only stale signals — should fast-exit
        $this->db->insert('signals')->row([
            'ip'        => '1.2.3.4',
            'type'      => 'test',
            'malicious' => 0,
            'time'      => time() - (86400 * 91),
        ])->execute();
        $this->db->insert('verdicts')->row([
            'ip'      => '1.2.3.4',
            'ban'     => 1,
            'reason'  => 'test',
            'time'    => time(),
            'expires' => time() + 3600,
        ])->execute();
        $this->expectException(BannedException::class);
        $this->sentry->resolve('1.2.3.4');
    }

    // signal() + rule evaluation

    public function test_signal_triggers_ban_at_threshold(): void
    {
        $this->sentry->addRule(new Rule(Outcome::Ban, 3, 3600, 600));
        $this->sentry->signal('test', Severity::Suspicious, '1.2.3.4', silent: true);
        $this->sentry->signal('test', Severity::Suspicious, '1.2.3.4', silent: true);
        $this->expectException(BannedException::class);
        $this->sentry->signal('test', Severity::Suspicious, '1.2.3.4');
    }

    public function test_signal_triggers_challenge_at_threshold(): void
    {
        $this->sentry->addRule(new Rule(Outcome::Challenge, 2, 3600, 300));
        $this->sentry->signal('test', Severity::Suspicious, '1.2.3.4', silent: true);
        $this->expectException(ChallengedException::class);
        $this->sentry->signal('test', Severity::Suspicious, '1.2.3.4');
    }

    public function test_signal_ban_beats_challenge_when_both_triggered(): void
    {
        $this->sentry
            ->addRule(new Rule(Outcome::Challenge, 1, 3600, 300))
            ->addRule(new Rule(Outcome::Ban, 1, 3600, 600));
        $this->expectException(BannedException::class);
        $this->sentry->signal('test', Severity::Suspicious, '1.2.3.4');
    }

    public function test_signal_silent_does_not_throw(): void
    {
        $this->expectNotToPerformAssertions();
        $this->sentry->addRule(new Rule(Outcome::Ban, 1, 3600, 600));
        $this->sentry->signal('test', Severity::Suspicious, '1.2.3.4', silent: true);
    }

    public function test_signal_skip_rules_does_not_evaluate(): void
    {
        $this->expectNotToPerformAssertions();
        $this->sentry->addRule(new Rule(Outcome::Ban, 1, 3600, 600));
        $this->sentry->signal('test', Severity::Suspicious, '1.2.3.4', skip_rules: true);
    }

    public function test_signal_does_not_write_duplicate_ban(): void
    {
        $this->sentry->addRule(new Rule(Outcome::Ban, 1, 3600, 600));
        try {
            $this->sentry->signal('test', Severity::Suspicious, '1.2.3.4');
        }
        catch (BannedException) {
        }
        try {
            $this->sentry->signal('test', Severity::Suspicious, '1.2.3.4');
        }
        catch (BannedException) {
        }
        $count = $this->db->select('verdicts')->where('ip', '1.2.3.4')->count();
        $this->assertEquals(1, $count);
    }

    public function test_signal_does_not_write_duplicate_challenge(): void
    {
        $this->sentry->addRule(new Rule(Outcome::Challenge, 1, 3600, 300));
        try {
            $this->sentry->signal('test', Severity::Suspicious, '1.2.3.4');
        }
        catch (ChallengedException) {
        }
        try {
            $this->sentry->signal('test', Severity::Suspicious, '1.2.3.4');
        }
        catch (ChallengedException) {
        }
        $count = $this->db->select('verdicts')->where('ip', '1.2.3.4')->count();
        $this->assertEquals(1, $count);
    }

    // Ban ramp-up

    public function test_ban_ramp_up_increases_duration_on_repeat(): void
    {
        $this->sentry->addRule(new Rule(Outcome::Ban, 1, 3600, 600));
        // first ban
        try {
            $this->sentry->signal('test', Severity::Suspicious, '1.2.3.4');
        }
        catch (BannedException) {
        }
        // expire it
        $this->db->pdo->exec('UPDATE verdicts SET expires = ' . (time() - 1));
        // second ban
        try {
            $this->sentry->signal('test', Severity::Suspicious, '1.2.3.4');
        }
        catch (BannedException) {
        }

        $bans = [...$this->db->select('verdicts')->where('ip', '1.2.3.4')->fetchAll()];
        $first_duration = $bans[0]['expires'] - $bans[0]['time'];
        $second_duration = $bans[1]['expires'] - $bans[1]['time'];
        $this->assertGreaterThan($first_duration, $second_duration);
    }

    public function test_ban_ramp_up_respects_max_duration(): void
    {
        $sentry = new Sentry(
            $this->db,
            ban_ramp_up_window: 86400 * 30,
            ban_ramp_up_rate: 100.0,
            ban_max_duration: 3600,
        );
        $sentry->addRule(new Rule(Outcome::Ban, 1, 3600, 600));
        // seed prior bans to force ramp-up well past max
        for ($i = 0; $i < 5; $i++) {
            $this->db->insert('verdicts')->row([
                'ip'      => '1.2.3.4',
                'ban'     => 1,
                'reason'  => 'seeded',
                'time'    => time() - 100,
                'expires' => time() - 1,
            ])->execute();
        }
        try {
            $sentry->signal('test', Severity::Suspicious, '1.2.3.4');
        }
        catch (BannedException) {
        }

        $ban = $this->db->select('verdicts')
            ->where('ip', '1.2.3.4')
            ->where('reason', 'seeded', '!=')
            ->fetch();
        $this->assertLessThanOrEqual(3600, $ban['expires'] - $ban['time']);
    }

    public function test_ban_ramp_up_ignores_bans_outside_window(): void
    {
        $sentry = new Sentry(
            $this->db,
            ban_ramp_up_window: 3600,
            ban_ramp_up_rate: 2.0,
            ban_max_duration: 86400 * 30,
        );
        $sentry->addRule(new Rule(Outcome::Ban, 1, 3600, 600));
        // seed bans outside ramp-up window
        for ($i = 0; $i < 5; $i++) {
            $this->db->insert('verdicts')->row([
                'ip'      => '1.2.3.4',
                'ban'     => 1,
                'reason'  => 'old',
                'time'    => time() - 7200,
                'expires' => time() - 3600,
            ])->execute();
        }
        try {
            $sentry->signal('test', Severity::Suspicious, '1.2.3.4');
        }
        catch (BannedException) {
        }

        $ban = $this->db->select('verdicts')
            ->where('ip', '1.2.3.4')
            ->where('reason', 'old', '!=')
            ->fetch();
        $this->assertEqualsWithDelta(600, $ban['expires'] - $ban['time'], 2);
    }

    // Worst outcome selection

    public function test_ban_beats_challenge_regardless_of_duration(): void
    {
        $this->sentry
            ->addRule(new Rule(Outcome::Challenge, 1, 3600, 86400)) // long challenge
            ->addRule(new Rule(Outcome::Ban, 1, 3600, 60)) // short ban
            ->addRule(new Rule(Outcome::Challenge, 1, 3600, 86400)); // long challenge again to ensure ordering isn't accidentally making us pass
        try {
            $this->sentry->signal('test', Severity::Suspicious, '1.2.3.4');
        }
        catch (BannedException) {
        }
        $this->assertEquals(1, $this->db->select('verdicts')
            ->where('ban = 1')
            ->where('ip', '1.2.3.4')
            ->count());
        $this->assertEquals(0, $this->db->select('verdicts')
            ->where('ban = 0')
            ->where('ip', '1.2.3.4')
            ->count());
    }

    public function test_longer_ban_wins_over_shorter_ban(): void
    {
        $this->sentry
            ->addRule(new Rule(Outcome::Ban, 1, 3600, 600))
            ->addRule(new Rule(Outcome::Ban, 1, 3600, 3600))
            ->addRule(new Rule(Outcome::Ban, 1, 3600, 600));
        try {
            $this->sentry->signal('test', Severity::Suspicious, '1.2.3.4');
        }
        catch (BannedException) {
        }
        $ban = $this->db->select('verdicts')->where('ip', '1.2.3.4')->fetch();
        // base duration before ramp-up should reflect the longer rule
        $this->assertGreaterThanOrEqual(3600, $ban['expires'] - $ban['time']);
    }

    public function test_longer_challenge_wins_over_shorter_challenge(): void
    {
        $this->sentry
            ->addRule(new Rule(Outcome::Challenge, 1, 3600, 300))
            ->addRule(new Rule(Outcome::Challenge, 1, 3600, 600));
        try {
            $this->sentry->signal('test', Severity::Suspicious, '1.2.3.4');
        }
        catch (ChallengedException) {
        }
        $challenge = $this->db->select('verdicts')->where('ip', '1.2.3.4')->fetch();
        $this->assertEqualsWithDelta(600, $challenge['expires'] - $challenge['time'], 2);
    }

    public function test_only_one_verdict_row_written_when_multiple_rules_trigger(): void
    {
        $this->sentry
            ->addRule(new Rule(Outcome::Ban, 1, 3600, 600))
            ->addRule(new Rule(Outcome::Ban, 1, 3600, 3600));
        try {
            $this->sentry->signal('test', Severity::Suspicious, '1.2.3.4');
        }
        catch (BannedException) {
        }
        $this->assertEquals(1, $this->db->select('verdicts')->where('ip', '1.2.3.4')->count());
    }

    public function test_untriggered_rules_do_not_influence_outcome(): void
    {
        // only the threshold:1 rule triggers, threshold:99 should have no effect
        $this->sentry
            ->addRule(new Rule(Outcome::Challenge, 1, 3600, 300))
            ->addRule(new Rule(Outcome::Ban, 99, 3600, 3600));
        try {
            $this->sentry->signal('test', Severity::Suspicious, '1.2.3.4');
        }
        catch (ChallengedException) {
        }
        $this->assertEquals(0, $this->db->select('verdicts')
            ->where('ban = 1')
            ->where('ip', '1.2.3.4')
            ->count());
        $this->assertEquals(1, $this->db->select('verdicts')
            ->where('ban = 0')
            ->where('ip', '1.2.3.4')
            ->count());
    }

    // Reputation sources

    public function test_reputation_source_ban_throws_banned_exception(): void
    {
        $this->sentry->addReputationSource(

            new class implements ReputationSourceInterface {

            public function check(string $ip_normalized): Outcome|null
            {
                return Outcome::Ban;
            }

            },
        );
        $this->expectException(BannedException::class);
        $this->sentry->resolve('1.2.3.4');
    }

    public function test_reputation_source_challenge_throws_challenged_exception(): void
    {
        $this->sentry->addReputationSource(

            new class implements ReputationSourceInterface {

            public function check(string $ip_normalized): Outcome|null
            {
                return Outcome::Challenge;
            }

            },
        );
        $this->expectException(ChallengedException::class);
        $this->sentry->resolve('1.2.3.4');
    }

    public function test_reputation_source_null_allows_ip(): void
    {
        $this->expectNotToPerformAssertions();
        $this->sentry->addReputationSource(

            new class implements ReputationSourceInterface {

            public function check(string $ip_normalized): Outcome|null
            {
                return null;
            }

            },
        );
        $this->sentry->resolve('1.2.3.4');
    }

    public function test_reputation_source_ban_writes_verdict_to_db(): void
    {
        $this->sentry->addReputationSource(

            new class implements ReputationSourceInterface {

            public function check(string $ip_normalized): Outcome|null
            {
                return Outcome::Ban;
            }

            },
        );
        try {
            $this->sentry->resolve('1.2.3.4');
        }
        catch (BannedException) {
        }
        $this->assertEquals(1, $this->db->select('verdicts')->where('ip', '1.2.3.4')->where('ban', 1)->count());
    }

    public function test_reputation_source_challenge_writes_verdict_to_db(): void
    {
        $this->sentry->addReputationSource(

            new class implements ReputationSourceInterface {

            public function check(string $ip_normalized): Outcome|null
            {
                return Outcome::Challenge;
            }

            },
        );
        try {
            $this->sentry->resolve('1.2.3.4');
        }
        catch (ChallengedException) {
        }
        $this->assertEquals(1, $this->db->select('verdicts')->where('ip', '1.2.3.4')->where('ban', 0)->count());
    }

    public function test_reputation_source_ban_beats_challenge(): void
    {
        $this->sentry
            ->addReputationSource(

                new class implements ReputationSourceInterface {

            public function check(string $ip_normalized): Outcome|null
            {
                return Outcome::Challenge;
            }

                },
            )
            ->addReputationSource(

                new class implements ReputationSourceInterface {

            public function check(string $ip_normalized): Outcome|null
            {
                return Outcome::Ban;
            }

                },
            );
        $this->expectException(BannedException::class);
        $this->sentry->resolve('1.2.3.4');
    }

    public function test_reputation_source_ban_short_circuits_remaining_sources(): void
    {
        $checked = false;
        $this->sentry
            ->addReputationSource(

                new class implements ReputationSourceInterface {

            public function check(string $ip_normalized): Outcome|null
            {
                return Outcome::Ban;
            }

                },
            )
            ->addReputationSource(

                new class ($checked) implements ReputationSourceInterface {

            public function __construct(private bool &$checked) {}

            public function check(string $ip_normalized): Outcome|null
            {
                $this->checked = true;
                return null;
            }

                },
            );
        try {
            $this->sentry->resolve('1.2.3.4');
        }
        catch (BannedException) {
        }
        $this->assertFalse($checked);
    }

    public function test_reputation_source_verdict_persists_for_subsequent_resolves(): void
    {
        $callCount = 0;
        $this->sentry->addReputationSource(

            new class ($callCount) implements ReputationSourceInterface {

            public function __construct(private int &$callCount) {}

            public function check(string $ip_normalized): Outcome|null
            {
                $this->callCount++;
                return Outcome::Ban;
            }

            },
        );
        try {
            $this->sentry->resolve('1.2.3.4');
        }
        catch (BannedException) {
        }
        try {
            $this->sentry->resolve('1.2.3.4');
        }
        catch (BannedException) {
        }
        // source should only be called once — second resolve hits local verdict
        $this->assertEquals(1, $callCount);
    }

    public function test_reputation_source_challenge_not_repeated_after_released(): void
    {
        $source =

            new class implements ReputationSourceInterface {

            public function check(string $ip_normalized): Outcome|null
            {
                return Outcome::Challenge;
            }

            };
        $this->sentry->addReputationSource($source);
        // write a released challenge verdict for this source
        $this->db->insert('verdicts')->row([
            'ip'       => '1.2.3.4',
            'ban'      => 0,
            'reason'   => $source::class,
            'time'     => time(),
            'expires'  => time() + 3600,
            'released' => time(),
        ])->execute();
        // should not throw — challenge was already released
        $this->expectNotToPerformAssertions();
        $this->sentry->resolve('1.2.3.4');
    }

    public function test_reputation_source_challenge_repeated_after_released_verdict_expires(): void
    {
        $source =

            new class implements ReputationSourceInterface {

            public function check(string $ip_normalized): Outcome|null
            {
                return Outcome::Challenge;
            }

            };
        $this->sentry->addReputationSource($source);
        // write an expired released challenge verdict
        $this->db->insert('verdicts')->row([
            'ip'       => '1.2.3.4',
            'ban'      => 0,
            'reason'   => $source::class,
            'time'     => time() - 7200,
            'expires'  => time() - 3600,
            'released' => time() - 3600,
        ])->execute();
        $this->expectException(ChallengedException::class);
        $this->sentry->resolve('1.2.3.4');
    }

    // release()

    public function test_release_clears_challenge_verdict(): void
    {
        $this->db->insert('verdicts')
            ->row(['ip' => '1.2.3.4', 'ban' => 0, 'expires' => time() + 300, 'released' => null, 'time' => time(), 'reason' => 'test'])
            ->execute();
        $this->sentry->release('1.2.3.4');
        $this->sentry->resolve('1.2.3.4'); // should not throw
        $this->expectNotToPerformAssertions();
    }

    public function test_release_does_not_clear_ban_by_default(): void
    {
        $this->db->insert('verdicts')
            ->row(['ip' => '1.2.3.4', 'ban' => 1, 'expires' => time() + 300, 'released' => null, 'time' => time(), 'reason' => 'test'])
            ->execute();
        $this->sentry->release('1.2.3.4');
        $this->expectException(BannedException::class);
        $this->sentry->resolve('1.2.3.4');
    }

    public function test_release_clears_ban_when_release_bans_is_true(): void
    {
        $this->db->insert('verdicts')
            ->row(['ip' => '1.2.3.4', 'ban' => 1, 'expires' => time() + 300, 'released' => null, 'time' => time(), 'reason' => 'test'])
            ->execute();
        $this->sentry->release('1.2.3.4', release_bans: true);
        $this->sentry->resolve('1.2.3.4');
        $this->expectNotToPerformAssertions();
    }

    public function test_release_only_affects_specified_ip(): void
    {
        $ip1 = '1.2.3.4';
        $ip2 = '5.6.7.8';
        $this->db->insert('verdicts')
            ->row(['ip' => $ip1, 'ban' => 1, 'expires' => time() + 300, 'released' => null, 'time' => time(), 'reason' => 'test'])
            ->row(['ip' => $ip2, 'ban' => 1, 'expires' => time() + 300, 'released' => null, 'time' => time(), 'reason' => 'test'])
            ->execute();
        $this->sentry->release('1.2.3.4', release_bans: true);
        $this->sentry->resolve('1.2.3.4');
        $this->expectException(BannedException::class);
        $this->sentry->resolve('5.6.7.8');
    }

    public function test_release_ignores_already_expired_verdicts(): void
    {
        $this->db->insert('verdicts')
            ->row(['ip' => '1.2.3.4', 'ban' => 0, 'expires' => time() - 60, 'released' => null, 'time' => time() - 360, 'reason' => 'test'])
            ->execute();
        $this->sentry->release('1.2.3.4');
        // verify the row was not touched — released should still be null
        $row = $this->db->select('verdicts')
            ->where('ip', '1.2.3.4')
            ->fetch();
        $this->assertNull($row['released']);
    }

    public function test_release_is_idempotent(): void
    {
        $this->db->insert('verdicts')
            ->row(['ip' => '1.2.3.4', 'ban' => 1, 'expires' => time() + 300, 'released' => null, 'time' => time(), 'reason' => 'test'])
            ->execute();
        $this->sentry->release('1.2.3.4', release_bans: true);
        $this->sentry->release('1.2.3.4', release_bans: true);
        $this->sentry->resolve('1.2.3.4');
        $this->expectNotToPerformAssertions();
    }

    public function test_release_on_clean_ip_does_nothing(): void
    {
        $this->sentry->release('1.2.3.4');
        $this->sentry->resolve('1.2.3.4');
        $this->expectNotToPerformAssertions();
    }

}
