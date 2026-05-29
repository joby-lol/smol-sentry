<?php

/**
 * smolSentry
 * https://github.com/joby-lol/smol-sentry
 * (c) 2026 Joby Elliott code@joby.lol
 * MIT License https://opensource.org/licenses/MIT
 */

namespace Joby\Smol\Sentry\Reporting;

use PHPUnit\Framework\TestCase;

class VerdictTest extends TestCase
{

    private function row(array $overrides = []): array
    {
        return array_merge([
            'id'       => 1,
            'ip'       => '1.2.3.4',
            'ban'      => 1,
            'reason'   => 'test',
            'time'     => 1000000000,
            'expires'  => 1000003600,
            'released' => null,
        ], $overrides);
    }

    public function test_hydrate_sets_id(): void
    {
        $verdict = Verdict::hydrate($this->row(['id' => 99]));
        $this->assertEquals(99, $verdict->id);
    }

    public function test_hydrate_sets_ip(): void
    {
        $verdict = Verdict::hydrate($this->row(['ip' => '5.6.7.8']));
        $this->assertEquals('5.6.7.8', $verdict->ip);
    }

    public function test_hydrate_maps_ban_one_to_true(): void
    {
        $verdict = Verdict::hydrate($this->row(['ban' => 1]));
        $this->assertTrue($verdict->ban);
    }

    public function test_hydrate_maps_ban_zero_to_false(): void
    {
        $verdict = Verdict::hydrate($this->row(['ban' => 0]));
        $this->assertFalse($verdict->ban);
    }

    public function test_hydrate_sets_reason_as_safe_string(): void
    {
        $verdict = Verdict::hydrate($this->row(['reason' => 'rule_triggered']));
        $this->assertInstanceOf(SafeString::class, $verdict->reason);
        $this->assertEquals('rule_triggered', $verdict->reason->raw_value);
    }

    public function test_hydrate_sets_time_as_datetime_immutable(): void
    {
        $verdict = Verdict::hydrate($this->row(['time' => 1000000000]));
        $this->assertEquals(1000000000, $verdict->time->getTimestamp());
    }

    public function test_hydrate_sets_expires_as_datetime_immutable(): void
    {
        $verdict = Verdict::hydrate($this->row(['expires' => 1000003600]));
        $this->assertEquals(1000003600, $verdict->expires->getTimestamp());
    }

    public function test_hydrate_sets_released_as_null_when_absent(): void
    {
        $verdict = Verdict::hydrate($this->row(['released' => null]));
        $this->assertNull($verdict->released);
    }

    public function test_hydrate_sets_released_as_datetime_immutable_when_present(): void
    {
        $verdict = Verdict::hydrate($this->row(['released' => 1000001800]));
        $this->assertEquals(1000001800, $verdict->released->getTimestamp());
    }

}
