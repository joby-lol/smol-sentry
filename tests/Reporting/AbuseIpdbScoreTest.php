<?php

/**
 * smolSentry
 * https://github.com/joby-lol/smol-sentry
 * (c) 2026 Joby Elliott code@joby.lol
 * MIT License https://opensource.org/licenses/MIT
 */

namespace Joby\Smol\Sentry\Reporting;

use PHPUnit\Framework\TestCase;

class AbuseIpdbScoreTest extends TestCase
{

    private function row(array $overrides = []): array
    {
        return array_merge([
            'ip'         => '1.2.3.4',
            'score'      => 42,
            'checked_at' => 1000000000,
        ], $overrides);
    }

    public function test_hydrate_sets_ip(): void
    {
        $score = AbuseIpdbScore::hydrate($this->row(['ip' => '5.6.7.8']));
        $this->assertEquals('5.6.7.8', $score->ip);
    }

    public function test_hydrate_sets_score(): void
    {
        $score = AbuseIpdbScore::hydrate($this->row(['score' => 75]));
        $this->assertEquals(75, $score->score);
    }

    public function test_hydrate_sets_checked_at_as_datetime_immutable(): void
    {
        $score = AbuseIpdbScore::hydrate($this->row(['checked_at' => 1000000000]));
        $this->assertEquals(1000000000, $score->checked_at->getTimestamp());
    }

}
