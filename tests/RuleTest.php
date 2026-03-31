<?php

/**
 * smolSentry
 * https://github.com/joby-lol/smol-sentry
 * (c) 2026 Joby Elliott code@joby.lol
 * MIT License https://opensource.org/licenses/MIT
 */

namespace Joby\Smol\Sentry;

use PHPUnit\Framework\TestCase;

class RuleTest extends TestCase
{

    // Interface methods

    public function test_outcome_returns_correct_value(): void
    {
        $rule = new Rule(Outcome::Ban, 3, 3600, 600);
        $this->assertEquals(Outcome::Ban, $rule->outcome());
    }

    public function test_outcome_duration_returns_correct_value(): void
    {
        $rule = new Rule(Outcome::Ban, 3, 3600, 600);
        $this->assertEquals(600, $rule->outcomeDuration());
    }

    // __toString / humanDuration

    public function test_to_string_contains_outcome_name(): void
    {
        $this->assertStringContainsString('Ban', (string) new Rule(Outcome::Ban, 1, 60, 60));
        $this->assertStringContainsString('Challenge', (string) new Rule(Outcome::Challenge, 1, 60, 60));
    }

    public function test_to_string_contains_threshold(): void
    {
        $rule = new Rule(Outcome::Ban, 5, 3600, 600);
        $this->assertStringContainsString('5+', (string) $rule);
    }

    public function test_to_string_duration_seconds(): void
    {
        $rule = new Rule(Outcome::Ban, 1, 30, 45);
        $str = (string) $rule;
        $this->assertStringContainsString('30s', $str);
        $this->assertStringContainsString('45s', $str);
    }

    public function test_to_string_duration_minutes(): void
    {
        $rule = new Rule(Outcome::Ban, 1, 600, 300);
        $str = (string) $rule;
        $this->assertStringContainsString('10m', $str);
        $this->assertStringContainsString('5m', $str);
    }

    public function test_to_string_duration_hours(): void
    {
        $rule = new Rule(Outcome::Ban, 1, 7200, 3600);
        $str = (string) $rule;
        $this->assertStringContainsString('2h', $str);
        $this->assertStringContainsString('1h', $str);
    }

    public function test_to_string_duration_days(): void
    {
        $rule = new Rule(Outcome::Ban, 1, 86400 * 7, 86400);
        $str = (string) $rule;
        $this->assertStringContainsString('7d', $str);
        $this->assertStringContainsString('1d', $str);
    }

    public function test_to_string_includes_severity_when_set(): void
    {
        $rule = new Rule(Outcome::Ban, 1, 3600, 600, null, Severity::Malicious);
        $this->assertStringContainsString('severity:Malicious', (string) $rule);
    }

    public function test_to_string_includes_type_when_set(): void
    {
        $rule = new Rule(Outcome::Ban, 1, 3600, 600, 'dangerous_url');
        $this->assertStringContainsString('type:dangerous_url', (string) $rule);
    }

    public function test_to_string_omits_severity_when_null(): void
    {
        $rule = new Rule(Outcome::Ban, 1, 3600, 600);
        $this->assertStringNotContainsString('severity:', (string) $rule);
    }

    public function test_to_string_omits_type_when_null(): void
    {
        $rule = new Rule(Outcome::Ban, 1, 3600, 600);
        $this->assertStringNotContainsString('type:', (string) $rule);
    }

}
