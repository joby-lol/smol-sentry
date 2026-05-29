<?php

/**
 * smolSentry
 * https://github.com/joby-lol/smol-sentry
 * (c) 2026 Joby Elliott code@joby.lol
 * MIT License https://opensource.org/licenses/MIT
 */

namespace Joby\Smol\Sentry\Reporting;

use Joby\Smol\Sentry\Severity;
use PHPUnit\Framework\TestCase;

class SignalTest extends TestCase
{

    private function row(array $overrides = []): array
    {
        return array_merge([
            'id'        => 1,
            'ip'        => '1.2.3.4',
            'url'       => null,
            'type'      => 'test',
            'malicious' => 0,
            'time'      => 1000000000,
        ], $overrides);
    }

    public function test_hydrate_sets_id(): void
    {
        $signal = Signal::hydrate($this->row(['id' => 42]));
        $this->assertEquals(42, $signal->id);
    }

    public function test_hydrate_sets_ip(): void
    {
        $signal = Signal::hydrate($this->row(['ip' => '5.6.7.8']));
        $this->assertEquals('5.6.7.8', $signal->ip);
    }

    public function test_hydrate_sets_type_as_safe_string(): void
    {
        $signal = Signal::hydrate($this->row(['type' => 'dangerous_url']));
        $this->assertInstanceOf(SafeString::class, $signal->type);
        $this->assertEquals('dangerous_url', $signal->type->raw_value);
    }

    public function test_hydrate_sets_url_as_null_when_absent(): void
    {
        $signal = Signal::hydrate($this->row(['url' => null]));
        $this->assertNull($signal->url);
    }

    public function test_hydrate_sets_url_as_safe_string_when_present(): void
    {
        $signal = Signal::hydrate($this->row(['url' => 'https://example.com/foo']));
        $this->assertInstanceOf(SafeString::class, $signal->url);
        $this->assertEquals('https://example.com/foo', $signal->url->raw_value);
    }

    public function test_hydrate_maps_malicious_zero_to_suspicious(): void
    {
        $signal = Signal::hydrate($this->row(['malicious' => 0]));
        $this->assertEquals(Severity::Suspicious, $signal->severity);
    }

    public function test_hydrate_maps_malicious_one_to_malicious(): void
    {
        $signal = Signal::hydrate($this->row(['malicious' => 1]));
        $this->assertEquals(Severity::Malicious, $signal->severity);
    }

    public function test_hydrate_sets_time_as_datetime_immutable(): void
    {
        $signal = Signal::hydrate($this->row(['time' => 1000000000]));
        $this->assertEquals(1000000000, $signal->time->getTimestamp());
    }

}
