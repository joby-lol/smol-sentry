<?php

/**
 * smolSentry
 * https://github.com/joby-lol/smol-sentry
 * (c) 2026 Joby Elliott code@joby.lol
 * MIT License https://opensource.org/licenses/MIT
 */

namespace Joby\Smol\Sentry\Reporting;

use PHPUnit\Framework\TestCase;

class SafeStringTest extends TestCase
{

    public function test_raw_value_is_unmodified(): void
    {
        $s = new SafeString('<script>alert("xss")</script>');
        $this->assertEquals('<script>alert("xss")</script>', $s->raw_value);
    }

    public function test_to_string_escapes_angle_brackets(): void
    {
        $s = new SafeString('<b>bold</b>');
        $this->assertEquals('&lt;b&gt;bold&lt;/b&gt;', (string) $s);
    }

    public function test_to_string_escapes_ampersands(): void
    {
        $s = new SafeString('foo & bar');
        $this->assertEquals('foo &amp; bar', (string) $s);
    }

    public function test_to_string_escapes_double_quotes(): void
    {
        $s = new SafeString('say "hello"');
        $this->assertEquals('say &quot;hello&quot;', (string) $s);
    }

    public function test_to_string_escapes_single_quotes(): void
    {
        $s = new SafeString("it's fine");
        $this->assertEquals('it&#039;s fine', (string) $s);
    }

    public function test_to_string_leaves_plain_strings_unchanged(): void
    {
        $s = new SafeString('nothing special here');
        $this->assertEquals('nothing special here', (string) $s);
    }

}
