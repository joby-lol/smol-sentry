<?php

/**
 * smolSentry
 * https://github.com/joby-lol/smol-sentry
 * (c) 2026 Joby Elliott code@joby.lol
 * MIT License https://opensource.org/licenses/MIT
 */

namespace Joby\Smol\Sentry\Reporting;

use Stringable;

/**
 * Class that represents a value that may be untrustworthy, and will automatically sanitize output when stringed.
 */
readonly class SafeString implements Stringable
{

    public function __construct(public string $raw_value) {}

    public function __toString(): string
    {
        return htmlspecialchars($this->raw_value, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
    }

}
