<?php

/**
 * smolSentry
 * https://github.com/joby-lol/smol-sentry
 * (c) 2024-2025 Joby Elliott code@joby.lol
 * MIT License https://opensource.org/licenses/MIT
 */

namespace Joby\Smol\Sentry;

interface ReputationSourceInterface
{

    public function check(string $ip_normalized): Outcome|null;

}
