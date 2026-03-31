<?php

/**
 * smolSentry
 * https://github.com/joby-lol/smol-sentry
 * (c) 2026 Joby Elliott code@joby.lol
 * MIT License https://opensource.org/licenses/MIT
 */

namespace Joby\Smol\Sentry;

use Joby\Smol\Query\DB;
use Stringable;

/**
 * Interface for "rules" that run on the history of a given IP whenever a new signal is generated, and can trigger an outcome and outcome duration.
 */
interface RuleInterface extends Stringable
{

    public function triggered(DB $db, string $ip_normalized): bool;

    public function outcome(): Outcome;

    public function outcomeDuration(): int;

}
