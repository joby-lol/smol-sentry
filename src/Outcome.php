<?php

/**
 * smolSentry
 * https://github.com/joby-lol/smol-sentry
 * (c) 2026 Joby Elliott code@joby.lol
 * MIT License https://opensource.org/licenses/MIT
 */

namespace Joby\Smol\Sentry;

/**
 * Enum for specifying whether a rule being triggered should result in a challenge or an outright ban.
 */
enum Outcome
{

    case Ban;

    case Challenge;

}
