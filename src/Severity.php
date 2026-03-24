<?php

/**
 * smolSentry
 * https://github.com/joby-lol/smol-sentry
 * (c) 2024-2025 Joby Elliott code@joby.lol
 * MIT License https://opensource.org/licenses/MIT
 */

namespace Joby\Smol\Sentry;

/**
 * Enum for the level of severity that should be assigned to a given event.
 */
enum Severity
{

    /**
     * Suspicious events are those that could potentially happen by accident, but a pattern of them should be considered suspicious and grounds for a challenge. High numbers of suspicious events may also be considered ban-worthy.
     */
    case Suspicious;

    /**
     * Malicious events cannot happen by accident and should be considered indicative of actively malicious activity and should quickly lead to bans.
     */
    case Malicious;

}
