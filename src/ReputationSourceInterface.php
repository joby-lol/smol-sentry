<?php

/**
 * smolSentry
 * https://github.com/joby-lol/smol-sentry
 * (c) 2026 Joby Elliott code@joby.lol
 * MIT License https://opensource.org/licenses/MIT
 */

namespace Joby\Smol\Sentry;

interface ReputationSourceInterface
{

    /**
     * Check a given IP using this tool's internal lookup. Return an Outcome if confident, or null if not.
     */
    public function check(string $ip_normalized): Outcome|null;

    /**
     * Run any necessary database migration steps on this reputation source. May do nothing if not applicable.
     */
    public function migrateDB(): void;

    /**
     * Run any necessary database cleanup steps on this reputation source. May do nothing if not applicable.
     */
    public function cleanupDB(): void;

}
