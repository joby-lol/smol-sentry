<?php

/**
 * smolSentry
 * https://github.com/joby-lol/smol-sentry
 * (c) 2026 Joby Elliott code@joby.lol
 * MIT License https://opensource.org/licenses/MIT
 */

namespace Joby\Smol\Sentry\InspectionRules;

/**
 * This script is intended to be run via `composer update-crs` to update the subset of the OWASP CoreRuleSet data used by this library for detecting attacks. It can also be run manually to self-update in place, but note that it will update inside your vendor directory if run in that way.
 * 
 * @internal
 * @codeCoverageIgnore this is internal tooling
 */
class OwaspCrsUpdater
{

    public static function update(): void
    {
        static::copy("ai-critical-artifacts.data");
        static::copy("restricted-files.data");
        static::copy("scanners-user-agents.data");
    }

    protected static function copy(string $filename): void
    {
        $src = "https://raw.githubusercontent.com/coreruleset/coreruleset/refs/heads/main/rules/$filename";
        $dst = __DIR__ . "/owasp-crs/$filename";
        file_put_contents($dst, file_get_contents($src));
    }

}
