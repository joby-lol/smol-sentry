<?php

/**
 * smolSentry
 * https://github.com/joby-lol/smol-sentry
 * (c) 2026 Joby Elliott code@joby.lol
 * MIT License https://opensource.org/licenses/MIT
 */

namespace Joby\Smol\Sentry\InspectionRules;

use Joby\Smol\Sentry\Severity;

class MaliciousUserAgents extends AbstractDataFileRule
{

    protected const FILES = [
        __DIR__ . '/owasp-crs/scanners-user-agents.data'
    ];

    public function check(RequestData $request): Severity|null
    {
        $user_agent = $request->userAgent();
        if (empty($user_agent))
            return null;
        foreach ($this->lines() as $line) {
            if (str_contains($user_agent, $line))
                return Severity::Malicious;
        }
        return null;
    }

}
