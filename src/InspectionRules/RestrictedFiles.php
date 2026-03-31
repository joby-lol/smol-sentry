<?php

/**
 * smolSentry
 * https://github.com/joby-lol/smol-sentry
 * (c) 2026 Joby Elliott code@joby.lol
 * MIT License https://opensource.org/licenses/MIT
 */

namespace Joby\Smol\Sentry\InspectionRules;

use Joby\Smol\Sentry\Severity;

class RestrictedFiles extends AbstractDataFileRule
{

    protected const FILES = [
        __DIR__ . '/owasp-crs/restricted-files.data',
        __DIR__ . '/owasp-crs/ai-critical-artifacts.data'
    ];

    public function check(RequestData $request): Severity|null
    {
        // clean up and fully normalize path and parameters, each into a single string
        $path = $request->pathString(true);
        $parameters = $request->parameterString(true);
        foreach ($this->lines() as $line) {
            if (str_contains($path, $line))
                return Severity::Malicious;
            if (str_contains($parameters, $line))
                return Severity::Suspicious;
        }
        return null;
    }

}
