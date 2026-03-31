<?php

/**
 * smolSentry
 * https://github.com/joby-lol/smol-sentry
 * (c) 2026 Joby Elliott code@joby.lol
 * MIT License https://opensource.org/licenses/MIT
 */

namespace Joby\Smol\Sentry\InspectionRules;

use Joby\Smol\Sentry\Severity;

interface InspectionRule
{

    public function check(RequestData $request): Severity|null;

}
