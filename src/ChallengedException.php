<?php

/**
 * smolSentry
 * https://github.com/joby-lol/smol-sentry
 * (c) 2024-2025 Joby Elliott code@joby.lol
 * MIT License https://opensource.org/licenses/MIT
 */

namespace Joby\Smol\Sentry;

use RuntimeException;

/**
 * Class indicating that the current client has behaved in a suspicious manner and should be challenged somehow. Generally this should result in either a 303 See Other response that redirects to a CAPTCHA/challenge, or a normal 200 with a CAPTCHA/challenge presented on the same request URL.
 */
class ChallengedException extends RuntimeException
{

}
