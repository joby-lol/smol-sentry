<?php

/**
 * smolSentry
 * https://github.com/joby-lol/smol-sentry
 * (c) 2026 Joby Elliott code@joby.lol
 * MIT License https://opensource.org/licenses/MIT
 */

namespace Joby\Smol\Sentry;

use RuntimeException;

/**
 * Class indicating that the current client is banned, and that the request should not continue processing. Generally this should lead to a 403 Forbidden response being delivered to the client.
 */
class BannedException extends RuntimeException
{

}
