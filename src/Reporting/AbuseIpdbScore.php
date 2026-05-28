<?php

/**
 * smolSentry
 * https://github.com/joby-lol/smol-sentry
 * (c) 2026 Joby Elliott code@joby.lol
 * MIT License https://opensource.org/licenses/MIT
 */

namespace Joby\Smol\Sentry\Reporting;

use DateTimeImmutable;

readonly class AbuseIpdbScore
{

    /**
     * Hydration method for constructing an AbuseIpdbScore object from a raw database row.
     * 
     * @internal
     * 
     * @param array{ip:string,score:int,checked_at:int} $row
     */
    public static function hydrate(array $row): AbuseIpdbScore
    {
        return new AbuseIpdbScore(
            $row['ip'],
            $row['score'],
            // @phpstan-ignore-next-line we have to trust it's a timestamp
            DateTimeImmutable::createFromFormat('U', (string) $row['checked_at']),
        );
    }

    public function __construct(
        public string $ip,
        public int $score,
        public DateTimeImmutable $checked_at,
    ) {}

}
