<?php

/**
 * smolSentry
 * https://github.com/joby-lol/smol-sentry
 * (c) 2026 Joby Elliott code@joby.lol
 * MIT License https://opensource.org/licenses/MIT
 */

namespace Joby\Smol\Sentry\Reporting;

use DateTime;
use DateTimeImmutable;
use Joby\Smol\Sentry\Severity;

readonly class Verdict
{

    /**
     * Hydration method for constructing a Verdict object from a raw database row.
     *
     * @internal
     * 
     * @param array{id:int,ip:string,ban:int,reason:string,time:int,expires:int,released:int|null} $row
     */
    public static function hydrate(array $row): Verdict
    {
        return new Verdict(
            $row['id'],
            $row['ip'],
            (bool) $row['ban'],
            new SafeString($row['reason']),
            // @phpstan-ignore-next-line we have to trust it's a timestamp
            DateTimeImmutable::createFromFormat('U', (string) $row['time']),
            // @phpstan-ignore-next-line we have to trust it's a timestamp
            DateTimeImmutable::createFromFormat('U', (string) $row['expires']),
            // @phpstan-ignore-next-line we have to trust it's a timestamp
            $row['released'] ? DateTimeImmutable::createFromFormat('U', (string) $row['released']) : null
        );
    }

    public function __construct(
        public int $id,
        public string $ip,
        public bool $ban,
        public SafeString $reason,
        public DateTimeImmutable $time,
        public DateTimeImmutable $expires,
        public DateTimeImmutable|null $released,
    ) {}

}
