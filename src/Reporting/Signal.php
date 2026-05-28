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

readonly class Signal
{

    /**
     * Hydration method for constructing a Signal object from a raw database row.
     * 
     * @internal
     * 
     * @param array{id:int,ip:string,url:string,type:string,malicious:int,time:int} $row
     */
    public static function hydrate(array $row): Signal
    {
        return new Signal(
            $row['id'],
            $row['ip'],
            $row['url'] ? new SafeString($row['url']) : null,
            new SafeString($row['type']),
            $row['malicious'] ? Severity::Malicious : Severity::Suspicious,
            // @phpstan-ignore-next-line we have to trust it's a timestamp
            DateTimeImmutable::createFromFormat('U', $row['time']),
        );
    }

    public function __construct(
        public int $id,
        public string $ip,
        public SafeString|null $url,
        public SafeString $type,
        public Severity $severity,
        public DateTimeImmutable $time,
    ) {}

}
