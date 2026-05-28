<?php

/**
 * smolSentry
 * https://github.com/joby-lol/smol-sentry
 * (c) 2026 Joby Elliott code@joby.lol
 * MIT License https://opensource.org/licenses/MIT
 */

namespace Joby\Smol\Sentry\Reporting;

use Joby\Smol\Query\DB;
use Joby\Smol\Query\SelectQuery;
use Joby\Smol\Sentry\Sentry;

class Reports
{

    public function __construct(
        protected Sentry $sentry,
        protected DB $db,
    ) {}

    /**
     * Get a query for fetching all signals. Will be hydrated into Signal objects, and ordered by ID descending to put newer signals at the top.
     * 
     * @return SelectQuery<Signal>
     */
    public function signals(): SelectQuery
    {
        return $this->db->select('signals')
            ->hydrate(Signal::hydrate(...)) // @phpstan-ignore-line the shape is right
            ->order('id desc');
    }

    /**
     * Get a query for fetching all verdicts. Will be hydrated into Verdict objects, and orderd by ID descending to put newer verdicts at the top.
     * 
     * @return SelectQuery<Verdict>
     */
    public function verdicts(): SelectQuery
    {
        return $this->db->select('verdicts')
            ->hydrate(Verdict::hydrate(...)) // @phpstan-ignore-line the shape is right
            ->order('id desc');
    }

    /**
     * Get a query for fetching all AbuseIPDB scores. Will be hydrated into AbuseIpdb objects, and orderd by checked_at descending to put newer checks at the top.
     * 
     * @return SelectQuery<AbuseIpdbScore>|null
     */
    public function abuseIpdb(): SelectQuery|null
    {
        try {
            return $this->db->select('abuseipdb')
                ->hydrate(AbuseIpdbScore::hydrate(...)) // @phpstan-ignore-line the shape is right
                ->order('checked_at desc');
        }
        catch (\Throwable $th) {
            return null;
        }
    }

}
