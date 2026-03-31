<?php

/**
 * smolSentry
 * https://github.com/joby-lol/smol-sentry
 * (c) 2026 Joby Elliott code@joby.lol
 * MIT License https://opensource.org/licenses/MIT
 */

namespace Joby\Smol\Sentry;

use Joby\Smol\Query\DB;

/**
 * Basic implementation of rules, allowing easy implementation of common "n signals of x type in so much time" type checks with minimal ceremony.
 */
class Rule implements RuleInterface
{

    /**
     * @param Outcome $outcome the outcome that should be applied should this rule match, ban or challenge
     * @param int $threshold the number of matches that must be found for the rule to trigger
     * @param int $search_window the time window in which to search, in seconds
     * @param int $outcome_duration the duration of the ban or challenge -- ban time will be automatically ramped up for repeat offenders
     * @param string|null $signal_type the type of signals to consider for this rule
     * @param Severity|null $severity the severity of signals to consider for this rule, null to consider both suspicious and malicious
     */
    public function __construct(
        public readonly Outcome $outcome,
        public readonly int $threshold,
        public readonly int $search_window,
        public readonly int $outcome_duration,
        public readonly string|null $signal_type = null,
        public readonly Severity|null $severity = null,
    ) {}

    public function __toString(): string
    {
        $parts = [];
        // outcome + duration
        $parts[] = $this->outcome->name . ' for ' . $this->humanDuration($this->outcome_duration);
        // threshold + window
        $parts[] = $this->threshold . '+ signals in ' . $this->humanDuration($this->search_window);
        // filters
        if ($this->severity !== null)
            $parts[] = 'severity:' . $this->severity->name;
        if ($this->signal_type !== null)
            $parts[] = 'type:' . implode('|', (array) $this->signal_type);
        return implode(', ', $parts);
    }

    protected function humanDuration(int $seconds): string
    {
        return match (true) {
            $seconds < 60    => $seconds . 's',
            $seconds < 3600  => ($seconds / 60) . 'm',
            $seconds < 86400 => ($seconds / 3600) . 'h',
            default          => ($seconds / 86400) . 'd',
        };
    }

    /**
     * @inheritDoc
     */
    public function triggered(DB $db, string $ip_normalized): bool
    {
        $query = $db->select('signals')
            ->where('ip', $ip_normalized)
            ->where('time', time() - $this->search_window, '>');
        if ($this->severity !== null)
            $query->where(
                $this->severity === Severity::Malicious
                ? 'malicious'
                : 'NOT malicious'
            );
        if ($this->signal_type !== null)
            $query->where('type', $this->signal_type);
        return $query->count() >= $this->threshold;
    }

    /**
     * @inheritDoc
     */
    public function outcome(): Outcome
    {
        return $this->outcome;
    }

    /**
     * @inheritDoc
     */
    public function outcomeDuration(): int
    {
        return $this->outcome_duration;
    }

}
