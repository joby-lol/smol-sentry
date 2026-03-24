<?php

/**
 * smolSentry
 * https://github.com/joby-lol/smol-sentry
 * (c) 2024-2025 Joby Elliott code@joby.lol
 * MIT License https://opensource.org/licenses/MIT
 */

namespace Joby\Smol\Sentry;

use InvalidArgumentException;
use Joby\Smol\Query\DB;
use Joby\Smol\Query\Migrator;
use RuntimeException;

/**
 * Straightforward class for logging signals by IP address and determining whether a given IP should be banned or challenged. The basic interface beyond initial setup shouldn't require calling anything but resolve() to check for bans/challenges, and signal() to indicate that something suspicious/malicious has happened. Both public methods will throw exceptions indicating the level of action that is necessary, should it be determined at any time that the current client should be challenged or banned.
 * 
 * @phpstan-consistent-constructor
 */
class Sentry
{

    /**
     * List of rules to apply whenever a new signal is logged.
     * @var array<int,RuleInterface> $rules
     */
    protected array $rules = [];

    /**
     * List of external reputation sources to be checked for unknown IPs.
     * @var array<int,ReputationSourceInterface> $reputation_sources
     */
    protected array $reputation_sources = [];

    /**
     * Helper factory for making a useful basic implementation with reasonable defaults. Set up with the following rules:
     * - ban immediately on malicious signals
     * - challenge on 5 suspicious signals in 10 minutes
     * - ban on 20 suspicious signals in an hour
     * 
     * Optionally also configured with AbuseIPDB lookups if an api key is provided.
     * 
     * @param DB $db
     * @param string|null $abuseipdb_key your AbuseIPDB API Key
     * @param int $abuseipdb_daily_refreshes the number of refreshes of stale IPs to do per day -- generally best set to about half your API limit
     */
    public static function default(
        DB $db,
        string|null $abuseipdb_key = null,
        int $abuseipdb_daily_refreshes = 500,
    ): static
    {
        $instance = (new static($db))
            // ban immediately on malicious signals
            ->addRule(new Rule(
                Outcome::Ban,
                1,
                3600,
                300,
                null,
                Severity::Malicious,
            ))
            // challenge on 5 suspicious signals in 10 minutes
            ->addRule(new Rule(
                Outcome::Challenge,
                5,
                600,
                300,
                null,
                Severity::Suspicious,
            ))
            // ban on 20 suspicious signals in an hour
            ->addRule(new Rule(
                Outcome::Ban,
                20,
                3600,
                600,
                null,
                Severity::Suspicious,
            ));
        $instance->migrateDB();
        // if an abuseipdb key is provided, add it too
        if ($abuseipdb_key !== null) {
            $abuseipdb = new AbuseIpDb(
                $db,
                $abuseipdb_key,
                daily_refreshes: $abuseipdb_daily_refreshes,
            );
            $abuseipdb->migrateDB();
            $instance->addReputationSource($abuseipdb);
        }
        // return built instance
        return $instance;
    }

    /**
     * Construct a Sentry object given a specific database instance and optional configuration options.
     * @param DB $db
     * @param int $ban_ramp_up_window the rolling time window in which to count how many bans an IP has had for exponential ban ramp-up, in seconds (default 30 days)
     * @param float $ban_ramp_up_rate the number to exponentiate the base ban time by for exponential ban ramp-up (default 1.5)
     * @param int $ban_max_duration the maximum length an IP will be banned for, in seconds (default 30 days)
     * @param int $reputation_outcome_duration the duration of bans/challenges based on external reputation sources (default 24 hours)
     */
    public function __construct(
        protected DB $db,
        protected int $ban_ramp_up_window = 86400 * 30,
        protected float $ban_ramp_up_rate = 1.5,
        protected int $ban_max_duration = 86400 * 30,
        protected int $reputation_outcome_duration = 86400,
    ) {}

    public function migrateDB(): void
    {
        $migrator = new Migrator($this->db->filename, '_migrations_smolsentry');
        $migrator->addMigrationDirectory(__DIR__ . '/../migrations/sentry');
        $migrator->migrate();
    }

    /**
     * Flag a security signal about the current/given IP address, and throw immeidately if it leads to a challenge or ban flag for the client.
     * 
     * @param string $type an arbitrary string indicating the "type" of this signal
     * @param Severity $severity the severity of this signal
     * @param string|null $ip_string the IP address to check, uses an automatically-pulled current IP if left null
     * @param bool $skip_rules skip running rules checks (implies $silent)
     * @param bool $silent skip throwing exceptions and continue execution
     * 
     * @throws BannedException if the client should be banned
     * @throws ChallengedException if the client should be challenged
     */
    public function signal(string $type, Severity $severity = Severity::Suspicious, string|null $ip_string = null, bool $skip_rules = false, bool $silent = false): void
    {
        // attempt to auto-set and normalize IP
        $ip_string ??= $this->getIpString();
        $ip_normalized = $this->normalizedIp($ip_string);
        // log signal in database
        $this->db->insert('signals')
            ->row([
                'type'      => $type,
                'malicious' => $severity === Severity::Malicious,
                'ip'        => $ip_normalized,
                'time'      => time(),
            ])
            ->execute();
        // if skip_rules is true, return immediately
        if ($skip_rules)
            return;
        // process rules and update bans/challenges tables as needed
        $this->processRulesOnIp($ip_normalized);
        // resolve to throw applicable exceptions if not explicitly silent
        if (!$silent)
            $this->resolve($ip_string);
    }

    /**
     * Check the current or given IP address and throw an exception if it should be banned or challenged.
     * 
     * @param string|null $ip_string the IP address to check, uses an automatically-pulled current IP if left null
     * 
     * @throws BannedException if the client should be banned
     * @throws ChallengedException if the client should be challenged
     */
    public function resolve(string|null $ip_string = null): void
    {
        // attempt to auto-set and normalize IP
        $ip_string ??= $this->getIpString();
        $ip_normalized = $this->normalizedIp($ip_string);
        // query for existing verdicts
        $verdict = $this->db->select('verdicts')
            ->where('ip', $ip_normalized)
            ->where('released IS NULL')
            ->where('expires', time(), '>')
            ->order('ban DESC')
            ->order('expires DESC')
            ->fetch();
        // throw exception as appropriate
        if ($verdict) {
            if ($verdict['ban'])
                throw new BannedException("$ip_normalized is banned");
            else
                throw new ChallengedException("$ip_normalized is challenged");
        }
        // check reputation sources
        $this->resolveFromReputationSources($ip_normalized);
    }

    /**
     * Check the given IP address against all reputation sources, and ban/challenge as requested by them, using the "worst" outcome as the canonical one.
     * @param string $ip_normalized
     * @return void
     */
    protected function resolveFromReputationSources(string $ip_normalized): void
    {
        // loop through all reputation sources
        $first_challenge_source = null;
        foreach ($this->reputation_sources as $source) {
            $result = $source->check($ip_normalized);
            if ($result === Outcome::Ban) {
                // ban on first result matching this source
                $this->db->insert('verdicts')
                    ->row([
                        'ip'      => $ip_normalized,
                        'ban'     => 1,
                        'reason'  => $source::class,
                        'time'    => time(),
                        'expires' => time() + $this->reputation_outcome_duration,
                    ])
                    ->execute();
                throw new BannedException("$ip_normalized is banned");
            }
            elseif ($result === Outcome::Challenge) {
                $first_challenge_source ??= $source::class;
            }
        }
        // if there was a challenge, write that verdict and throw
        if ($first_challenge_source !== null) {
            // check if there is an existing verdict matching this one but released
            $query = $this->db->select('verdicts')
                ->where('ip', $ip_normalized)
                ->where('reason', $first_challenge_source)
                ->where('ban', 0)
                ->where('released IS NOT NULL')
                ->where('expires', time(), '>');
            if ($query->count() > 0)
                return;
            // write to database and throw
            $this->db->insert('verdicts')
                ->row([
                    'ip'      => $ip_normalized,
                    'ban'     => 0,
                    'reason'  => $first_challenge_source,
                    'time'    => time(),
                    'expires' => time() + $this->reputation_outcome_duration,
                ])
                ->execute();
            throw new ChallengedException("$ip_normalized is challenged");
        }
    }

    /**
     * Add a rule that will be processed on new signals being logged.
     */
    public function addRule(RuleInterface $rule): static
    {
        $this->rules[] = $rule;
        return $this;
    }

    /**
     * Add an external reputation source for automatically banning/challenging IPs based on external data such as AbuseIPDB
     */
    public function addReputationSource(ReputationSourceInterface $source): static
    {
        $this->reputation_sources[] = $source;
        return $this;
    }

    /**
     * Generate the current client IP address as a string.
     */
    protected function getIpString(): string
    {
        // @phpstan-ignore-next-line we have to just trust $_SERVER
        return $_SERVER['REMOTE_ADDR'];
    }

    /**
     * Convert a human-readable IPv4 or IPv6 string into a normalized string, including zeroing the last 64 bits of IPv6 addresses.
     */
    protected function normalizedIp(string $ip_string): string
    {
        $binary = inet_pton($ip_string);
        if ($binary === false)
            throw new InvalidArgumentException("Invalid IP address: $ip_string");
        // normalize IPv4-mapped IPv6 (::ffff:x.x.x.x) back to plain IPv4
        if (
            strlen($binary) === 16
            && str_starts_with($binary, "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xff")
        )
            $binary = substr($binary, 12);
        // mask IPv6 to /64
        if (strlen($binary) === 16)
            $binary = substr($binary, 0, 8) . str_repeat("\x00", 8);
        // return string value
        return inet_ntop($binary)
            ?: throw new RuntimeException("Unusual IP address error");
    }

    /**
     * Process all currently-configured rules on the given IP address, and write a ban or challenge to the database for it if any trigger, with timing based on the "worst" rule that has triggered. Where bans are considered worse than challenges, and longer outcome durations take precedence.
     */
    protected function processRulesOnIp(string $ip_normalized): void
    {
        // process rules into list of triggered rules
        $triggered = array_filter(
            $this->rules,
            fn(RuleInterface $rule): bool => $rule->triggered($this->db, $ip_normalized)
        );
        // if nothing triggered, return
        if (empty($triggered))
            return;
        // find the worst outcome
        $reason_string = implode("\n", $triggered);
        $worst = array_pop($triggered);
        while ($alt = array_pop($triggered)) {
            // Ban always beats Challenge
            if ($alt->outcome() === Outcome::Ban && $worst->outcome() === Outcome::Challenge) {
                $worst = $alt;
                continue;
            }
            // Challenge hard loses to Ban
            if ($alt->outcome() === Outcome::Challenge && $worst->outcome() === Outcome::Ban) {
                continue;
            }
            // Higher outcome duration wins
            if ($alt->outcomeDuration() > $worst->outcomeDuration()) {
                $worst = $alt;
                continue;
            }
        }
        // determine outcome time
        $outcome_duration = $worst->outcomeDuration();
        if ($worst->outcome() === Outcome::Ban)
            $outcome_duration = $this->banDuration($outcome_duration, $ip_normalized);
        // check if this IP is already banned or challenged
        $existing_query = $this->db->select('verdicts')
            ->where('ip', $ip_normalized)
            ->where('released IS NULL')
            ->where('expires', time(), '>');
        // if this new record is a ban, limit existing query to bans
        if ($worst->outcome() === Outcome::Ban)
            $existing_query->where('ban = 1');
        // do not add another record if this new one is redundant 
        if ($existing_query->count() > 0)
            return;
        // otherwise insert into database
        $this->db->insert('verdicts')
            ->row([
                'ip'      => $ip_normalized,
                'ban'     => $worst->outcome() === Outcome::Ban ? 1 : 0,
                'reason'  => $reason_string,
                'time'    => time(),
                'expires' => time() + $outcome_duration,
            ])
            ->execute();
    }

    /**
     * Given a base duration and IP address, check for existing bans within the ban ramp up window and scale the duration appropriately by exponentiating the ban ramp up rate. Value will never be higher than the ban max duration.
     */
    protected function banDuration(int $base_duration, string $ip_normalized): int
    {
        $previous_bans = $this->db->select('verdicts')
            ->where('ip', $ip_normalized)
            ->where('ban = 1')
            ->where('expires', time() - $this->ban_ramp_up_window, '>')
            ->where('released IS NULL')
            ->count();
        $multiplier = pow($this->ban_ramp_up_rate, $previous_bans);
        $new_duration = intval($base_duration * $multiplier);
        return min($new_duration, $this->ban_max_duration);
    }

}
