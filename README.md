# smolSentry

A lightweight IP-based threat detection and mitigation library for PHP 8.1+.

## Installation
```bash
composer require joby-lol/smol-sentry
```

## About

smolSentry logs suspicious activity by IP address, evaluates configurable rules, and throws exceptions when a client should be challenged or banned. It is deliberately as self-contained as possible — all state is stored in a SQLite database, which makes it easy to set up and run on nearly any server.

## Basic Usage
```php
use Joby\Smol\Query\DB;
use Joby\Smol\Sentry\Sentry;
use Joby\Smol\Sentry\BannedException;
use Joby\Smol\Sentry\ChallengedException;

$db = new DB('/path/to/sentry.db');
$sentry = Sentry::default($db);

// At the top of every request — throws if the client is banned or challenged
$sentry->resolve();

// When something suspicious happens — throws if it pushes the client over a threshold
$sentry->signal('dangerous_url', Severity::Malicious);
```

Both `resolve()` and `signal()` throw `BannedException` or `ChallengedException` when action is required. A banned client should receive a **403 Forbidden**. A challenged client should be redirected (**303 See Other**) to a CAPTCHA or similar challenge page, or served one inline with a **200**.

## Default Rules

`Sentry::default()` configures a reasonable starting point:

- One malicious signal: immediate ban (5 minutes base, ramps up exponentially for repeat offenders)
- 5 suspicious signals in 10 minutes: challenge
- 20 suspicious signals in an hour: ban

Optionally also configured with AbuseIPDB lookups:
```php
$sentry = Sentry::default($db, abuseipdb_key: 'your-api-key');
```

## Signals

Signals are the core input — they record that something suspicious or malicious happened during a request from a given IP.
```php
// Use the current request IP automatically
$sentry->signal('login_failure');
$sentry->signal('dangerous_url', Severity::Malicious);

// Or specify an IP explicitly
$sentry->signal('login_failure', Severity::Suspicious, '1.2.3.4');

// Log without throwing (useful for logging-only contexts)
$sentry->signal('login_failure', silent: true);

// Log without evaluating rules
$sentry->signal('login_failure', skip_rules: true);
```

Severity has two levels:
- `Severity::Suspicious` — accumulates toward rule thresholds
- `Severity::Malicious` — typically triggers an immediate ban

Signal types are arbitrary strings. Use whatever naming convention makes sense for your application.

## Rules

Rules define when accumulated signals should result in a ban or challenge. They are evaluated whenever a new signal is logged.
```php
use Joby\Smol\Sentry\Rule;
use Joby\Smol\Sentry\Outcome;
use Joby\Smol\Sentry\Severity;

$sentry->addRule(new Rule(
    outcome: Outcome::Ban,
    threshold: 5,           // number of signals required to trigger
    search_window: 3600,    // time window to search in seconds
    outcome_duration: 600,  // base duration of the outcome in seconds
    signal_type: 'login_failure', // null to match any type
    severity: Severity::Suspicious, // null to match any severity
));
```

When multiple rules trigger simultaneously, the worst outcome wins — bans beat challenges, and longer durations beat shorter ones. Only one verdict row is written per evaluation.

### Ban Ramp-Up

Ban durations increase exponentially for repeat offenders. A client banned multiple times within the ramp-up window receives progressively longer bans, up to a configurable maximum.
```php
$sentry = new Sentry(
    $db,
    ban_ramp_up_window: 86400 * 30, // look back 30 days for prior bans
    ban_ramp_up_rate: 1.5,           // multiply duration by 1.5x per prior ban
    ban_max_duration: 86400 * 30,    // cap at 30 days
);
```

## Reputation Sources

External reputation data can be checked for IPs with no local verdict. Reputation sources are consulted during `resolve()`, after local verdicts have been checked. Results are written as local verdicts so subsequent calls are fast.
```php
use Joby\Smol\Sentry\AbuseIpDb;

$abuseipdb = new AbuseIpDb($db, api_key: 'your-api-key');
$abuseipdb->migrateDB();

$sentry->addReputationSource($abuseipdb);
```

### AbuseIPDB

The bundled `AbuseIpDb` source checks individual IPs and their /24 (IPv4) or /48 (IPv6) blocks. Results are cached locally to preserve API quota. Default value of 500 in daily_refreshes is designed to be appropriate for use with a free AbuseIPDB account.
```php
$abuseipdb = new AbuseIpDb(
    db: $db,
    api_key: 'your-api-key',
    challenge_threshold: 70, // score >= this -> challenge
    ban_threshold: 90,       // score >= this -> ban
                             // score < challenge_threshold -> release existing verdict
    ttl: 86400,              // refresh cached scores after this many seconds
    max_stale: 86400 * 14,   // use stale data for up to this long if quota is exhausted
    daily_refreshes: 500,    // max refreshes of known IPs per day (reserve quota for new IPs)
    report_days: 30,         // days of reports to consider in API requests
);
```

Custom reputation sources can be added by implementing `ReputationSourceInterface`:
```php
interface ReputationSourceInterface {
    public function check(string $ip_normalized): Outcome|null;
}
```

Return `Outcome::Ban`, `Outcome::Challenge`, or `null` to pass. The source's class name is used as the verdict reason, which allows verdicts to be automatically released when a re-check returns a clean score.

## IP Normalization

All IP addresses are normalized before storage:

- IPv4-mapped IPv6 addresses (`::ffff:1.2.3.4`) are normalized to plain IPv4
- IPv6 addresses are masked to their /64 block (last 64 bits zeroed) — a bot rotating through addresses in the same /64 block is treated as a single client

## Database Setup

smolSentry stores all state in SQLite. Call `migrateDB()` before first use:
```php
$sentry->migrateDB(); // sets up signals and verdicts tables
$abuseipdb->migrateDB(); // sets up cache tables, if using AbuseIPDB
```

Because all state is in a single database file, multiple applications on the same server can share a smolSentry database — signals and verdicts from one site count toward thresholds on all others.

## Exception Handling
```php
try {
    // always run $sentry->resolve() as early as possible
    $sentry->resolve();
    // your app logic goes here, including additional signals which may throw BannedExceptions or ChallengedExceptions
} catch (BannedException $e) {
    http_response_code(403);
    exit;
} catch (ChallengedException $e) {
    header('Location: /challenge');
    exit;
}
```

## Requirements

Fully tested on PHP 8.3+, static analysis for PHP 8.1+. Requires the `pdo_sqlite` and `sqlite3` PHP extensions (both enabled by default in most PHP installations). Depends on [smolQuery](https://github.com/joby-lol/smol-query).

## License

MIT License - See [LICENSE](LICENSE) file for details.