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
use PDOException;
use PHPUnit\Framework\TestCase;

class ReportsTest extends TestCase
{

    protected DB $db;

    protected Reports $reports;

    protected string $db_file;

    protected function setUp(): void
    {
        $this->db_file = tempnam(sys_get_temp_dir(), 'smol_sentry_reports_test_');
        $this->db = new DB($this->db_file);
        $sentry = new Sentry($this->db);
        $sentry->migrateDB();
        $this->reports = new Reports($this->db);
    }

    protected function tearDown(): void
    {
        unset($this->db);
        unlink($this->db_file);
    }

    // signals()

    public function test_signals_returns_select_query(): void
    {
        $this->assertInstanceOf(SelectQuery::class, $this->reports->signals());
    }

    public function test_signals_returns_null_when_empty(): void
    {
        $this->assertNull($this->reports->signals()->fetch());
    }

    public function test_signals_hydrates_into_signal_objects(): void
    {
        $this->db->insert('signals')
            ->row(['ip' => '1.2.3.4', 'type' => 'test', 'malicious' => 0, 'time' => time()])
            ->execute();
        $this->assertInstanceOf(Signal::class, $this->reports->signals()->fetch());
    }

    public function test_signals_ordered_by_id_descending(): void
    {
        $this->db->insert('signals')
            ->row(['ip' => '1.2.3.4', 'type' => 'first', 'malicious' => 0, 'time' => time()])
            ->row(['ip' => '1.2.3.4', 'type' => 'second', 'malicious' => 0, 'time' => time()])
            ->execute();
        $signals = [...$this->reports->signals()->fetchAll()];
        $this->assertGreaterThan($signals[1]->id, $signals[0]->id);
    }

    // verdicts()

    public function test_verdicts_returns_select_query(): void
    {
        $this->assertInstanceOf(SelectQuery::class, $this->reports->verdicts());
    }

    public function test_verdicts_returns_null_when_empty(): void
    {
        $this->assertNull($this->reports->verdicts()->fetch());
    }

    public function test_verdicts_hydrates_into_verdict_objects(): void
    {
        $this->db->insert('verdicts')
            ->row(['ip' => '1.2.3.4', 'ban' => 1, 'reason' => 'test', 'time' => time(), 'expires' => time() + 3600])
            ->execute();
        $this->assertInstanceOf(Verdict::class, $this->reports->verdicts()->fetch());
    }

    public function test_verdicts_ordered_by_id_descending(): void
    {
        $this->db->insert('verdicts')
            ->row(['ip' => '1.2.3.4', 'ban' => 1, 'reason' => 'first', 'time' => time(), 'expires' => time() + 3600])
            ->row(['ip' => '5.6.7.8', 'ban' => 0, 'reason' => 'second', 'time' => time(), 'expires' => time() + 3600])
            ->execute();
        $verdicts = [...$this->reports->verdicts()->fetchAll()];
        $this->assertGreaterThan($verdicts[1]->id, $verdicts[0]->id);
    }

    // abuseIpdb()

    public function test_abuse_ipdb_throws_when_no_table_exists(): void
    {
        $this->expectException(PDOException::class);
        $this->reports->abuseIpdb()->fetch();
    }

    public function test_abuse_ipdb_returns_select_query_when_table_exists(): void
    {
        $this->createAbuseIpdbTables();
        $this->assertInstanceOf(SelectQuery::class, $this->reports->abuseIpdb());
    }

    public function test_abuse_ipdb_returns_null_when_empty(): void
    {
        $this->createAbuseIpdbTables();
        $this->assertNull($this->reports->abuseIpdb()->fetch());
    }

    public function test_abuse_ipdb_hydrates_into_abuse_ipdb_score_objects(): void
    {
        $this->createAbuseIpdbTables();
        $this->db->insert('abuseipdb')
            ->row(['ip' => '1.2.3.4', 'score' => 42, 'checked_at' => time()])
            ->execute();
        $this->assertInstanceOf(AbuseIpdbScore::class, $this->reports->abuseIpdb()->fetch());
    }

    public function test_abuse_ipdb_ordered_by_checked_at_descending(): void
    {
        $this->createAbuseIpdbTables();
        $this->db->insert('abuseipdb')
            ->row(['ip' => '1.2.3.4', 'score' => 10, 'checked_at' => time() - 100])
            ->row(['ip' => '5.6.7.8', 'score' => 20, 'checked_at' => time()])
            ->execute();
        $scores = [...$this->reports->abuseIpdb()->fetchAll()];
        $this->assertGreaterThan($scores[1]->checked_at->getTimestamp(), $scores[0]->checked_at->getTimestamp());
    }

    public function test_abuse_ipdb_blocks_ordered_by_checked_at_descending(): void
    {
        $this->createAbuseIpdbTables();
        $this->db->insert('abuseipdb_blocks')
            ->row(['ip' => '1.2.3.0/24', 'score' => 10, 'checked_at' => time() - 100])
            ->row(['ip' => '5.6.7.0/24', 'score' => 20, 'checked_at' => time()])
            ->execute();
        $scores = [...$this->reports->abuseIpdb(true)->fetchAll()];
        $this->assertGreaterThan($scores[1]->checked_at->getTimestamp(), $scores[0]->checked_at->getTimestamp());
    }

    // helpers

    private function createAbuseIpdbTables(): void
    {
        $this->db->pdo->exec('
            CREATE TABLE "abuseipdb" (
                "ip" STRING NOT NULL COLLATE BINARY PRIMARY KEY,
                "score" INTEGER NOT NULL,
                "checked_at" INTEGER NOT NULL
            )
        ');
        $this->db->pdo->exec('
            CREATE TABLE "abuseipdb_blocks" (
                "ip" STRING NOT NULL COLLATE BINARY PRIMARY KEY,
                "score" INTEGER NOT NULL,
                "checked_at" INTEGER NOT NULL
            )
        ');
    }

}
