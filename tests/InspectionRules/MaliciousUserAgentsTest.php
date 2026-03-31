<?php

namespace Joby\Smol\Sentry\InspectionRules;

use Joby\Smol\Sentry\Severity;
use PHPUnit\Framework\TestCase;

class MaliciousUserAgentsTest extends TestCase
{

    protected MaliciousUserAgents $rule;

    protected function setUp(): void
    {
        $this->rule = new MaliciousUserAgents();
    }

    public function test_flags_commix(): void
    {
        $request = new RequestData(['HTTP_USER_AGENT' => 'commix/v3.1'], [], [], [], []);
        $this->assertSame(Severity::Malicious, $this->rule->check($request));
    }

    public function test_flags_havij(): void
    {
        $request = new RequestData(['HTTP_USER_AGENT' => 'Havij'], [], [], [], []);
        $this->assertSame(Severity::Malicious, $this->rule->check($request));
    }

    public function test_flags_trufflehog(): void
    {
        $request = new RequestData(['HTTP_USER_AGENT' => 'trufflehog'], [], [], [], []);
        $this->assertSame(Severity::Malicious, $this->rule->check($request));
    }

    public function test_flags_scanner_in_longer_string(): void
    {
        $request = new RequestData(['HTTP_USER_AGENT' => 'Mozilla/5.0 commix something'], [], [], [], []);
        $this->assertSame(Severity::Malicious, $this->rule->check($request));
    }

    public function test_case_insensitive(): void
    {
        $request = new RequestData(['HTTP_USER_AGENT' => 'COMMIX'], [], [], [], []);
        $this->assertSame(Severity::Malicious, $this->rule->check($request));
    }

    public function test_allows_chrome(): void
    {
        $request = new RequestData(['HTTP_USER_AGENT' => 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'], [], [], [], []);
        $this->assertNull($this->rule->check($request));
    }

    public function test_allows_firefox(): void
    {
        $request = new RequestData(['HTTP_USER_AGENT' => 'Mozilla/5.0 (X11; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0'], [], [], [], []);
        $this->assertNull($this->rule->check($request));
    }

    public function test_allows_curl(): void
    {
        $request = new RequestData(['HTTP_USER_AGENT' => 'curl/8.4.0'], [], [], [], []);
        $this->assertNull($this->rule->check($request));
    }

    public function test_allows_empty_user_agent(): void
    {
        $request = new RequestData(['HTTP_USER_AGENT' => ''], [], [], [], []);
        $this->assertNull($this->rule->check($request));
    }

    public function test_allows_missing_user_agent(): void
    {
        $request = new RequestData([], [], [], [], []);
        $this->assertNull($this->rule->check($request));
    }

}
