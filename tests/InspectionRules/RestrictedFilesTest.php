<?php

namespace Joby\Smol\Sentry\InspectionRules;

use Joby\Smol\Sentry\Severity;
use PHPUnit\Framework\TestCase;

class RestrictedFilesTest extends TestCase
{

    protected RestrictedFiles $rule;

    protected function setUp(): void
    {
        $this->rule = new RestrictedFiles();
    }

    // Path matches — malicious

    public function test_dot_env_in_path_is_malicious(): void
    {
        $request = new RequestData(['REQUEST_URI' => '/.env'], [], [], [], []);
        $this->assertSame(Severity::Malicious, $this->rule->check($request));
    }

    public function test_dot_git_in_path_is_malicious(): void
    {
        $request = new RequestData(['REQUEST_URI' => '/.git/HEAD'], [], [], [], []);
        $this->assertSame(Severity::Malicious, $this->rule->check($request));
    }

    public function test_htpasswd_in_path_is_malicious(): void
    {
        $request = new RequestData(['REQUEST_URI' => '/.htpasswd'], [], [], [], []);
        $this->assertSame(Severity::Malicious, $this->rule->check($request));
    }

    public function test_nested_restricted_file_in_path_is_malicious(): void
    {
        $request = new RequestData(['REQUEST_URI' => '/app/config/.env'], [], [], [], []);
        $this->assertSame(Severity::Malicious, $this->rule->check($request));
    }

    public function test_encoded_restricted_file_in_path_is_malicious(): void
    {
        $request = new RequestData(['REQUEST_URI' => '/%2egit/config'], [], [], [], []);
        $this->assertSame(Severity::Malicious, $this->rule->check($request));
    }

    public function test_case_variation_in_path_is_malicious(): void
    {
        $request = new RequestData(['REQUEST_URI' => '/.ENV'], [], [], [], []);
        $this->assertSame(Severity::Malicious, $this->rule->check($request));
    }

    // AI critical artifacts — malicious in path

    public function test_claude_dir_in_path_is_malicious(): void
    {
        $request = new RequestData(['REQUEST_URI' => '/.claude/settings.json'], [], [], [], []);
        $this->assertSame(Severity::Malicious, $this->rule->check($request));
    }

    public function test_cursor_dir_in_path_is_malicious(): void
    {
        $request = new RequestData(['REQUEST_URI' => '/.cursor/mcp.json'], [], [], [], []);
        $this->assertSame(Severity::Malicious, $this->rule->check($request));
    }

    // Parameter matches — suspicious

    public function test_dot_env_in_get_param_is_suspicious(): void
    {
        $request = new RequestData(['REQUEST_URI' => '/search'], ['q' => '.env'], [], [], []);
        $this->assertSame(Severity::Suspicious, $this->rule->check($request));
    }

    public function test_dot_git_in_post_param_is_suspicious(): void
    {
        $request = new RequestData(['REQUEST_URI' => '/submit'], [], ['path' => '/.git/config'], [], []);
        $this->assertSame(Severity::Suspicious, $this->rule->check($request));
    }

    public function test_restricted_file_in_cookie_is_suspicious(): void
    {
        $request = new RequestData(['REQUEST_URI' => '/'], [], [], [], ['data' => '.htpasswd']);
        $this->assertSame(Severity::Suspicious, $this->rule->check($request));
    }

    public function test_restricted_file_in_uploaded_filename_is_suspicious(): void
    {
        $request = new RequestData(['REQUEST_URI' => '/upload'], [], [], ['.htaccess'], []);
        $this->assertSame(Severity::Suspicious, $this->rule->check($request));
    }

    // Path takes priority over parameters

    public function test_path_match_returns_malicious_even_with_param_match(): void
    {
        $request = new RequestData(['REQUEST_URI' => '/.env'], ['q' => '.git/'], [], [], []);
        $this->assertSame(Severity::Malicious, $this->rule->check($request));
    }

    // Clean requests

    public function test_normal_path_returns_null(): void
    {
        $request = new RequestData(['REQUEST_URI' => '/about/contact'], [], [], [], []);
        $this->assertNull($this->rule->check($request));
    }

    public function test_normal_path_with_params_returns_null(): void
    {
        $request = new RequestData(
            ['REQUEST_URI' => '/search'],
            ['q' => 'hello world'],
            [],
            [],
            [],
        );
        $this->assertNull($this->rule->check($request));
    }

    public function test_normal_file_upload_returns_null(): void
    {
        $request = new RequestData(['REQUEST_URI' => '/upload'], [], [], ['report.pdf'], []);
        $this->assertNull($this->rule->check($request));
    }

    public function test_empty_request_returns_null(): void
    {
        $request = new RequestData(['REQUEST_URI' => '/'], [], [], [], []);
        $this->assertNull($this->rule->check($request));
    }

}
