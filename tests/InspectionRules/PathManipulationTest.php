<?php

namespace Joby\Smol\Sentry\InspectionRules;

use Joby\Smol\Sentry\Severity;
use PHPUnit\Framework\TestCase;

class PathManipulationTest extends TestCase
{

    protected PathManipulation $rule;

    protected function setUp(): void
    {
        $this->rule = new PathManipulation();
    }

    // check_controlCharacters

    public function test_null_byte_in_path_is_malicious(): void
    {
        $request = new RequestData(['REQUEST_URI' => "/etc/passwd\x00.jpg"], [], [], [], []);
        $this->assertSame(Severity::Malicious, PathManipulation::check_controlCharacters($request));
    }

    public function test_encoded_null_byte_in_path_is_malicious(): void
    {
        $request = new RequestData(['REQUEST_URI' => '/etc/passwd%00.jpg'], [], [], [], []);
        $this->assertSame(Severity::Malicious, PathManipulation::check_controlCharacters($request));
    }

    public function test_bell_character_in_path_is_malicious(): void
    {
        $request = new RequestData(['REQUEST_URI' => "/foo\x07bar"], [], [], [], []);
        $this->assertSame(Severity::Malicious, PathManipulation::check_controlCharacters($request));
    }

    public function test_del_character_in_path_is_malicious(): void
    {
        $request = new RequestData(['REQUEST_URI' => "/foo\x7fbar"], [], [], [], []);
        $this->assertSame(Severity::Malicious, PathManipulation::check_controlCharacters($request));
    }

    public function test_tab_in_path_is_malicious(): void
    {
        $request = new RequestData(['REQUEST_URI' => "/foo\tbar"], [], [], [], []);
        $this->assertSame(Severity::Malicious, PathManipulation::check_controlCharacters($request));
    }

    public function test_null_byte_in_get_param_is_suspicious(): void
    {
        $request = new RequestData(['REQUEST_URI' => '/'], ["file" => "test\x00.php"], [], [], []);
        $this->assertSame(Severity::Suspicious, PathManipulation::check_controlCharacters($request));
    }

    public function test_control_char_in_post_param_is_suspicious(): void
    {
        $request = new RequestData(['REQUEST_URI' => '/'], [], ["data" => "foo\x01bar"], [], []);
        $this->assertSame(Severity::Suspicious, PathManipulation::check_controlCharacters($request));
    }

    public function test_tab_in_param_is_allowed(): void
    {
        $request = new RequestData(['REQUEST_URI' => '/'], ['text' => "col1\tcol2"], [], [], []);
        $this->assertNull(PathManipulation::check_controlCharacters($request));
    }

    public function test_newline_in_param_is_allowed(): void
    {
        $request = new RequestData(['REQUEST_URI' => '/'], ['text' => "line1\nline2"], [], [], []);
        $this->assertNull(PathManipulation::check_controlCharacters($request));
    }

    public function test_carriage_return_in_param_is_allowed(): void
    {
        $request = new RequestData(['REQUEST_URI' => '/'], ['text' => "line1\r\nline2"], [], [], []);
        $this->assertNull(PathManipulation::check_controlCharacters($request));
    }

    public function test_clean_path_has_no_control_characters(): void
    {
        $request = new RequestData(['REQUEST_URI' => '/foo/bar.html'], [], [], [], []);
        $this->assertNull(PathManipulation::check_controlCharacters($request));
    }

    // check_pathLeadingDots

    public function test_dotfile_at_root_is_malicious(): void
    {
        $request = new RequestData(['REQUEST_URI' => '/.env'], [], [], [], []);
        $this->assertSame(Severity::Malicious, PathManipulation::check_pathLeadingDots($request));
    }

    public function test_dotdir_in_path_is_malicious(): void
    {
        $request = new RequestData(['REQUEST_URI' => '/.git/HEAD'], [], [], [], []);
        $this->assertSame(Severity::Malicious, PathManipulation::check_pathLeadingDots($request));
    }

    public function test_nested_dotfile_is_malicious(): void
    {
        $request = new RequestData(['REQUEST_URI' => '/app/config/.env'], [], [], [], []);
        $this->assertSame(Severity::Malicious, PathManipulation::check_pathLeadingDots($request));
    }

    public function test_path_traversal_is_malicious(): void
    {
        $request = new RequestData(['REQUEST_URI' => '/../../etc/passwd'], [], [], [], []);
        $this->assertSame(Severity::Malicious, PathManipulation::check_pathLeadingDots($request));
    }

    public function test_encoded_dot_path_is_malicious(): void
    {
        $request = new RequestData(['REQUEST_URI' => '/%2egit/config'], [], [], [], []);
        $this->assertSame(Severity::Malicious, PathManipulation::check_pathLeadingDots($request));
    }

    public function test_double_encoded_dot_path_is_malicious(): void
    {
        $request = new RequestData(['REQUEST_URI' => '/%252e%252e/etc/passwd'], [], [], [], []);
        $this->assertSame(Severity::Malicious, PathManipulation::check_pathLeadingDots($request));
    }

    public function test_backslash_dot_path_is_malicious(): void
    {
        $request = new RequestData(['REQUEST_URI' => '\\.git\\config'], [], [], [], []);
        $this->assertSame(Severity::Malicious, PathManipulation::check_pathLeadingDots($request));
    }

    public function test_path_starting_with_dot_is_malicious(): void
    {
        $request = new RequestData(['REQUEST_URI' => '.hidden'], [], [], [], []);
        $this->assertSame(Severity::Malicious, PathManipulation::check_pathLeadingDots($request));
    }

    public function test_normal_path_has_no_leading_dots(): void
    {
        $request = new RequestData(['REQUEST_URI' => '/about/contact.html'], [], [], [], []);
        $this->assertNull(PathManipulation::check_pathLeadingDots($request));
    }

    public function test_dot_in_filename_is_fine(): void
    {
        $request = new RequestData(['REQUEST_URI' => '/images/photo.jpg'], [], [], [], []);
        $this->assertNull(PathManipulation::check_pathLeadingDots($request));
    }

    public function test_multiple_dots_in_filename_is_fine(): void
    {
        $request = new RequestData(['REQUEST_URI' => '/files/archive.tar.gz'], [], [], [], []);
        $this->assertNull(PathManipulation::check_pathLeadingDots($request));
    }

    // check_pathGlobAttempts

    public function test_asterisk_in_path_is_suspicious(): void
    {
        $request = new RequestData(['REQUEST_URI' => '/files/*'], [], [], [], []);
        $this->assertSame(Severity::Suspicious, PathManipulation::check_pathGlobAttempts($request));
    }

    public function test_square_brackets_in_path_is_suspicious(): void
    {
        $request = new RequestData(['REQUEST_URI' => '/files/[test]'], [], [], [], []);
        $this->assertSame(Severity::Suspicious, PathManipulation::check_pathGlobAttempts($request));
    }

    public function test_curly_braces_in_path_is_suspicious(): void
    {
        $request = new RequestData(['REQUEST_URI' => '/files/{a,b,c}'], [], [], [], []);
        $this->assertSame(Severity::Suspicious, PathManipulation::check_pathGlobAttempts($request));
    }

    public function test_encoded_asterisk_in_path_is_suspicious(): void
    {
        $request = new RequestData(['REQUEST_URI' => '/files/%2a'], [], [], [], []);
        $this->assertSame(Severity::Suspicious, PathManipulation::check_pathGlobAttempts($request));
    }

    public function test_normal_path_has_no_glob_characters(): void
    {
        $request = new RequestData(['REQUEST_URI' => '/about/contact'], [], [], [], []);
        $this->assertNull(PathManipulation::check_pathGlobAttempts($request));
    }

    // check_parametersPathTraversal

    public function test_traversal_at_start_of_get_param_is_suspicious(): void
    {
        $request = new RequestData(['REQUEST_URI' => '/'], ['file' => '../../../etc/passwd'], [], [], []);
        $this->assertSame(Severity::Suspicious, PathManipulation::check_parametersPathTraversal($request));
    }

    public function test_traversal_at_start_of_post_param_is_suspicious(): void
    {
        $request = new RequestData(['REQUEST_URI' => '/'], [], ['path' => '../secret'], [], []);
        $this->assertSame(Severity::Suspicious, PathManipulation::check_parametersPathTraversal($request));
    }

    public function test_traversal_at_start_of_cookie_is_suspicious(): void
    {
        $request = new RequestData(['REQUEST_URI' => '/'], [], [], [], ['data' => '../../../etc/shadow']);
        $this->assertSame(Severity::Suspicious, PathManipulation::check_parametersPathTraversal($request));
    }

    public function test_traversal_in_uploaded_filename_is_suspicious(): void
    {
        $request = new RequestData(['REQUEST_URI' => '/'], [], [], ['../../../etc/cron.d/backdoor'], []);
        $this->assertSame(Severity::Suspicious, PathManipulation::check_parametersPathTraversal($request));
    }

    public function test_traversal_mid_string_is_not_flagged(): void
    {
        $request = new RequestData(['REQUEST_URI' => '/'], ['text' => 'navigate to ../parent'], [], [], []);
        $this->assertNull(PathManipulation::check_parametersPathTraversal($request));
    }

    public function test_normal_param_values_are_fine(): void
    {
        $request = new RequestData(['REQUEST_URI' => '/'], ['q' => 'hello world'], [], [], []);
        $this->assertNull(PathManipulation::check_parametersPathTraversal($request));
    }

    public function test_relative_path_without_traversal_is_fine(): void
    {
        $request = new RequestData(['REQUEST_URI' => '/'], ['path' => 'subdir/file.txt'], [], [], []);
        $this->assertNull(PathManipulation::check_parametersPathTraversal($request));
    }

    // check_overEncoding

    public function test_double_encoded_path_is_malicious(): void
    {
        $request = new RequestData(['REQUEST_URI' => '/%252e%252e/etc/passwd'], [], [], [], []);
        $this->assertSame(Severity::Malicious, PathManipulation::check_overEncoding($request));
    }

    public function test_double_encoded_slash_in_path_is_malicious(): void
    {
        $request = new RequestData(['REQUEST_URI' => '/foo%252fbar'], [], [], [], []);
        $this->assertSame(Severity::Malicious, PathManipulation::check_overEncoding($request));
    }

    public function test_double_encoded_param_is_suspicious(): void
    {
        $request = new RequestData(['REQUEST_URI' => '/'], ['q' => '%252e%252e'], [], [], []);
        $this->assertSame(Severity::Suspicious, PathManipulation::check_overEncoding($request));
    }

    public function test_single_encoded_path_is_fine(): void
    {
        $request = new RequestData(['REQUEST_URI' => '/foo%20bar'], [], [], [], []);
        $this->assertNull(PathManipulation::check_overEncoding($request));
    }

    public function test_unencoded_path_is_fine(): void
    {
        $request = new RequestData(['REQUEST_URI' => '/foo/bar'], [], [], [], []);
        $this->assertNull(PathManipulation::check_overEncoding($request));
    }

    public function test_literal_percent_in_path_is_fine(): void
    {
        $request = new RequestData(['REQUEST_URI' => '/100%done'], [], [], [], []);
        $this->assertNull(PathManipulation::check_overEncoding($request));
    }

    // check_longUrl

    public function test_normal_url_is_fine(): void
    {
        $request = new RequestData(['REQUEST_URI' => '/about'], [], [], [], []);
        $this->assertNull(PathManipulation::check_longUrl($request));
    }

    public function test_url_at_2048_is_fine(): void
    {
        $path = '/' . str_repeat('a', 2047);
        $request = new RequestData(['REQUEST_URI' => $path], [], [], [], []);
        $this->assertNull(PathManipulation::check_longUrl($request));
    }

    public function test_url_over_2048_is_suspicious(): void
    {
        $path = '/' . str_repeat('a', 2048);
        $request = new RequestData(['REQUEST_URI' => $path], [], [], [], []);
        $this->assertSame(Severity::Suspicious, PathManipulation::check_longUrl($request));
    }

    public function test_long_url_from_path_plus_query_is_suspicious(): void
    {
        $path = '/' . str_repeat('a', 1024);
        $request = new RequestData(['REQUEST_URI' => $path], ['q' => str_repeat('b', 1100)], [], [], []);
        $this->assertSame(Severity::Suspicious, PathManipulation::check_longUrl($request));
    }

    public function test_long_query_alone_is_suspicious(): void
    {
        $request = new RequestData(['REQUEST_URI' => '/'], ['q' => str_repeat('x', 2100)], [], [], []);
        $this->assertSame(Severity::Suspicious, PathManipulation::check_longUrl($request));
    }

    // check() integration — severity escalation

    public function test_clean_request_returns_null(): void
    {
        $request = new RequestData(['REQUEST_URI' => '/about/contact.html'], ['q' => 'hello'], [], [], []);
        $this->assertNull($this->rule->check($request));
    }

    public function test_malicious_signal_returned_immediately(): void
    {
        $request = new RequestData(['REQUEST_URI' => "/.env\x00"], [], [], [], []);
        $this->assertSame(Severity::Malicious, $this->rule->check($request));
    }

    public function test_suspicious_only_returns_suspicious(): void
    {
        $path = '/' . str_repeat('a', 2048);
        $request = new RequestData(['REQUEST_URI' => $path], [], [], [], []);
        $this->assertSame(Severity::Suspicious, $this->rule->check($request));
    }

    public function test_malicious_takes_priority_over_suspicious(): void
    {
        $long_and_dotfile = '/.env/' . str_repeat('a', 2048);
        $request = new RequestData(['REQUEST_URI' => $long_and_dotfile], [], [], [], []);
        $this->assertSame(Severity::Malicious, $this->rule->check($request));
    }

}
