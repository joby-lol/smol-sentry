<?php

namespace Joby\Smol\Sentry\InspectionRules;

use PHPUnit\Framework\TestCase;

class RequestDataTest extends TestCase
{

    // userAgent()

    public function test_user_agent_returns_lowercased_value(): void
    {
        $request = new RequestData(['HTTP_USER_AGENT' => 'Mozilla/5.0'], [], [], [], []);
        $this->assertSame('mozilla/5.0', $request->userAgent());
    }

    public function test_user_agent_trims_whitespace(): void
    {
        $request = new RequestData(['HTTP_USER_AGENT' => '  curl/8.0  '], [], [], [], []);
        $this->assertSame('curl/8.0', $request->userAgent());
    }

    public function test_user_agent_returns_empty_string_when_missing(): void
    {
        $request = new RequestData([], [], [], [], []);
        $this->assertSame('', $request->userAgent());
    }

    public function test_user_agent_returns_empty_string_when_empty(): void
    {
        $request = new RequestData(['HTTP_USER_AGENT' => ''], [], [], [], []);
        $this->assertSame('', $request->userAgent());
    }

    // pathString()

    public function test_path_string_returns_request_uri_without_query(): void
    {
        $request = new RequestData(['REQUEST_URI' => '/foo/bar?q=1'], [], [], [], []);
        $this->assertSame('/foo/bar', $request->pathString(false));
    }

    public function test_path_string_normalized(): void
    {
        $request = new RequestData(['REQUEST_URI' => '/Foo/%42ar'], [], [], [], []);
        $this->assertSame('/foo/bar', $request->pathString(true));
    }

    public function test_path_string_returns_slash_when_missing(): void
    {
        $request = new RequestData([], [], [], [], []);
        $this->assertSame('/', $request->pathString(false));
    }

    // queryString()

    public function test_query_string_includes_keys_and_values(): void
    {
        $request = new RequestData([], ['foo' => 'bar', 'baz' => 'qux'], [], [], []);
        $result = $request->queryString(false);
        $this->assertStringContainsString('foo=bar', $result);
        $this->assertStringContainsString('baz=qux', $result);
    }

    public function test_query_string_normalized(): void
    {
        $request = new RequestData([], ['key' => '%41%42%43'], [], [], []);
        $this->assertStringContainsString('key=abc', $request->queryString(true));
    }

    public function test_query_string_empty_when_no_get(): void
    {
        $request = new RequestData([], [], [], [], []);
        $this->assertSame('', $request->queryString(false));
    }

    // postString()

    public function test_post_string_includes_keys_and_values(): void
    {
        $request = new RequestData([], [], ['name' => 'alice'], [], []);
        $this->assertStringContainsString('name=alice', $request->postString(false));
    }

    public function test_post_string_normalized(): void
    {
        $request = new RequestData([], [], ['field' => 'Hello%20World'], [], []);
        $this->assertStringContainsString('field=hello world', $request->postString(true));
    }

    // cookieString()

    public function test_cookie_string_includes_keys_and_values(): void
    {
        $request = new RequestData([], [], [], [], ['session' => 'abc123']);
        $this->assertStringContainsString('session=abc123', $request->cookieString(false));
    }

    public function test_cookie_string_normalized(): void
    {
        $request = new RequestData([], [], [], [], ['token' => 'ABC']);
        $this->assertStringContainsString('token=abc', $request->cookieString(true));
    }

    // filesString()

    public function test_files_string_contains_filenames(): void
    {
        $request = new RequestData([], [], [], ['photo.jpg', 'doc.pdf'], []);
        $result = $request->filesString(false);
        $this->assertStringContainsString('photo.jpg', $result);
        $this->assertStringContainsString('doc.pdf', $result);
    }

    public function test_files_string_normalized(): void
    {
        $request = new RequestData([], [], [], ['Photo.JPG'], []);
        $this->assertStringContainsString('photo.jpg', $request->filesString(true));
    }

    public function test_files_string_empty_when_no_files(): void
    {
        $request = new RequestData([], [], [], [], []);
        $this->assertSame('', $request->filesString(false));
    }

    // parameterString()

    public function test_parameter_string_combines_all_sources(): void
    {
        $request = new RequestData(
            [],
            ['g' => 'get_val'],
            ['p' => 'post_val'],
            ['file.txt'],
            ['c' => 'cookie_val'],
        );
        $result = $request->parameterString(false);
        $this->assertStringContainsString('get_val', $result);
        $this->assertStringContainsString('post_val', $result);
        $this->assertStringContainsString('file.txt', $result);
        $this->assertStringContainsString('cookie_val', $result);
    }

    // allParameterValues()

    public function test_all_parameter_values_yields_all_sources(): void
    {
        $request = new RequestData(
            [],
            ['a' => 'from_get'],
            ['b' => 'from_post'],
            ['from_file'],
            ['c' => 'from_cookie'],
        );
        $values = iterator_to_array($request->allParameterValues(false));
        $this->assertContains('from_get', $values);
        $this->assertContains('from_post', $values);
        $this->assertContains('from_file', $values);
        $this->assertContains('from_cookie', $values);
    }

    public function test_all_parameter_values_normalized(): void
    {
        $request = new RequestData([], ['a' => 'UPPER'], [], [], []);
        $values = iterator_to_array($request->allParameterValues(true));
        $this->assertContains('upper', $values);
        $this->assertNotContains('UPPER', $values);
    }

    public function test_all_parameter_values_empty_when_no_params(): void
    {
        $request = new RequestData([], [], [], [], []);
        $values = iterator_to_array($request->allParameterValues(false));
        $this->assertEmpty($values);
    }

    // normalizeString()

    public function test_normalize_lowercases(): void
    {
        $this->assertSame('hello', RequestData::normalizeString('HELLO'));
    }

    public function test_normalize_decodes_url_encoding(): void
    {
        $this->assertSame('hello world', RequestData::normalizeString('Hello%20World'));
    }

    public function test_normalize_decodes_double_encoding(): void
    {
        $this->assertSame('.env', RequestData::normalizeString('%252e%2565nv'));
    }

    public function test_normalize_replaces_backslashes(): void
    {
        $this->assertSame('foo/bar/baz', RequestData::normalizeString('foo\\bar\\baz'));
    }

    public function test_normalize_handles_all_transforms_together(): void
    {
        $this->assertSame('foo/bar', RequestData::normalizeString('FOO\\%42ar'));
    }

    public function test_normalize_leaves_clean_strings_unchanged(): void
    {
        $this->assertSame('hello', RequestData::normalizeString('hello'));
    }

    public function test_normalize_handles_literal_percent(): void
    {
        $input = '100% done';
        $result = RequestData::normalizeString($input);
        $this->assertSame('100% done', $result);
    }

}
