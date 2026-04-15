<?php

/**
 * smolSentry
 * https://github.com/joby-lol/smol-sentry
 * (c) 2026 Joby Elliott code@joby.lol
 * MIT License https://opensource.org/licenses/MIT
 */

namespace Joby\Smol\Sentry\InspectionRules;

use Generator;

/**
 * Basic DTO for storing flattened/hinted data for the raw request so that it's easier to work with and pass around in a useful/testable way.
 */
class RequestData
{

    /**
     * @param array<string,string> $SERVER
     * @param array<string,string> $GET
     * @param array<string,string> $POST
     * @param array<int,string> $FILES
     * @param array<string,string> $COOKIE
     */
    public function __construct(
        public readonly array $SERVER,
        public readonly array $GET,
        public readonly array $POST,
        public readonly array $FILES,
        public readonly array $COOKIE,
    ) {}

    /**
     * Get an iterator of all user-provided values. Optionally normalized to lower case, forward slashes, and decoding arbitrary-depth URL encoding.
     * 
     * @return Generator<string>
     */
    public function allParameterValues(bool $normalized): Generator
    {
        foreach ($this->GET as $v)
            yield $normalized ? static::normalizeString($v) : $v;
        foreach ($this->POST as $v)
            yield $normalized ? static::normalizeString($v) : $v;
        foreach ($this->FILES as $v)
            yield $normalized ? static::normalizeString($v) : $v;
        foreach ($this->COOKIE as $v)
            yield $normalized ? static::normalizeString($v) : $v;
    }

    /**
     * Get all user-provided parameters other than the path, in a single string. Optionally normalized to lowercase, forward slashes, and the removal of arbitrary-depth url encoding.
     */
    public function parameterString(bool $normalized): string
    {
        return implode(';', [
            $this->queryString($normalized),
            $this->postString($normalized),
            $this->filesString($normalized),
            $this->cookieString($normalized),
        ]);
    }

    /**
     * Get the path portion of the request, not including the query string. Optionally normalized to lower case, forward slashes, and decoding arbitrary-depth URL encoding.
     */
    public function pathString(bool $normalized): string
    {
        $path = $this->SERVER['REQUEST_URI'] ?? '/';
        $qpos = strpos($path, '?');
        if ($qpos !== false)
            $path = substr($path, 0, $qpos);
        if ($normalized)
            $path = static::normalizeString($path);
        return $path;
    }

    /**
     * Get the query string of the request. Optionally normalized to lower case, forward slashes, and decoding arbitrary-depth URL encoding. Note that normalization may produce an invalid query string, but may be useful for certain checks.
     */
    public function queryString(bool $normalized): string
    {
        $query = static::arrayString($this->GET);
        if ($normalized)
            $query = static::normalizeString($query);
        return $query;
    }

    /**
     * Get a single string of all user-provided POST data. Optionally normalized to lower case, forward slashes, and decoding arbitrary-depth URL encoding.
     */
    public function postString(bool $normalized): string
    {
        $query = static::arrayString($this->POST);
        if ($normalized)
            $query = static::normalizeString($query);
        return $query;
    }

    /**
     * Get a single string of all user-provided cookie data. Optionally normalized to lower case, forward slashes, and decoding arbitrary-depth URL encoding.
     */
    public function cookieString(bool $normalized): string
    {
        $query = static::arrayString($this->COOKIE);
        if ($normalized)
            $query = static::normalizeString($query);
        return $query;
    }

    /**
     * Get a single string of all non-file-content user-provided file upload data. Optionally normalized to lower case, forward slashes, and decoding arbitrary-depth URL encoding.
     */
    public function filesString(bool $normalized): string
    {
        $query = implode(' ', $this->FILES);
        if ($normalized)
            $query = static::normalizeString($query);
        return $query;
    }

    /**
     * @param array<string,string> $array
     * @return string
     */
    protected static function arrayString(array $array): string
    {
        $string = [];
        foreach ($array as $key => $value) {
            $string[] = $key . '=' . $value;
        }
        return implode(' ', $string);
    }

    /**
     * Get the user agent string of the request.
     */
    public function userAgent(): string
    {
        $ua = $this->SERVER['HTTP_USER_AGENT'] ?? '';
        $ua = trim($ua);
        $ua = strtolower($ua);
        return $ua;
    }

    /**
     * Normalize a string before security checks. Useful for avoiding obfuscation tactics: mismatched slashes, case shenanigans, and nested URL encoding.
     * @internal
     */
    public static function normalizeString(string $string): string
    {
        // arbitrary-depth url-decoding
        do {
            $previous = $string;
            $string = urldecode($string);
        } while ($string !== $previous);
        // normalize slashes and lowercase
        $string = str_replace('\\', '/', $string);
        $string = strtolower($string);
        // return normalized value
        return $string;
    }

}
