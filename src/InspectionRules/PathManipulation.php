<?php

/**
 * smolSentry
 * https://github.com/joby-lol/smol-sentry
 * (c) 2026 Joby Elliott code@joby.lol
 * MIT License https://opensource.org/licenses/MIT
 */

namespace Joby\Smol\Sentry\InspectionRules;

use Joby\Smol\Sentry\Severity;

class PathManipulation implements InspectionRule
{

    public function check(RequestData $request): Severity|null
    {
        $suspicious = false;
        foreach ($this->checks() as $check) {
            $result = $check($request);
            if ($result === Severity::Malicious)
                return Severity::Malicious;
            elseif ($result === Severity::Suspicious)
                $suspicious = true;
        }
        if ($suspicious)
            return Severity::Suspicious;
        return null;
    }

    /**
     * @return array<callable(RequestData):(Severity|null)>
     */
    protected function checks(): array
    {
        return [
            static::check_controlCharacters(...),
            static::check_pathLeadingDots(...),
            static::check_pathGlobAttempts(...),
            static::check_parametersPathTraversal(...),
            static::check_overEncoding(...),
            static::check_longUrl(...),
        ];
    }

    public static function check_controlCharacters(RequestData $request): Severity|null
    {
        if (preg_match("/[\x00-\x1f\x7f]/", $request->pathString(true)))
            return Severity::Malicious;
        elseif (preg_match("/[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]/", $request->parameterString(true)))
            return Severity::Suspicious;
        else
            return null;
    }

    /**
     * @internal
     */
    public static function check_pathLeadingDots(RequestData $request): Severity|null
    {
        $path = $request->pathString(true);
        if (str_starts_with($path, '.'))
            return Severity::Malicious;
        elseif (str_contains($path, '/.'))
            return Severity::Malicious;
        return null;
    }

    public static function check_parametersPathTraversal(RequestData $request): Severity|null
    {
        foreach ($request->allParameterValues(true) as $value) {
            if (str_starts_with($value, '../'))
                return Severity::Suspicious;
        }
        return null;
    }

    public static function check_pathGlobAttempts(RequestData $request): Severity|null
    {
        $path = $request->pathString(true);
        if (preg_match('/[\*\[\]\{\}]/', $path))
            return Severity::Suspicious;
        return null;
    }

    /**
     * @internal
     */
    public static function check_overEncoding(RequestData $request): Severity|null
    {
        if (static::containsOverEncoding($request->pathString(false)))
            return Severity::Malicious;
        if (static::containsOverEncoding($request->parameterString(false)))
            return Severity::Suspicious;
        return null;
    }

    /**
     * @internal
     */
    public static function check_longUrl(RequestData $request): Severity|null
    {
        if ((strlen($request->pathString(false)) + strlen($request->queryString(false))) > 2048)
            return Severity::Suspicious;
        return null;
    }

    protected static function containsOverEncoding(string $string): bool
    {
        $decoded = urldecode($string);
        $double = urldecode($decoded);
        return $decoded !== $double;
    }

}
