<?php

/**
 * smolSentry
 * https://github.com/joby-lol/smol-sentry
 * (c) 2026 Joby Elliott code@joby.lol
 * MIT License https://opensource.org/licenses/MIT
 */

namespace Joby\Smol\Sentry;

use Joby\Smol\Sentry\InspectionRules\InspectionRule;
use Joby\Smol\Sentry\InspectionRules\MaliciousUserAgents;
use Joby\Smol\Sentry\InspectionRules\PathManipulation;
use Joby\Smol\Sentry\InspectionRules\RequestData;
use Joby\Smol\Sentry\InspectionRules\RestrictedFiles;
use RuntimeException;

class Inspector
{

    /**
     * An array of named rules to have the request matched against.
     * @var array<string,InspectionRule> $rules
     */
    public array $rules = [];

    public function __construct(
        protected Sentry $sentry,
    ) {}

    /**
     * @param array<string,string>|null $SERVER
     * @param array<string,string|array<string,string>>|null $GET
     * @param array<string,string|array<string,string>>|null $POST
     * @param array<string, array{name: string|array<mixed>, type: string|array<mixed>, tmp_name: string|array<mixed>, error: int|array<mixed>, size: int|array<mixed>}>|null $FILES
     * @param array<string,string|array<string,string>>|null $COOKIE
     */
    public function inspect(
        array|null $SERVER = null,
        array|null $GET = null,
        array|null $POST = null,
        array|null $FILES = null,
        array|null $COOKIE = null,
    ): void
    {
        $request = new RequestData(
            $SERVER ??= $_SERVER, // @phpstan-ignore-line $_SERVER shape is right
            static::flatten($GET ?? $_GET),
            static::flatten($POST ?? $_POST),
            static::flattenFiles($FILES ?? $_FILES), // @phpstan-ignore-line $_FILES has a goofy shape
            static::flatten($COOKIE ?? $_COOKIE),
        );
        $first_suspicious_rule = null;
        foreach ($this->rules as $name => $rule) {
            $result = $rule->check($request);
            if ($result === Severity::Malicious) {
                $this->sentry->signal('Inspector: ' . $name, Severity::Malicious);
                return;
            }
            elseif ($result === Severity::Suspicious) {
                $first_suspicious_rule ??= $name;
            }
        }
        if ($first_suspicious_rule !== null)
            $this->sentry->signal('Inspector: ' . $first_suspicious_rule, Severity::Suspicious);
    }

    public function addRule(string $name, InspectionRule $rule): static
    {
        $this->rules[$name] = $rule;
        return $this;
    }

    public function addDefaultRules(): static
    {
        $this->rules['path_manipulation'] = new PathManipulation();
        $this->rules['restricted_files'] = new RestrictedFiles();
        $this->rules['malicious_user_agents'] = new MaliciousUserAgents();
        return $this;
    }

    /**
     * @param array<string, array{name: string|array<mixed>, type: string|array<mixed>, tmp_name: string|array<mixed>, error: int|array<mixed>, size: int|array<mixed>}> $files
     * @return array<int,string>
     * @internal
     */
    public static function flattenFiles(array $files): array
    {
        $filenames = [];
        foreach ($files as $file) {
            if (is_array($file['name']))
                foreach (static::flatten($file['name']) as $filename)
                    $filenames[] = $filename;
            else
                $filenames[] = $file['name'];
        }
        return $filenames;
    }

    /**
     * @param array<mixed> $array
     * @return array<string,string>
     * @internal
     */
    public static function flatten(array $array): array
    {
        $flattened = [];
        foreach ($array as $key => $value) {
            if (is_array($value))
                foreach (static::flatten($value) as $k => $v) {
                    $flattened_key = $key . '/' . $k;
                    while (array_key_exists($flattened_key, $flattened))
                        $flattened_key .= '_';
                    $flattened[$flattened_key] = $v;
                }
            elseif (is_scalar($value))
                $flattened[(string) $key] = (string) $value;
            else
                throw new RuntimeException("Got a non-scalar value in a flatten() call");
        }
        return $flattened;
    }

}
