<?php

/**
 * smolSentry
 * https://github.com/joby-lol/smol-sentry
 * (c) 2026 Joby Elliott code@joby.lol
 * MIT License https://opensource.org/licenses/MIT
 */

namespace Joby\Smol\Sentry\InspectionRules;

use Generator;
use RuntimeException;

abstract class AbstractDataFileRule implements InspectionRule
{

    /**
     * Files to include in the lines listing
     * @var array<string> FILES
     */
    protected const FILES = [];

    /**
     * @return Generator<string>
     */
    protected function lines(): Generator
    {
        foreach (static::FILES as $filename) {
            $file = fopen($filename, "r");
            if ($file === false)
                throw new RuntimeException("Failed to read file $filename");
            while ($line = fgets($file)) {
                $line = trim($line);
                if (empty($line))
                    continue;
                if (str_starts_with($line, "#"))
                    continue;
                yield strtolower($line);
            }
        }
    }

}
