<?php
/**
 * Build script: compress index.dev.php into index.php
 *
 * Usage:
 *   php build.php
 */

declare(strict_types=1);

$source = __DIR__ . '/index.dev.php';
$target = __DIR__ . '/index.php';

function compressCss(string $css): string {
    $css = preg_replace('!\/\*.*?\*\/!s', '', $css);
    $css = preg_replace('/\s+/u', ' ', $css);
    $css = preg_replace('/\s*([{};:,>~+])\s*/u', '$1', $css);
    $css = str_replace(';}', '}', $css);
    return trim($css);
}

if (!file_exists($source)) {
    fwrite(STDERR, "Source file not found: {$source}\n");
    exit(1);
}

$minified = @php_strip_whitespace($source);
if ($minified === false) {
    fwrite(STDERR, "Failed to read or minify source file: {$source}\n");
    exit(2);
}

$minified = preg_replace_callback(
    '/(<style\b[^>]*>)(.*?)(<\/style>)/is',
    function (array $matches) {
        return $matches[1] . compressCss($matches[2]) . $matches[3];
    },
    $minified
);

$result = @file_put_contents($target, $minified);
if ($result === false) {
    fwrite(STDERR, "Failed to write target file: {$target}\n");
    exit(3);
}

fwrite(STDOUT, "Compressed {$source} to {$target} ({$result} bytes).\n");
exit(0);
