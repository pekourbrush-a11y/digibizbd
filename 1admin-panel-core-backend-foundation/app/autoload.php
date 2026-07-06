<?php
/**
 * =====================================================================
 * autoload.php
 * ---------------------------------------------------------------------
 * Minimal, dependency-free class autoloader for PHP 8.3.
 * No Composer or third-party libraries needed on shared hosting.
 *
 * Any class placed inside /app/classes/ is autoloaded automatically as
 * long as the filename matches the class name, e.g.:
 *   app/classes/Example.php  ->  class Example
 *   app/classes/Models/Foo.php -> namespace Models; class Foo
 *
 * This file only registers the autoloader. Core classes (Database,
 * Response) are required directly by bootstrap.php since they are
 * always-needed, foundational dependencies.
 * =====================================================================
 */

if (!defined('APP_BOOTSTRAPPED')) {
    http_response_code(403);
    exit('Direct access forbidden.');
}

define('APP_CLASSES_PATH', __DIR__ . '/classes');

spl_autoload_register(function (string $className): void {
    $relativePath = str_replace('\\', DIRECTORY_SEPARATOR, $className);
    $filePath = APP_CLASSES_PATH . DIRECTORY_SEPARATOR . $relativePath . '.php';

    if (is_file($filePath)) {
        require_once $filePath;
    }
});
