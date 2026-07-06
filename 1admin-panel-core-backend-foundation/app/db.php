<?php
/**
 * =====================================================================
 * db.php
 * ---------------------------------------------------------------------
 * Secure PDO database connection layer.
 *
 * Database singleton wrapping PDO with:
 *   - Exception-based error handling (no raw errors leaked to output)
 *   - Prepared statement helpers (query / fetchOne / fetchAll / execute)
 *   - Transaction helpers
 *   - One shared connection reused for the lifetime of the request
 * =====================================================================
 */

if (!defined('APP_BOOTSTRAPPED')) {
    http_response_code(403);
    exit('Direct access forbidden.');
}

final class Database
{
    private static ?Database $instance = null;
    private PDO $pdo;

    private function __construct()
    {
        $dsn = sprintf(
            '%s:host=%s;port=%s;dbname=%s;charset=%s',
            DB_DRIVER,
            DB_HOST,
            DB_PORT,
            DB_NAME,
            DB_CHARSET
        );

        $options = [
            PDO::ATTR_ERRMODE            => PDO::ERRMODE_EXCEPTION,
            PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
            PDO::ATTR_EMULATE_PREPARES   => false, // real prepared statements
            PDO::ATTR_PERSISTENT         => false, // safer on shared hosting
        ];

        try {
            $this->pdo = new PDO($dsn, DB_USER, DB_PASS, $options);
        } catch (PDOException $e) {
            error_log('[DB CONNECTION ERROR] ' . $e->getMessage());
            throw new RuntimeException('Database connection failed.');
        }
    }

    private function __clone() {}

    public function __wakeup()
    {
        throw new RuntimeException('Cannot unserialize a singleton.');
    }

    public static function getInstance(): Database
    {
        if (self::$instance === null) {
            self::$instance = new self();
        }
        return self::$instance;
    }

    public function getPdo(): PDO
    {
        return $this->pdo;
    }

    public function query(string $sql, array $params = []): PDOStatement
    {
        $stmt = $this->pdo->prepare($sql);
        $stmt->execute($params);
        return $stmt;
    }

    public function fetchOne(string $sql, array $params = []): ?array
    {
        $row = $this->query($sql, $params)->fetch();
        return $row === false ? null : $row;
    }

    public function fetchAll(string $sql, array $params = []): array
    {
        return $this->query($sql, $params)->fetchAll();
    }

    public function fetchColumn(string $sql, array $params = []): mixed
    {
        $value = $this->query($sql, $params)->fetchColumn();
        return $value === false ? null : $value;
    }

    public function insert(string $sql, array $params = []): string
    {
        $this->query($sql, $params);
        return $this->pdo->lastInsertId();
    }

    public function execute(string $sql, array $params = []): int
    {
        return $this->query($sql, $params)->rowCount();
    }

    public function beginTransaction(): bool
    {
        return $this->pdo->beginTransaction();
    }

    public function commit(): bool
    {
        return $this->pdo->commit();
    }

    public function rollBack(): bool
    {
        if ($this->pdo->inTransaction()) {
            return $this->pdo->rollBack();
        }
        return false;
    }

    public function inTransaction(): bool
    {
        return $this->pdo->inTransaction();
    }

    public function lastInsertId(): string
    {
        return $this->pdo->lastInsertId();
    }
}

/**
 * Convenience global accessor: db()->fetchAll(...)
 */
function db(): Database
{
    return Database::getInstance();
}
