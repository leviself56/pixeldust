<?php

declare(strict_types=1);

$config = require __DIR__ . '/config.php';

date_default_timezone_set($config['app']['timezone'] ?? 'UTC');

if (session_status() === PHP_SESSION_NONE) {
	session_name($config['app']['session_name'] ?? 'pixeldust_session');
	session_start();
}

function app_config(): array
{
	global $config;
	return $config;
}

function db(): PDO
{
	static $pdo = null;

	if ($pdo instanceof PDO) {
		return $pdo;
	}

	$cfg = app_config()['db'];
	$dsn = sprintf(
		'mysql:host=%s;port=%d;dbname=%s;charset=%s',
		$cfg['host'],
		(int) $cfg['port'],
		$cfg['name'],
		$cfg['charset']
	);

	$pdo = new PDO($dsn, $cfg['user'], $cfg['pass'], [
		PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
		PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
	]);

	try {
		$pdo->exec("SET time_zone = '+00:00'");
	} catch (Throwable $e) {
	}

	return $pdo;
}

function app_timezone_name(): string
{
	return (string) (app_config()['app']['timezone'] ?? 'UTC');
}

function app_timezone_object(): DateTimeZone
{
	try {
		return new DateTimeZone(app_timezone_name());
	} catch (Throwable $e) {
		return new DateTimeZone('UTC');
	}
}

function parse_db_datetime_utc(?string $value): ?DateTimeImmutable
{
	if ($value === null || trim($value) === '') {
		return null;
	}

	$value = trim($value);
	$dateTime = DateTimeImmutable::createFromFormat('Y-m-d H:i:s', $value, new DateTimeZone('UTC'));
	if ($dateTime instanceof DateTimeImmutable) {
		return $dateTime;
	}

	try {
		return new DateTimeImmutable($value, new DateTimeZone('UTC'));
	} catch (Throwable $e) {
		return null;
	}
}

function format_db_datetime(?string $value, string $format = 'Y-m-d H:i:s', string $empty = '-'): string
{
	$dateTimeUtc = parse_db_datetime_utc($value);
	if (!$dateTimeUtc) {
		return $empty;
	}

	return $dateTimeUtc->setTimezone(app_timezone_object())->format($format);
}

function is_installed(): bool
{
	try {
		$stmt = db()->query("SHOW TABLES LIKE 'pd_admin_users'");
		if (!$stmt->fetch()) {
			return false;
		}

		$countStmt = db()->query('SELECT COUNT(*) AS total FROM pd_admin_users');
		$row = $countStmt->fetch();
		return (int) ($row['total'] ?? 0) > 0;
	} catch (Throwable $e) {
		return false;
	}
}

function base_url(): string
{
	$isHttps = !empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off';
	$scheme = $isHttps ? 'https' : 'http';
	$host = $_SERVER['HTTP_HOST'] ?? 'localhost';
	$scriptDir = dirname($_SERVER['SCRIPT_NAME'] ?? '/pixeldust/index.php');

	if (strpos($scriptDir, '/admin') !== false) {
		$scriptDir = dirname($scriptDir);
	}

	return rtrim($scheme . '://' . $host . rtrim($scriptDir, '/'), '/');
}

function e(string $value): string
{
	return htmlspecialchars($value, ENT_QUOTES, 'UTF-8');
}

function redirect(string $path): void
{
	header('Location: ' . $path);
	exit;
}

function flash(string $key, ?string $message = null): ?string
{
	if ($message !== null) {
		$_SESSION['flash'][$key] = $message;
		return null;
	}

	if (!isset($_SESSION['flash'][$key])) {
		return null;
	}

	$msg = (string) $_SESSION['flash'][$key];
	unset($_SESSION['flash'][$key]);
	return $msg;
}

function current_admin(): ?array
{
	if (empty($_SESSION['admin_user_id'])) {
		return null;
	}

	$stmt = db()->prepare('SELECT id, username, created_at, last_login_at FROM pd_admin_users WHERE id = :id LIMIT 1');
	$stmt->execute(['id' => (int) $_SESSION['admin_user_id']]);
	$admin = $stmt->fetch();

	return $admin ?: null;
}

function require_admin(): void
{
	if (!is_installed()) {
		redirect('../install.php');
	}

	if (!current_admin()) {
		flash('error', 'Please login to continue.');
		redirect('../login.php');
	}
}

function sanitize_pixel_key(string $pixelKey): string
{
	$pixelKey = trim($pixelKey);
	if ($pixelKey === '') {
		return '';
	}

	$pixelKey = preg_replace('/\s+/', '_', $pixelKey);
	if (function_exists('mb_strtolower')) {
		$pixelKey = mb_strtolower($pixelKey, 'UTF-8');
	} else {
		$pixelKey = strtolower($pixelKey);
	}

	$pixelKey = preg_replace('/[^a-z0-9_]/', '', $pixelKey);
	$pixelKey = preg_replace('/_+/', '_', $pixelKey);
	$pixelKey = trim($pixelKey, '_');

	return $pixelKey;
}

function create_pixel_if_missing(string $pixelKey, ?int $createdBy = null): int
{
	$pixelKey = sanitize_pixel_key($pixelKey);
	if ($pixelKey === '') {
		throw new InvalidArgumentException('Pixel key is required.');
	}

	$select = db()->prepare('SELECT id FROM pd_pixels WHERE pixel_key = :pixel_key LIMIT 1');
	$select->execute(['pixel_key' => $pixelKey]);
	$row = $select->fetch();

	if ($row) {
		return (int) $row['id'];
	}

	$insert = db()->prepare(
		'INSERT INTO pd_pixels (pixel_key, label, created_by, created_at, updated_at, total_hits)
		 VALUES (:pixel_key, :label, :created_by, NOW(), NOW(), 0)'
	);
	$insert->execute([
		'pixel_key' => $pixelKey,
		'label' => $pixelKey,
		'created_by' => $createdBy,
	]);

	return (int) db()->lastInsertId();
}

function table_exists(PDO $pdo, string $table): bool
{
	$stmt = $pdo->prepare('SELECT COUNT(*) AS total FROM information_schema.TABLES WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = :table_name');
	$stmt->execute(['table_name' => $table]);
	$row = $stmt->fetch();
	return (int) ($row['total'] ?? 0) > 0;
}

function column_exists(PDO $pdo, string $table, string $column): bool
{
	$stmt = $pdo->prepare('SELECT COUNT(*) AS total FROM information_schema.COLUMNS WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = :table_name AND COLUMN_NAME = :column_name');
	$stmt->execute([
		'table_name' => $table,
		'column_name' => $column,
	]);
	$row = $stmt->fetch();
	return (int) ($row['total'] ?? 0) > 0;
}

function index_exists(PDO $pdo, string $table, string $index): bool
{
	$stmt = $pdo->prepare('SELECT COUNT(*) AS total FROM information_schema.STATISTICS WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = :table_name AND INDEX_NAME = :index_name');
	$stmt->execute([
		'table_name' => $table,
		'index_name' => $index,
	]);
	$row = $stmt->fetch();
	return (int) ($row['total'] ?? 0) > 0;
}

function run_schema_migrations(PDO $pdo): array
{
	$applied = [];

	if (!table_exists($pdo, 'pd_admin_users')) {
		$pdo->exec(
			'CREATE TABLE pd_admin_users (
				id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
				username VARCHAR(100) NOT NULL UNIQUE,
				password_hash VARCHAR(255) NOT NULL,
				created_at DATETIME NOT NULL,
				last_login_at DATETIME NULL
			) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4'
		);
		$applied[] = 'Created table pd_admin_users';
	}

	if (!table_exists($pdo, 'pd_pixels')) {
		$pdo->exec(
			'CREATE TABLE pd_pixels (
				id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
				pixel_key VARCHAR(191) NOT NULL UNIQUE,
				label VARCHAR(191) NOT NULL,
				created_by INT UNSIGNED NULL,
				created_at DATETIME NOT NULL,
				updated_at DATETIME NOT NULL,
				total_hits INT UNSIGNED NOT NULL DEFAULT 0,
				INDEX idx_pixel_key (pixel_key)
			) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4'
		);
		$applied[] = 'Created table pd_pixels';
	}

	if (!table_exists($pdo, 'pd_pixel_hits')) {
		$pdo->exec(
			'CREATE TABLE pd_pixel_hits (
				id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
				pixel_id INT UNSIGNED NOT NULL,
				pixel_key VARCHAR(191) NOT NULL,
				hit_at DATETIME NOT NULL,
				ip_address VARCHAR(45) NOT NULL,
				user_agent TEXT NULL,
				referrer TEXT NULL,
				request_uri TEXT NULL,
				query_string TEXT NULL,
				accept_language VARCHAR(255) NULL,
				remote_host VARCHAR(255) NULL,
				INDEX idx_pixel_id (pixel_id),
				INDEX idx_pixel_key (pixel_key),
				INDEX idx_hit_at (hit_at)
			) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4'
		);
		$applied[] = 'Created table pd_pixel_hits';
	}

	if (!table_exists($pdo, 'pd_trigger_actions')) {
		$pdo->exec(
			'CREATE TABLE pd_trigger_actions (
				id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
				trigger_id VARCHAR(191) NOT NULL UNIQUE,
				name VARCHAR(191) NOT NULL,
				webhook_url TEXT NOT NULL,
				payload_template TEXT NULL,
				is_active TINYINT(1) NOT NULL DEFAULT 1,
				is_default TINYINT(1) NOT NULL DEFAULT 0,
				created_by INT UNSIGNED NULL,
				created_at DATETIME NOT NULL,
				updated_at DATETIME NOT NULL,
				INDEX idx_trigger_id (trigger_id),
				INDEX idx_is_active (is_active),
				INDEX idx_is_default (is_default)
			) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4'
		);
		$applied[] = 'Created table pd_trigger_actions';
	}

	if (!table_exists($pdo, 'pd_pixel_trigger_assignments')) {
		$pdo->exec(
			'CREATE TABLE pd_pixel_trigger_assignments (
				id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
				pixel_key VARCHAR(191) NOT NULL,
				trigger_action_id INT UNSIGNED NOT NULL,
				created_at DATETIME NOT NULL,
				UNIQUE KEY uniq_pixel_trigger (pixel_key, trigger_action_id),
				INDEX idx_pixel_key (pixel_key),
				INDEX idx_trigger_action_id (trigger_action_id)
			) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4'
		);
		$applied[] = 'Created table pd_pixel_trigger_assignments';
	}

	if (!table_exists($pdo, 'pd_ip_enrichment')) {
		$pdo->exec(
			'CREATE TABLE pd_ip_enrichment (
				ip_address VARCHAR(45) PRIMARY KEY,
				country_code CHAR(2) NULL,
				region VARCHAR(120) NULL,
				city VARCHAR(120) NULL,
				latitude DECIMAL(9,6) NULL,
				longitude DECIMAL(9,6) NULL,
				asn VARCHAR(20) NULL,
				asn_org VARCHAR(255) NULL,
				isp_name VARCHAR(255) NULL,
				is_proxy TINYINT(1) NOT NULL DEFAULT 0,
				is_hosting TINYINT(1) NOT NULL DEFAULT 0,
				source VARCHAR(50) NOT NULL DEFAULT "unresolved",
				confidence DECIMAL(4,3) NOT NULL DEFAULT 0.000,
				updated_at DATETIME NOT NULL
			) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4'
		);
		$applied[] = 'Created table pd_ip_enrichment';
	}

	if (!table_exists($pdo, 'pd_hit_classification')) {
		$pdo->exec(
			'CREATE TABLE pd_hit_classification (
				hit_id BIGINT UNSIGNED PRIMARY KEY,
				pixel_id INT UNSIGNED NOT NULL,
				pixel_key VARCHAR(191) NOT NULL,
				ip_address VARCHAR(45) NOT NULL,
				email_client_guess VARCHAR(50) NOT NULL DEFAULT "unknown",
				email_client_confidence DECIMAL(4,3) NOT NULL DEFAULT 0.000,
				traffic_type VARCHAR(30) NOT NULL DEFAULT "unknown",
				isp_guess VARCHAR(255) NULL,
				isp_source VARCHAR(30) NOT NULL DEFAULT "unknown",
				classified_at DATETIME NOT NULL,
				INDEX idx_pixel_time (pixel_id, classified_at),
				INDEX idx_pixel_ip (pixel_id, ip_address),
				INDEX idx_email_client (email_client_guess),
				INDEX idx_traffic_type (traffic_type)
			) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4'
		);
		$applied[] = 'Created table pd_hit_classification';
	}

	if (!table_exists($pdo, 'pd_ip_enrichment_queue')) {
		$pdo->exec(
			'CREATE TABLE pd_ip_enrichment_queue (
				ip_address VARCHAR(45) PRIMARY KEY,
				first_seen_at DATETIME NOT NULL,
				last_seen_at DATETIME NOT NULL,
				next_attempt_at DATETIME NOT NULL,
				attempt_count INT UNSIGNED NOT NULL DEFAULT 0,
				last_error VARCHAR(255) NULL,
				processed_at DATETIME NULL,
				created_at DATETIME NOT NULL,
				updated_at DATETIME NOT NULL
			) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4'
		);
		$applied[] = 'Created table pd_ip_enrichment_queue';
	}

	$pixelColumns = [
		'label' => 'ALTER TABLE pd_pixels ADD COLUMN label VARCHAR(191) NOT NULL DEFAULT "" AFTER pixel_key',
		'created_by' => 'ALTER TABLE pd_pixels ADD COLUMN created_by INT UNSIGNED NULL AFTER label',
		'created_at' => 'ALTER TABLE pd_pixels ADD COLUMN created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP AFTER created_by',
		'updated_at' => 'ALTER TABLE pd_pixels ADD COLUMN updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP AFTER created_at',
		'total_hits' => 'ALTER TABLE pd_pixels ADD COLUMN total_hits INT UNSIGNED NOT NULL DEFAULT 0 AFTER updated_at',
	];

	foreach ($pixelColumns as $column => $sql) {
		if (!column_exists($pdo, 'pd_pixels', $column)) {
			$pdo->exec($sql);
			$applied[] = 'Added column pd_pixels.' . $column;
		}
	}

	$hitColumns = [
		'pixel_id' => 'ALTER TABLE pd_pixel_hits ADD COLUMN pixel_id INT UNSIGNED NOT NULL AFTER id',
		'pixel_key' => 'ALTER TABLE pd_pixel_hits ADD COLUMN pixel_key VARCHAR(191) NOT NULL AFTER pixel_id',
		'hit_at' => 'ALTER TABLE pd_pixel_hits ADD COLUMN hit_at DATETIME NOT NULL AFTER pixel_key',
		'ip_address' => 'ALTER TABLE pd_pixel_hits ADD COLUMN ip_address VARCHAR(45) NOT NULL AFTER hit_at',
		'user_agent' => 'ALTER TABLE pd_pixel_hits ADD COLUMN user_agent TEXT NULL AFTER ip_address',
		'referrer' => 'ALTER TABLE pd_pixel_hits ADD COLUMN referrer TEXT NULL AFTER user_agent',
		'request_uri' => 'ALTER TABLE pd_pixel_hits ADD COLUMN request_uri TEXT NULL AFTER referrer',
		'query_string' => 'ALTER TABLE pd_pixel_hits ADD COLUMN query_string TEXT NULL AFTER request_uri',
		'accept_language' => 'ALTER TABLE pd_pixel_hits ADD COLUMN accept_language VARCHAR(255) NULL AFTER query_string',
		'remote_host' => 'ALTER TABLE pd_pixel_hits ADD COLUMN remote_host VARCHAR(255) NULL AFTER accept_language',
	];

	foreach ($hitColumns as $column => $sql) {
		if (!column_exists($pdo, 'pd_pixel_hits', $column)) {
			$pdo->exec($sql);
			$applied[] = 'Added column pd_pixel_hits.' . $column;
		}
	}

	$adminColumns = [
		'last_login_at' => 'ALTER TABLE pd_admin_users ADD COLUMN last_login_at DATETIME NULL AFTER created_at',
	];

	foreach ($adminColumns as $column => $sql) {
		if (!column_exists($pdo, 'pd_admin_users', $column)) {
			$pdo->exec($sql);
			$applied[] = 'Added column pd_admin_users.' . $column;
		}
	}

	$triggerColumns = [
		'trigger_id' => 'ALTER TABLE pd_trigger_actions ADD COLUMN trigger_id VARCHAR(191) NOT NULL AFTER id',
		'name' => 'ALTER TABLE pd_trigger_actions ADD COLUMN name VARCHAR(191) NOT NULL AFTER trigger_id',
		'webhook_url' => 'ALTER TABLE pd_trigger_actions ADD COLUMN webhook_url TEXT NOT NULL AFTER name',
		'payload_template' => 'ALTER TABLE pd_trigger_actions ADD COLUMN payload_template TEXT NULL AFTER webhook_url',
		'is_active' => 'ALTER TABLE pd_trigger_actions ADD COLUMN is_active TINYINT(1) NOT NULL DEFAULT 1 AFTER payload_template',
		'is_default' => 'ALTER TABLE pd_trigger_actions ADD COLUMN is_default TINYINT(1) NOT NULL DEFAULT 0 AFTER is_active',
		'created_by' => 'ALTER TABLE pd_trigger_actions ADD COLUMN created_by INT UNSIGNED NULL AFTER is_default',
		'created_at' => 'ALTER TABLE pd_trigger_actions ADD COLUMN created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP AFTER created_by',
		'updated_at' => 'ALTER TABLE pd_trigger_actions ADD COLUMN updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP AFTER created_at',
	];

	foreach ($triggerColumns as $column => $sql) {
		if (!column_exists($pdo, 'pd_trigger_actions', $column)) {
			$pdo->exec($sql);
			$applied[] = 'Added column pd_trigger_actions.' . $column;
		}
	}

	$assignmentColumns = [
		'pixel_key' => 'ALTER TABLE pd_pixel_trigger_assignments ADD COLUMN pixel_key VARCHAR(191) NOT NULL AFTER id',
		'trigger_action_id' => 'ALTER TABLE pd_pixel_trigger_assignments ADD COLUMN trigger_action_id INT UNSIGNED NOT NULL AFTER pixel_key',
		'created_at' => 'ALTER TABLE pd_pixel_trigger_assignments ADD COLUMN created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP AFTER trigger_action_id',
	];

	foreach ($assignmentColumns as $column => $sql) {
		if (!column_exists($pdo, 'pd_pixel_trigger_assignments', $column)) {
			$pdo->exec($sql);
			$applied[] = 'Added column pd_pixel_trigger_assignments.' . $column;
		}
	}

	$ipEnrichmentColumns = [
		'country_code' => 'ALTER TABLE pd_ip_enrichment ADD COLUMN country_code CHAR(2) NULL AFTER ip_address',
		'region' => 'ALTER TABLE pd_ip_enrichment ADD COLUMN region VARCHAR(120) NULL AFTER country_code',
		'city' => 'ALTER TABLE pd_ip_enrichment ADD COLUMN city VARCHAR(120) NULL AFTER region',
		'latitude' => 'ALTER TABLE pd_ip_enrichment ADD COLUMN latitude DECIMAL(9,6) NULL AFTER city',
		'longitude' => 'ALTER TABLE pd_ip_enrichment ADD COLUMN longitude DECIMAL(9,6) NULL AFTER latitude',
		'asn' => 'ALTER TABLE pd_ip_enrichment ADD COLUMN asn VARCHAR(20) NULL AFTER longitude',
		'asn_org' => 'ALTER TABLE pd_ip_enrichment ADD COLUMN asn_org VARCHAR(255) NULL AFTER asn',
		'isp_name' => 'ALTER TABLE pd_ip_enrichment ADD COLUMN isp_name VARCHAR(255) NULL AFTER asn_org',
		'is_proxy' => 'ALTER TABLE pd_ip_enrichment ADD COLUMN is_proxy TINYINT(1) NOT NULL DEFAULT 0 AFTER isp_name',
		'is_hosting' => 'ALTER TABLE pd_ip_enrichment ADD COLUMN is_hosting TINYINT(1) NOT NULL DEFAULT 0 AFTER is_proxy',
		'source' => 'ALTER TABLE pd_ip_enrichment ADD COLUMN source VARCHAR(50) NOT NULL DEFAULT "unresolved" AFTER is_hosting',
		'confidence' => 'ALTER TABLE pd_ip_enrichment ADD COLUMN confidence DECIMAL(4,3) NOT NULL DEFAULT 0.000 AFTER source',
		'updated_at' => 'ALTER TABLE pd_ip_enrichment ADD COLUMN updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP AFTER confidence',
	];

	foreach ($ipEnrichmentColumns as $column => $sql) {
		if (!column_exists($pdo, 'pd_ip_enrichment', $column)) {
			$pdo->exec($sql);
			$applied[] = 'Added column pd_ip_enrichment.' . $column;
		}
	}

	$hitClassificationColumns = [
		'pixel_id' => 'ALTER TABLE pd_hit_classification ADD COLUMN pixel_id INT UNSIGNED NOT NULL AFTER hit_id',
		'pixel_key' => 'ALTER TABLE pd_hit_classification ADD COLUMN pixel_key VARCHAR(191) NOT NULL AFTER pixel_id',
		'ip_address' => 'ALTER TABLE pd_hit_classification ADD COLUMN ip_address VARCHAR(45) NOT NULL AFTER pixel_key',
		'email_client_guess' => 'ALTER TABLE pd_hit_classification ADD COLUMN email_client_guess VARCHAR(50) NOT NULL DEFAULT "unknown" AFTER ip_address',
		'email_client_confidence' => 'ALTER TABLE pd_hit_classification ADD COLUMN email_client_confidence DECIMAL(4,3) NOT NULL DEFAULT 0.000 AFTER email_client_guess',
		'traffic_type' => 'ALTER TABLE pd_hit_classification ADD COLUMN traffic_type VARCHAR(30) NOT NULL DEFAULT "unknown" AFTER email_client_confidence',
		'isp_guess' => 'ALTER TABLE pd_hit_classification ADD COLUMN isp_guess VARCHAR(255) NULL AFTER traffic_type',
		'isp_source' => 'ALTER TABLE pd_hit_classification ADD COLUMN isp_source VARCHAR(30) NOT NULL DEFAULT "unknown" AFTER isp_guess',
		'classified_at' => 'ALTER TABLE pd_hit_classification ADD COLUMN classified_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP AFTER isp_source',
	];

	foreach ($hitClassificationColumns as $column => $sql) {
		if (!column_exists($pdo, 'pd_hit_classification', $column)) {
			$pdo->exec($sql);
			$applied[] = 'Added column pd_hit_classification.' . $column;
		}
	}

	$queueColumns = [
		'first_seen_at' => 'ALTER TABLE pd_ip_enrichment_queue ADD COLUMN first_seen_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP AFTER ip_address',
		'last_seen_at' => 'ALTER TABLE pd_ip_enrichment_queue ADD COLUMN last_seen_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP AFTER first_seen_at',
		'next_attempt_at' => 'ALTER TABLE pd_ip_enrichment_queue ADD COLUMN next_attempt_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP AFTER last_seen_at',
		'attempt_count' => 'ALTER TABLE pd_ip_enrichment_queue ADD COLUMN attempt_count INT UNSIGNED NOT NULL DEFAULT 0 AFTER next_attempt_at',
		'last_error' => 'ALTER TABLE pd_ip_enrichment_queue ADD COLUMN last_error VARCHAR(255) NULL AFTER attempt_count',
		'processed_at' => 'ALTER TABLE pd_ip_enrichment_queue ADD COLUMN processed_at DATETIME NULL AFTER last_error',
		'created_at' => 'ALTER TABLE pd_ip_enrichment_queue ADD COLUMN created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP AFTER processed_at',
		'updated_at' => 'ALTER TABLE pd_ip_enrichment_queue ADD COLUMN updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP AFTER created_at',
	];

	foreach ($queueColumns as $column => $sql) {
		if (!column_exists($pdo, 'pd_ip_enrichment_queue', $column)) {
			$pdo->exec($sql);
			$applied[] = 'Added column pd_ip_enrichment_queue.' . $column;
		}
	}

	$indexes = [
		['table' => 'pd_pixels', 'name' => 'idx_pixel_key', 'sql' => 'CREATE INDEX idx_pixel_key ON pd_pixels (pixel_key)'],
		['table' => 'pd_pixel_hits', 'name' => 'idx_pixel_id', 'sql' => 'CREATE INDEX idx_pixel_id ON pd_pixel_hits (pixel_id)'],
		['table' => 'pd_pixel_hits', 'name' => 'idx_pixel_key', 'sql' => 'CREATE INDEX idx_pixel_key ON pd_pixel_hits (pixel_key)'],
		['table' => 'pd_pixel_hits', 'name' => 'idx_hit_at', 'sql' => 'CREATE INDEX idx_hit_at ON pd_pixel_hits (hit_at)'],
		['table' => 'pd_pixel_hits', 'name' => 'idx_pixel_time', 'sql' => 'CREATE INDEX idx_pixel_time ON pd_pixel_hits (pixel_id, hit_at)'],
		['table' => 'pd_pixel_hits', 'name' => 'idx_pixel_ip_time', 'sql' => 'CREATE INDEX idx_pixel_ip_time ON pd_pixel_hits (pixel_id, ip_address, hit_at)'],
		['table' => 'pd_pixel_hits', 'name' => 'idx_pixel_ref_time', 'sql' => 'CREATE INDEX idx_pixel_ref_time ON pd_pixel_hits (pixel_id, referrer(191), hit_at)'],
		['table' => 'pd_pixel_hits', 'name' => 'idx_pixel_host_time', 'sql' => 'CREATE INDEX idx_pixel_host_time ON pd_pixel_hits (pixel_id, remote_host(191), hit_at)'],
		['table' => 'pd_trigger_actions', 'name' => 'idx_trigger_id', 'sql' => 'CREATE INDEX idx_trigger_id ON pd_trigger_actions (trigger_id)'],
		['table' => 'pd_trigger_actions', 'name' => 'idx_is_active', 'sql' => 'CREATE INDEX idx_is_active ON pd_trigger_actions (is_active)'],
		['table' => 'pd_trigger_actions', 'name' => 'idx_is_default', 'sql' => 'CREATE INDEX idx_is_default ON pd_trigger_actions (is_default)'],
		['table' => 'pd_pixel_trigger_assignments', 'name' => 'idx_pixel_key', 'sql' => 'CREATE INDEX idx_pixel_key ON pd_pixel_trigger_assignments (pixel_key)'],
		['table' => 'pd_pixel_trigger_assignments', 'name' => 'idx_trigger_action_id', 'sql' => 'CREATE INDEX idx_trigger_action_id ON pd_pixel_trigger_assignments (trigger_action_id)'],
		['table' => 'pd_pixel_trigger_assignments', 'name' => 'uniq_pixel_trigger', 'sql' => 'CREATE UNIQUE INDEX uniq_pixel_trigger ON pd_pixel_trigger_assignments (pixel_key, trigger_action_id)'],
		['table' => 'pd_ip_enrichment', 'name' => 'idx_country', 'sql' => 'CREATE INDEX idx_country ON pd_ip_enrichment (country_code)'],
		['table' => 'pd_ip_enrichment', 'name' => 'idx_asn', 'sql' => 'CREATE INDEX idx_asn ON pd_ip_enrichment (asn)'],
		['table' => 'pd_ip_enrichment', 'name' => 'idx_isp', 'sql' => 'CREATE INDEX idx_isp ON pd_ip_enrichment (isp_name)'],
		['table' => 'pd_hit_classification', 'name' => 'idx_pixel_time', 'sql' => 'CREATE INDEX idx_pixel_time ON pd_hit_classification (pixel_id, classified_at)'],
		['table' => 'pd_hit_classification', 'name' => 'idx_pixel_ip', 'sql' => 'CREATE INDEX idx_pixel_ip ON pd_hit_classification (pixel_id, ip_address)'],
		['table' => 'pd_hit_classification', 'name' => 'idx_email_client', 'sql' => 'CREATE INDEX idx_email_client ON pd_hit_classification (email_client_guess)'],
		['table' => 'pd_hit_classification', 'name' => 'idx_traffic_type', 'sql' => 'CREATE INDEX idx_traffic_type ON pd_hit_classification (traffic_type)'],
		['table' => 'pd_ip_enrichment_queue', 'name' => 'idx_next_attempt', 'sql' => 'CREATE INDEX idx_next_attempt ON pd_ip_enrichment_queue (next_attempt_at)'],
		['table' => 'pd_ip_enrichment_queue', 'name' => 'idx_last_seen', 'sql' => 'CREATE INDEX idx_last_seen ON pd_ip_enrichment_queue (last_seen_at)'],
	];

	foreach ($indexes as $indexDef) {
		if (!index_exists($pdo, $indexDef['table'], $indexDef['name'])) {
			$pdo->exec($indexDef['sql']);
			$applied[] = 'Created index ' . $indexDef['table'] . '.' . $indexDef['name'];
		}
	}

	return $applied;
}

function analytics_table_status(): array
{
	static $status = null;

	if (is_array($status)) {
		return $status;
	}

	try {
		$pdo = db();
		$status = [
			'ip_enrichment' => table_exists($pdo, 'pd_ip_enrichment'),
			'hit_classification' => table_exists($pdo, 'pd_hit_classification'),
			'ip_queue' => table_exists($pdo, 'pd_ip_enrichment_queue'),
		];
	} catch (Throwable $e) {
		$status = [
			'ip_enrichment' => false,
			'hit_classification' => false,
			'ip_queue' => false,
		];
	}

	return $status;
}

function is_public_ip(string $ipAddress): bool
{
	return filter_var($ipAddress, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE) !== false;
}

function normalize_referrer_domain(?string $referrer): string
{
	if ($referrer === null) {
		return '-';
	}

	$referrer = trim($referrer);
	if ($referrer === '') {
		return '-';
	}

	$host = parse_url($referrer, PHP_URL_HOST);
	if (!is_string($host) || trim($host) === '') {
		$clean = strtolower($referrer);
		$clean = preg_replace('/^[a-z]+:\/\//i', '', $clean);
		$parts = explode('/', $clean, 2);
		$host = $parts[0] ?? '';
	}

	$host = strtolower(trim((string) $host));
	return $host !== '' ? $host : '-';
}

function infer_isp_from_remote_host(?string $remoteHost): ?string
{
	if ($remoteHost === null) {
		return null;
	}

	$remoteHost = trim(strtolower($remoteHost));
	if ($remoteHost === '') {
		return null;
	}

	if (preg_match('/^[0-9]+(\.[0-9]+){3}$/', $remoteHost) === 1) {
		return null;
	}

	if (strpos($remoteHost, 'google-proxy-') === 0 || str_ends_with($remoteHost, '.google.com')) {
		return 'Google';
	}

	if (strpos($remoteHost, '.ycpi.') !== false && str_ends_with($remoteHost, '.yahoo.com')) {
		return 'Yahoo';
	}

	$parts = explode('.', $remoteHost);
	if (count($parts) >= 2) {
		return $parts[count($parts) - 2] . '.' . $parts[count($parts) - 1];
	}

	return $remoteHost;
}

function infer_email_client(array $hit): array
{
	$userAgent = strtolower((string) ($hit['user_agent'] ?? ''));
	$referrer = strtolower((string) ($hit['referrer'] ?? ''));
	$remoteHost = strtolower((string) ($hit['remote_host'] ?? ''));

	if (
		strpos($userAgent, 'googleimageproxy') !== false ||
		strpos($remoteHost, 'google-proxy-') === 0 ||
		strpos($referrer, 'mobile-webview.gmail.com') !== false ||
		strpos($referrer, 'mail.google.com') !== false
	) {
		return ['client' => 'gmail', 'confidence' => 0.95];
	}

	if (
		strpos($userAgent, 'yahoomailproxy') !== false ||
		(strpos($remoteHost, '.ycpi.') !== false && str_ends_with($remoteHost, '.yahoo.com'))
	) {
		return ['client' => 'yahoo_mail', 'confidence' => 0.95];
	}

	if (
		strpos($referrer, 'outlook.live.com') !== false ||
		strpos($userAgent, 'oneoutlook/') !== false ||
		strpos($userAgent, 'ms-office') !== false
	) {
		return ['client' => 'outlook_family', 'confidence' => 0.9];
	}

	if (
		strpos($referrer, 'webmail.') !== false ||
		strpos($referrer, 'mail.') !== false ||
		strpos($referrer, 'neo.space') !== false ||
		strpos($referrer, 'titan.email') !== false
	) {
		return ['client' => 'other_webmail', 'confidence' => 0.7];
	}

	return ['client' => 'unknown', 'confidence' => 0.2];
}

function infer_traffic_type(array $hit, array $enrichment, string $emailClient): string
{
	$userAgent = strtolower((string) ($hit['user_agent'] ?? ''));

	if ($emailClient === 'gmail' || $emailClient === 'yahoo_mail') {
		return 'proxy';
	}

	if (strpos($userAgent, 'bot') !== false || strpos($userAgent, 'crawler') !== false || strpos($userAgent, 'spider') !== false) {
		return 'bot';
	}

	if ((int) ($enrichment['is_proxy'] ?? 0) === 1) {
		return 'proxy';
	}

	if (trim((string) ($hit['user_agent'] ?? '')) === '') {
		return 'unknown';
	}

	return 'human';
}

function lookup_ip_enrichment_remote(string $ipAddress): array
{
	$default = [
		'ip_address' => $ipAddress,
		'country_code' => null,
		'region' => null,
		'city' => null,
		'latitude' => null,
		'longitude' => null,
		'asn' => null,
		'asn_org' => null,
		'isp_name' => null,
		'is_proxy' => 0,
		'is_hosting' => 0,
		'source' => 'unresolved',
		'confidence' => 0.0,
	];

	if (!is_public_ip($ipAddress)) {
		$default['source'] = 'private_or_reserved';
		return $default;
	}

	$url = 'http://ip-api.com/json/' . rawurlencode($ipAddress) . '?fields=status,countryCode,regionName,city,lat,lon,as,isp,proxy,hosting,query';
	$response = false;

	if (function_exists('curl_init')) {
		$ch = curl_init($url);
		if ($ch !== false) {
			curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
			curl_setopt($ch, CURLOPT_CONNECTTIMEOUT, 2);
			curl_setopt($ch, CURLOPT_TIMEOUT, 3);
			$response = curl_exec($ch);
			curl_close($ch);
		}
	} else {
		$context = stream_context_create([
			'http' => [
				'timeout' => 3,
			],
		]);
		$response = @file_get_contents($url, false, $context);
	}

	if (!is_string($response) || trim($response) === '') {
		return $default;
	}

	$decoded = json_decode($response, true);
	if (!is_array($decoded) || ($decoded['status'] ?? '') !== 'success') {
		return $default;
	}

	$asnRaw = trim((string) ($decoded['as'] ?? ''));
	$asn = null;
	$asnOrg = null;
	if ($asnRaw !== '') {
		$parts = explode(' ', $asnRaw, 2);
		$asn = $parts[0] ?? null;
		$asnOrg = $parts[1] ?? null;
	}

	return [
		'ip_address' => $ipAddress,
		'country_code' => strtoupper(substr((string) ($decoded['countryCode'] ?? ''), 0, 2)) ?: null,
		'region' => trim((string) ($decoded['regionName'] ?? '')) ?: null,
		'city' => trim((string) ($decoded['city'] ?? '')) ?: null,
		'latitude' => isset($decoded['lat']) ? (float) $decoded['lat'] : null,
		'longitude' => isset($decoded['lon']) ? (float) $decoded['lon'] : null,
		'asn' => $asn,
		'asn_org' => $asnOrg,
		'isp_name' => trim((string) ($decoded['isp'] ?? '')) ?: null,
		'is_proxy' => !empty($decoded['proxy']) ? 1 : 0,
		'is_hosting' => !empty($decoded['hosting']) ? 1 : 0,
		'source' => 'ip-api.com',
		'confidence' => 0.7,
	];
}

function upsert_ip_enrichment(array $enrichment): void
{
	$status = analytics_table_status();
	if (!$status['ip_enrichment']) {
		return;
	}

	$stmt = db()->prepare(
		'INSERT INTO pd_ip_enrichment (
			ip_address, country_code, region, city, latitude, longitude, asn, asn_org, isp_name,
			is_proxy, is_hosting, source, confidence, updated_at
		) VALUES (
			:ip_address, :country_code, :region, :city, :latitude, :longitude, :asn, :asn_org, :isp_name,
			:is_proxy, :is_hosting, :source, :confidence, NOW()
		)
		ON DUPLICATE KEY UPDATE
			country_code = VALUES(country_code),
			region = VALUES(region),
			city = VALUES(city),
			latitude = VALUES(latitude),
			longitude = VALUES(longitude),
			asn = VALUES(asn),
			asn_org = VALUES(asn_org),
			isp_name = VALUES(isp_name),
			is_proxy = VALUES(is_proxy),
			is_hosting = VALUES(is_hosting),
			source = VALUES(source),
			confidence = VALUES(confidence),
			updated_at = NOW()'
	);

	$stmt->execute([
		'ip_address' => (string) ($enrichment['ip_address'] ?? ''),
		'country_code' => $enrichment['country_code'] ?? null,
		'region' => $enrichment['region'] ?? null,
		'city' => $enrichment['city'] ?? null,
		'latitude' => $enrichment['latitude'] ?? null,
		'longitude' => $enrichment['longitude'] ?? null,
		'asn' => $enrichment['asn'] ?? null,
		'asn_org' => $enrichment['asn_org'] ?? null,
		'isp_name' => $enrichment['isp_name'] ?? null,
		'is_proxy' => (int) ($enrichment['is_proxy'] ?? 0),
		'is_hosting' => (int) ($enrichment['is_hosting'] ?? 0),
		'source' => (string) ($enrichment['source'] ?? 'unresolved'),
		'confidence' => (float) ($enrichment['confidence'] ?? 0),
	]);
}

function ensure_ip_enrichment(string $ipAddress, bool $allowRemoteLookup = false): array
{
	$default = [
		'ip_address' => $ipAddress,
		'country_code' => null,
		'region' => null,
		'city' => null,
		'latitude' => null,
		'longitude' => null,
		'asn' => null,
		'asn_org' => null,
		'isp_name' => null,
		'is_proxy' => 0,
		'is_hosting' => 0,
		'source' => 'unresolved',
		'confidence' => 0.0,
	];

	$status = analytics_table_status();
	if (!$status['ip_enrichment']) {
		return $default;
	}

	try {
		$existingStmt = db()->prepare('SELECT * FROM pd_ip_enrichment WHERE ip_address = :ip_address LIMIT 1');
		$existingStmt->execute(['ip_address' => $ipAddress]);
		$existing = $existingStmt->fetch();
		if ($existing) {
			$existing['is_proxy'] = (int) ($existing['is_proxy'] ?? 0);
			$existing['is_hosting'] = (int) ($existing['is_hosting'] ?? 0);
			$existing['confidence'] = (float) ($existing['confidence'] ?? 0);
			return $existing;
		}
	} catch (Throwable $e) {
		return $default;
	}

	if (!$allowRemoteLookup) {
		return $default;
	}

	$enrichment = lookup_ip_enrichment_remote($ipAddress);

	try {
		upsert_ip_enrichment($enrichment);
	} catch (Throwable $e) {
	}

	return $enrichment;
}

function classify_and_store_hit(int $hitId, int $pixelId, string $pixelKey, array $hitData, bool $allowRemoteLookup = false): void
{
	$status = analytics_table_status();
	if (!$status['hit_classification']) {
		return;
	}

	$ipAddress = trim((string) ($hitData['ip_address'] ?? ''));
	$enrichment = $ipAddress !== '' ? ensure_ip_enrichment($ipAddress, $allowRemoteLookup) : [
		'is_proxy' => 0,
		'isp_name' => null,
	];

	$email = infer_email_client($hitData);
	$remoteHostIsp = infer_isp_from_remote_host((string) ($hitData['remote_host'] ?? ''));
	$asnIsp = trim((string) ($enrichment['asn_org'] ?? ''));
	$ispName = trim((string) ($enrichment['isp_name'] ?? ''));

	$ispGuess = null;
	$ispSource = 'unknown';
	if ($remoteHostIsp !== null && $remoteHostIsp !== '') {
		$ispGuess = $remoteHostIsp;
		$ispSource = 'remote_host';
	} elseif ($ispName !== '') {
		$ispGuess = $ispName;
		$ispSource = 'geo_isp';
	} elseif ($asnIsp !== '') {
		$ispGuess = $asnIsp;
		$ispSource = 'asn';
	}

	$trafficType = infer_traffic_type($hitData, $enrichment, (string) $email['client']);

	$stmt = db()->prepare(
		'INSERT INTO pd_hit_classification (
			hit_id, pixel_id, pixel_key, ip_address, email_client_guess, email_client_confidence,
			traffic_type, isp_guess, isp_source, classified_at
		) VALUES (
			:hit_id, :pixel_id, :pixel_key, :ip_address, :email_client_guess, :email_client_confidence,
			:traffic_type, :isp_guess, :isp_source, NOW()
		)
		ON DUPLICATE KEY UPDATE
			pixel_id = VALUES(pixel_id),
			pixel_key = VALUES(pixel_key),
			ip_address = VALUES(ip_address),
			email_client_guess = VALUES(email_client_guess),
			email_client_confidence = VALUES(email_client_confidence),
			traffic_type = VALUES(traffic_type),
			isp_guess = VALUES(isp_guess),
			isp_source = VALUES(isp_source),
			classified_at = NOW()'
	);

	$stmt->execute([
		'hit_id' => $hitId,
		'pixel_id' => $pixelId,
		'pixel_key' => $pixelKey,
		'ip_address' => $ipAddress,
		'email_client_guess' => (string) $email['client'],
		'email_client_confidence' => (float) $email['confidence'],
		'traffic_type' => $trafficType,
		'isp_guess' => $ispGuess,
		'isp_source' => $ispSource,
	]);
}

function backfill_hit_classification_for_pixel(int $pixelId, int $limit = 100, bool $allowRemoteLookup = false): int
{
	$status = analytics_table_status();
	if (!$status['hit_classification']) {
		return 0;
	}

	$limit = max(1, min(500, $limit));
	$stmt = db()->prepare(
		'SELECT h.id, h.pixel_id, h.pixel_key, h.ip_address, h.user_agent, h.referrer, h.request_uri, h.accept_language, h.remote_host
		 FROM pd_pixel_hits h
		 LEFT JOIN pd_hit_classification c ON c.hit_id = h.id
		 WHERE h.pixel_id = :pixel_id AND c.hit_id IS NULL
		 ORDER BY h.id DESC
		 LIMIT :limit'
	);
	$stmt->bindValue(':pixel_id', $pixelId, PDO::PARAM_INT);
	$stmt->bindValue(':limit', $limit, PDO::PARAM_INT);
	$stmt->execute();

	$rows = $stmt->fetchAll();
	foreach ($rows as $row) {
		try {
			classify_and_store_hit(
				(int) $row['id'],
				(int) $row['pixel_id'],
				(string) $row['pixel_key'],
				[
					'ip_address' => (string) ($row['ip_address'] ?? ''),
					'user_agent' => (string) ($row['user_agent'] ?? ''),
					'referrer' => (string) ($row['referrer'] ?? ''),
					'request_uri' => (string) ($row['request_uri'] ?? ''),
					'accept_language' => (string) ($row['accept_language'] ?? ''),
					'remote_host' => (string) ($row['remote_host'] ?? ''),
				],
				$allowRemoteLookup
			);
		} catch (Throwable $e) {
		}
	}

	return count($rows);
}

function can_spawn_background_process(): bool
{
	if (!function_exists('exec')) {
		return false;
	}

	$disabled = (string) ini_get('disable_functions');
	if ($disabled !== '') {
		$parts = array_map('trim', explode(',', $disabled));
		if (in_array('exec', $parts, true)) {
			return false;
		}
	}

	return true;
}

function enqueue_ip_for_enrichment(string $ipAddress): void
{
	$ipAddress = trim($ipAddress);
	if ($ipAddress === '' || strlen($ipAddress) > 45) {
		return;
	}

	$status = analytics_table_status();
	if (!$status['ip_queue']) {
		return;
	}

	$stmt = db()->prepare(
		'INSERT INTO pd_ip_enrichment_queue (
			ip_address, first_seen_at, last_seen_at, next_attempt_at, attempt_count, last_error, processed_at, created_at, updated_at
		) VALUES (
			:ip_address, NOW(), NOW(), NOW(), 0, NULL, NULL, NOW(), NOW()
		)
		ON DUPLICATE KEY UPDATE
			last_seen_at = NOW(),
			updated_at = NOW(),
			next_attempt_at = IF(next_attempt_at > NOW(), NOW(), next_attempt_at)'
	);

	$stmt->execute(['ip_address' => $ipAddress]);
}

function try_start_ip_enrichment_worker(int $minSpawnIntervalSeconds = 30): bool
{
	if (!can_spawn_background_process()) {
		return false;
	}

	$status = analytics_table_status();
	if (!$status['ip_queue']) {
		return false;
	}

	$lockFile = sys_get_temp_dir() . '/pixeldust_ip_worker_last_spawn.lock';
	$now = time();
	$lastSpawn = @file_exists($lockFile) ? (int) @filemtime($lockFile) : 0;
	if ($lastSpawn > 0 && ($now - $lastSpawn) < max(1, $minSpawnIntervalSeconds)) {
		return false;
	}

	$workerScript = dirname(__DIR__) . '/workers/ip_enrichment_worker.php';
	if (!is_file($workerScript)) {
		return false;
	}

	@touch($lockFile);

	$phpBinary = PHP_BINARY;
	if (!is_string($phpBinary) || trim($phpBinary) === '') {
		$phpBinary = 'php';
	}

	$cmd = escapeshellarg($phpBinary) . ' ' . escapeshellarg($workerScript) . ' >/dev/null 2>&1 &';
	@exec($cmd);

	return true;
}

function process_ip_enrichment_queue(int $maxRows = 100, int $maxRuntimeSeconds = 8): array
{
	$status = analytics_table_status();
	if (!$status['ip_queue'] || !$status['ip_enrichment']) {
		return ['processed' => 0, 'succeeded' => 0, 'failed' => 0, 'locked' => false];
	}

	$maxRows = max(1, min(1000, $maxRows));
	$maxRuntimeSeconds = max(1, min(60, $maxRuntimeSeconds));
	$startedAt = microtime(true);

	$lockStmt = db()->prepare('SELECT GET_LOCK(:lock_name, 0) AS got_lock');
	$lockStmt->execute(['lock_name' => 'pixeldust_ip_enrichment_worker']);
	$gotLock = (int) ($lockStmt->fetch()['got_lock'] ?? 0) === 1;
	if (!$gotLock) {
		return ['processed' => 0, 'succeeded' => 0, 'failed' => 0, 'locked' => true];
	}

	$processed = 0;
	$succeeded = 0;
	$failed = 0;

	try {
		$selectStmt = db()->prepare(
			'SELECT ip_address, attempt_count
			 FROM pd_ip_enrichment_queue
			 WHERE next_attempt_at <= NOW()
			 ORDER BY last_seen_at DESC
			 LIMIT :limit'
		);

		$deleteStmt = db()->prepare('DELETE FROM pd_ip_enrichment_queue WHERE ip_address = :ip_address');
		$failStmt = db()->prepare(
			'UPDATE pd_ip_enrichment_queue
			 SET attempt_count = :attempt_count,
			     next_attempt_at = DATE_ADD(NOW(), INTERVAL :retry_seconds SECOND),
			     last_error = :last_error,
			     updated_at = NOW()
			 WHERE ip_address = :ip_address'
		);

		while ($processed < $maxRows && (microtime(true) - $startedAt) < $maxRuntimeSeconds) {
			$remaining = $maxRows - $processed;
			$selectStmt->bindValue(':limit', min(50, $remaining), PDO::PARAM_INT);
			$selectStmt->execute();
			$batch = $selectStmt->fetchAll();
			if (!$batch) {
				break;
			}

			foreach ($batch as $row) {
				if ($processed >= $maxRows || (microtime(true) - $startedAt) >= $maxRuntimeSeconds) {
					break;
				}

				$processed++;
				$ipAddress = trim((string) ($row['ip_address'] ?? ''));
				$attempt = (int) ($row['attempt_count'] ?? 0) + 1;

				if ($ipAddress === '') {
					$failed++;
					continue;
				}

				try {
					$enrichment = ensure_ip_enrichment($ipAddress, true);
					$source = (string) ($enrichment['source'] ?? 'unresolved');

					if ($source !== 'unresolved') {
						$deleteStmt->execute(['ip_address' => $ipAddress]);
						$succeeded++;
						continue;
					}
				} catch (Throwable $e) {
				}

				$failed++;
				$retrySeconds = min(3600, (int) pow(2, min($attempt, 10)));
				$failStmt->bindValue(':attempt_count', $attempt, PDO::PARAM_INT);
				$failStmt->bindValue(':retry_seconds', $retrySeconds, PDO::PARAM_INT);
				$failStmt->bindValue(':last_error', 'lookup_failed', PDO::PARAM_STR);
				$failStmt->bindValue(':ip_address', $ipAddress, PDO::PARAM_STR);
				$failStmt->execute();
			}
		}
	} finally {
		$releaseStmt = db()->prepare('SELECT RELEASE_LOCK(:lock_name)');
		$releaseStmt->execute(['lock_name' => 'pixeldust_ip_enrichment_worker']);
	}

	return [
		'processed' => $processed,
		'succeeded' => $succeeded,
		'failed' => $failed,
		'locked' => false,
	];
}

function normalize_trigger_id(string $triggerId): string
{
	return trim($triggerId);
}

function get_active_triggers_for_pixel(?string $explicitTriggerId = null): array
{
	if ($explicitTriggerId === null || $explicitTriggerId === '') {
		return [];
	}

	$explicitStmt = db()->prepare(
		'SELECT id, trigger_id, name, webhook_url, payload_template
		 FROM pd_trigger_actions
		 WHERE trigger_id = :trigger_id AND is_active = 1
		 LIMIT 1'
	);
	$explicitStmt->execute(['trigger_id' => $explicitTriggerId]);
	$explicitAction = $explicitStmt->fetch();

	if (!$explicitAction) {
		return [];
	}

	return [$explicitAction];
}

function render_trigger_payload_template(?string $template, array $context): array
{
	if ($template === null || trim($template) === '') {
		return $context;
	}

	$rendered = $template;
	foreach ($context as $key => $value) {
		$rendered = str_replace('{{' . $key . '}}', (string) $value, $rendered);
	}

	$decoded = json_decode($rendered, true);
	if (is_array($decoded)) {
		return $decoded;
	}

	return [
		'message' => $rendered,
		'context' => $context,
	];
}

function send_webhook_json(string $url, array $payload): bool
{
	try {
		if (trim($url) === '' || !filter_var($url, FILTER_VALIDATE_URL)) {
			return false;
		}

		$body = json_encode($payload, JSON_UNESCAPED_SLASHES);
		if (!is_string($body)) {
			return false;
		}

		if (function_exists('curl_init')) {
			$ch = curl_init($url);
			if ($ch === false) {
				return false;
			}

			curl_setopt($ch, CURLOPT_POST, true);
			curl_setopt($ch, CURLOPT_POSTFIELDS, $body);
			curl_setopt($ch, CURLOPT_HTTPHEADER, [
				'Content-Type: application/json',
				'Content-Length: ' . strlen($body),
			]);
			curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
			curl_setopt($ch, CURLOPT_CONNECTTIMEOUT, 1);
			curl_setopt($ch, CURLOPT_TIMEOUT, 2);
			curl_exec($ch);
			$httpCode = (int) curl_getinfo($ch, CURLINFO_HTTP_CODE);
			curl_close($ch);

			return $httpCode >= 200 && $httpCode < 300;
		}

		$context = stream_context_create([
			'http' => [
				'method' => 'POST',
				'header' => "Content-Type: application/json\r\nContent-Length: " . strlen($body) . "\r\n",
				'content' => $body,
				'timeout' => 2,
				'ignore_errors' => true,
			],
		]);

		$result = @file_get_contents($url, false, $context);
		return $result !== false;
	} catch (Throwable $e) {
		return false;
	}
}

function fire_pixel_triggers(string $pixelKey, int $pixelId, int $hitId, array $hitData, ?string $explicitTriggerId = null): void
{
	try {
		$triggerId = $explicitTriggerId !== null ? normalize_trigger_id($explicitTriggerId) : null;
		$actions = get_active_triggers_for_pixel($triggerId);
		if (!$actions) {
			return;
		}

		$totalHitsStmt = db()->prepare('SELECT total_hits FROM pd_pixels WHERE id = :id LIMIT 1');
		$totalHitsStmt->execute(['id' => $pixelId]);
		$totalHits = (int) ($totalHitsStmt->fetch()['total_hits'] ?? 0);

		$context = [
			'event' => 'pixel_loaded',
			'pixel_id' => $pixelKey,
			'pixel_db_id' => $pixelId,
			'hit_id' => $hitId,
			'hits' => $totalHits,
			'trigger_id' => $triggerId ?? '',
			'hit_at' => (string) ($hitData['hit_at'] ?? date('Y-m-d H:i:s')),
			'ip_address' => (string) ($hitData['ip_address'] ?? ''),
			'user_agent' => (string) ($hitData['user_agent'] ?? ''),
			'referrer' => (string) ($hitData['referrer'] ?? ''),
			'request_uri' => (string) ($hitData['request_uri'] ?? ''),
			'query_string' => (string) ($hitData['query_string'] ?? ''),
			'accept_language' => (string) ($hitData['accept_language'] ?? ''),
			'remote_host' => (string) ($hitData['remote_host'] ?? ''),
		];

		foreach ($actions as $action) {
			try {
				$payload = render_trigger_payload_template((string) ($action['payload_template'] ?? ''), $context);
				$payload['_trigger'] = [
					'id' => (string) $action['trigger_id'],
					'name' => (string) $action['name'],
				];
				send_webhook_json((string) $action['webhook_url'], $payload);
			} catch (Throwable $e) {
			}
		}
	} catch (Throwable $e) {
	}
}

function render_header(string $title): void
{
	$appName = app_config()['app']['name'] ?? 'Pixel Dust';
	echo '<!doctype html><html lang="en"><head><meta charset="utf-8">';
	echo '<meta name="viewport" content="width=device-width, initial-scale=1">';
	echo '<title>' . e($title) . ' - ' . e($appName) . '</title>';
	echo '<style>
		body{font-family:Arial,sans-serif;background:#f7f7f7;margin:0;padding:0;color:#1e1e1e}
		.container{max-width:1040px;margin:24px auto;padding:0 16px}
		.card{background:#fff;border:1px solid #ddd;border-radius:8px;padding:16px;margin-bottom:16px}
		h1,h2,h3{margin:0 0 12px}
		p{margin:0 0 10px}
		table{width:100%;border-collapse:collapse}
		th,td{padding:8px;border:1px solid #ddd;text-align:left;vertical-align:top}
		th{background:#f2f2f2}
		.muted{color:#666;font-size:0.9rem}
		.error{background:#ffeaea;color:#7f1d1d;padding:10px;border-radius:6px;margin-bottom:12px}
		.success{background:#e9f8ea;color:#14532d;padding:10px;border-radius:6px;margin-bottom:12px}
		input,select{padding:8px;border:1px solid #bbb;border-radius:4px;width:100%;box-sizing:border-box}
		button{padding:8px 12px;border:0;border-radius:4px;background:#1f4ea5;color:#fff;cursor:pointer}
		a{color:#1f4ea5;text-decoration:none}
		.nav-btn{display:inline-block;padding:8px 12px;border:1px solid #1f4ea5;border-radius:4px;background:#f0f5ff;color:#1f4ea5;font-size:0.92rem;line-height:1.2}
		.nav-btn:hover{background:#e3edff}
		.nav-btn.logout{border-color:#8b1e1e;background:#fff1f1;color:#8b1e1e}
		.nav-btn.logout:hover{background:#ffe6e6}
		.row{display:grid;grid-template-columns:repeat(auto-fit,minmax(240px,1fr));gap:12px}
		.inline{display:flex;gap:8px;align-items:center;flex-wrap:wrap}
		.spaced{display:flex;justify-content:space-between;gap:12px;align-items:center;flex-wrap:wrap}
	</style>';
	echo '</head><body><div class="container">';
}

function render_footer(): void
{
	echo '</div></body></html>';
}
