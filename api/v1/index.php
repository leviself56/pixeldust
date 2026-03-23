<?php

declare(strict_types=1);

require __DIR__ . '/../../_libraries/core.php';

header('Content-Type: application/json; charset=utf-8');

function api_json_response(array $payload, int $status = 200): void
{
	http_response_code($status);
	echo json_encode($payload, JSON_UNESCAPED_SLASHES);
	exit;
}

function api_get_basic_auth_credentials(): array
{
	$user = null;
	$pass = null;

	if (isset($_SERVER['PHP_AUTH_USER'], $_SERVER['PHP_AUTH_PW'])) {
		$user = (string) $_SERVER['PHP_AUTH_USER'];
		$pass = (string) $_SERVER['PHP_AUTH_PW'];
		return [$user, $pass];
	}

	$authHeader = '';
	if (isset($_SERVER['HTTP_AUTHORIZATION'])) {
		$authHeader = (string) $_SERVER['HTTP_AUTHORIZATION'];
	} elseif (isset($_SERVER['REDIRECT_HTTP_AUTHORIZATION'])) {
		$authHeader = (string) $_SERVER['REDIRECT_HTTP_AUTHORIZATION'];
	}

	if ($authHeader !== '' && stripos($authHeader, 'Basic ') === 0) {
		$encoded = trim(substr($authHeader, 6));
		$decoded = base64_decode($encoded, true);
		if ($decoded !== false && strpos($decoded, ':') !== false) {
			[$user, $pass] = explode(':', $decoded, 2);
			return [(string) $user, (string) $pass];
		}
	}

	return [null, null];
}

if (!is_installed()) {
	api_json_response([
		'ok' => false,
		'error' => 'Pixel Dust is not installed.',
	], 503);
}

[$apiUser, $apiPass] = api_get_basic_auth_credentials();

if ($apiUser === null || $apiPass === null) {
	header('WWW-Authenticate: Basic realm="Pixel Dust API"');
	api_json_response([
		'ok' => false,
		'error' => 'Authentication required.',
	], 401);
}

$authStmt = db()->prepare('SELECT id, username, password_hash FROM pd_admin_users WHERE username = :username LIMIT 1');
$authStmt->execute(['username' => $apiUser]);
$admin = $authStmt->fetch();

if (!$admin || !password_verify($apiPass, (string) $admin['password_hash'])) {
	header('WWW-Authenticate: Basic realm="Pixel Dust API"');
	api_json_response([
		'ok' => false,
		'error' => 'Invalid username or password.',
	], 401);
}

$pixelKey = trim((string) ($_GET['id'] ?? ''));
if ($pixelKey === '') {
	api_json_response([
		'ok' => false,
		'error' => 'Missing required query parameter: id',
	], 400);
}

$page = (int) ($_GET['page'] ?? 1);
if ($page < 1) {
	$page = 1;
}

$perPage = (int) ($_GET['per_page'] ?? 25);
if ($perPage < 1) {
	$perPage = 25;
}
if ($perPage > 250) {
	$perPage = 250;
}

$pixelStmt = db()->prepare('SELECT id, pixel_key, total_hits, created_at, updated_at FROM pd_pixels WHERE pixel_key = :pixel_key LIMIT 1');
$pixelStmt->execute(['pixel_key' => $pixelKey]);
$pixel = $pixelStmt->fetch();

if (!$pixel) {
	api_json_response([
		'ok' => false,
		'error' => 'Pixel not found.',
		'pixel_id' => $pixelKey,
	], 404);
}

$totalHits = (int) $pixel['total_hits'];
$totalRecords = $totalHits;
$totalPages = max(1, (int) ceil($totalRecords / $perPage));
if ($page > $totalPages) {
	$page = $totalPages;
}
$offset = ($page - 1) * $perPage;

$hitsStmt = db()->prepare(
	'SELECT id, hit_at, ip_address, user_agent, referrer, request_uri, query_string, accept_language, remote_host
	 FROM pd_pixel_hits
	 WHERE pixel_id = :pixel_id
	 ORDER BY hit_at DESC, id DESC
	 LIMIT :offset, :limit'
);
$hitsStmt->bindValue(':pixel_id', (int) $pixel['id'], PDO::PARAM_INT);
$hitsStmt->bindValue(':offset', $offset, PDO::PARAM_INT);
$hitsStmt->bindValue(':limit', $perPage, PDO::PARAM_INT);
$hitsStmt->execute();
$records = $hitsStmt->fetchAll();

api_json_response([
	'ok' => true,
	'pixel' => [
		'id' => (string) $pixel['pixel_key'],
		'hits' => $totalHits,
		'created_at' => (string) $pixel['created_at'],
		'updated_at' => (string) $pixel['updated_at'],
	],
	'pagination' => [
		'page' => $page,
		'per_page' => $perPage,
		'total_records' => $totalRecords,
		'total_pages' => $totalPages,
	],
	'records' => $records,
]);
