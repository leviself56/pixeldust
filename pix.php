<?php

declare(strict_types=1);

require __DIR__ . '/_libraries/core.php';

if (!is_installed()) {
	http_response_code(503);
	header('Content-Type: text/plain; charset=utf-8');
	echo 'Pixel Dust not installed.';
	exit;
}

$pixelKey = trim((string) ($_GET['id'] ?? 'default'));
if ($pixelKey === '') {
	$pixelKey = 'default';
}

$explicitTriggerId = trim((string) ($_GET['trigger'] ?? ''));
if ($explicitTriggerId === '') {
	$explicitTriggerId = trim((string) ($_GET['trigger_id'] ?? ''));
}

$pixelId = create_pixel_if_missing($pixelKey);

$ipAddress = substr((string) ($_SERVER['REMOTE_ADDR'] ?? ''), 0, 45);
$userAgent = (string) ($_SERVER['HTTP_USER_AGENT'] ?? '');
$referrer = (string) ($_SERVER['HTTP_REFERER'] ?? '');
$requestUri = (string) ($_SERVER['REQUEST_URI'] ?? '');
$queryString = (string) ($_SERVER['QUERY_STRING'] ?? '');
$acceptLanguage = substr((string) ($_SERVER['HTTP_ACCEPT_LANGUAGE'] ?? ''), 0, 255);
$remoteHost = substr((string) @gethostbyaddr($ipAddress), 0, 255);

$insertHit = db()->prepare(
	'INSERT INTO pd_pixel_hits (
		pixel_id, pixel_key, hit_at, ip_address, user_agent, referrer, request_uri, query_string, accept_language, remote_host
	 ) VALUES (
		:pixel_id, :pixel_key, NOW(), :ip_address, :user_agent, :referrer, :request_uri, :query_string, :accept_language, :remote_host
	 )'
);

$insertHit->execute([
	'pixel_id' => $pixelId,
	'pixel_key' => $pixelKey,
	'ip_address' => $ipAddress,
	'user_agent' => $userAgent,
	'referrer' => $referrer,
	'request_uri' => $requestUri,
	'query_string' => $queryString,
	'accept_language' => $acceptLanguage,
	'remote_host' => $remoteHost,
]);

$hitId = (int) db()->lastInsertId();

$hitAtStmt = db()->prepare('SELECT hit_at FROM pd_pixel_hits WHERE id = :id LIMIT 1');
$hitAtStmt->execute(['id' => $hitId]);
$hitAt = (string) ($hitAtStmt->fetch()['hit_at'] ?? date('Y-m-d H:i:s'));

$update = db()->prepare('UPDATE pd_pixels SET total_hits = total_hits + 1, updated_at = NOW() WHERE id = :id');
$update->execute(['id' => $pixelId]);

try {
	fire_pixel_triggers($pixelKey, $pixelId, $hitId, [
		'hit_at' => $hitAt,
		'ip_address' => $ipAddress,
		'user_agent' => $userAgent,
		'referrer' => $referrer,
		'request_uri' => $requestUri,
		'query_string' => $queryString,
		'accept_language' => $acceptLanguage,
		'remote_host' => $remoteHost,
	], $explicitTriggerId !== '' ? $explicitTriggerId : null);
} catch (Throwable $e) {
}

header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
header('Pragma: no-cache');
header('Expires: 0');
header('Content-Type: image/gif');

echo base64_decode('R0lGODlhAQABAIAAAAAAAP///ywAAAAAAQABAAACAUwAOw==');
