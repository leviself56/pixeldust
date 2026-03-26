<?php

declare(strict_types=1);

require __DIR__ . '/../_libraries/core.php';

if (PHP_SAPI !== 'cli') {
	http_response_code(403);
	echo "CLI only\n";
	exit(1);
}

$maxRows = isset($argv[1]) ? (int) $argv[1] : 120;
$maxRuntimeSeconds = isset($argv[2]) ? (int) $argv[2] : 8;

try {
	$result = process_ip_enrichment_queue($maxRows, $maxRuntimeSeconds);
	echo json_encode($result, JSON_UNESCAPED_SLASHES) . PHP_EOL;
	exit(0);
} catch (Throwable $e) {
	echo json_encode([
		'processed' => 0,
		'succeeded' => 0,
		'failed' => 0,
		'locked' => false,
		'error' => $e->getMessage(),
	], JSON_UNESCAPED_SLASHES) . PHP_EOL;
	exit(1);
}
