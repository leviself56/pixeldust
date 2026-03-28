<?php

declare(strict_types=1);

require __DIR__ . '/../_libraries/core.php';

require_admin();

$type = trim((string) ($_GET['type'] ?? ''));
$value = trim((string) ($_GET['value'] ?? ''));
$period = (string) ($_GET['period'] ?? '7d');
$adKey = sanitize_ad_key((string) ($_GET['ad_key'] ?? ''));
$validPeriods = ['24h', '7d', '30d', 'all'];
if (!in_array($period, $validPeriods, true)) {
	$period = '7d';
}

if ($period === 'all') {
	$cutoffUtc = '1970-01-01 00:00:00';
} else {
	$periodIntervalSpec = $period === '24h' ? 'PT24H' : ($period === '30d' ? 'P30D' : 'P7D');
	$cutoffUtc = (new DateTimeImmutable('now', new DateTimeZone('UTC')))
		->sub(new DateInterval($periodIntervalSpec))
		->format('Y-m-d H:i:s');
}

if ($type === 'ip') {
	$ipAddress = $value;
	if ($ipAddress === '' || strlen($ipAddress) > 45 || filter_var($ipAddress, FILTER_VALIDATE_IP) === false) {
		flash('error', 'Invalid IP selected for link-out.');
		redirect('ad-analytics.php?period=' . urlencode($period));
	}

	$bestSource = null;

	if ($adKey !== '') {
		try {
			$adSpecificStmt = db()->prepare(
				'SELECT ad_key AS source_key, COUNT(*) AS hits
				 FROM pd_ad_hit_logs
				 WHERE ip_address = :ip_address AND ad_key = :ad_key AND hit_at >= :cutoff_utc
				 GROUP BY ad_key
				 LIMIT 1'
			);
			$adSpecificStmt->execute([
				'ip_address' => $ipAddress,
				'ad_key' => $adKey,
				'cutoff_utc' => $cutoffUtc,
			]);
			$adSpecificRow = $adSpecificStmt->fetch();
			if ($adSpecificRow) {
				$bestSource = [
					'source_type' => 'ad',
					'source_key' => (string) ($adSpecificRow['source_key'] ?? ''),
					'hits' => (int) ($adSpecificRow['hits'] ?? 0),
				];
			}
		} catch (Throwable $e) {
		}
	}

	if (!$bestSource) {
		try {
			$adStmt = db()->prepare(
				'SELECT ad_key AS source_key, COUNT(*) AS hits
				 FROM pd_ad_hit_logs
				 WHERE ip_address = :ip_address AND hit_at >= :cutoff_utc
				 GROUP BY ad_key
				 ORDER BY hits DESC, source_key ASC
				 LIMIT 1'
			);
			$adStmt->execute([
				'ip_address' => $ipAddress,
				'cutoff_utc' => $cutoffUtc,
			]);
			$adRow = $adStmt->fetch();
			if ($adRow) {
				$bestSource = [
					'source_type' => 'ad',
					'source_key' => (string) ($adRow['source_key'] ?? ''),
					'hits' => (int) ($adRow['hits'] ?? 0),
				];
			}
		} catch (Throwable $e) {
		}
	}

	try {
		$pixelStmt = db()->prepare(
			'SELECT pixel_key AS source_key, COUNT(*) AS hits
			 FROM pd_pixel_hits
			 WHERE ip_address = :ip_address AND hit_at >= :cutoff_utc
			 GROUP BY pixel_key
			 ORDER BY hits DESC, source_key ASC
			 LIMIT 1'
		);
		$pixelStmt->execute([
			'ip_address' => $ipAddress,
			'cutoff_utc' => $cutoffUtc,
		]);
		$pixelRow = $pixelStmt->fetch();
		if ($pixelRow) {
			$pixelHits = (int) ($pixelRow['hits'] ?? 0);
			if (!$bestSource || $pixelHits > (int) ($bestSource['hits'] ?? 0)) {
				$bestSource = [
					'source_type' => 'pixel',
					'source_key' => (string) ($pixelRow['source_key'] ?? ''),
					'hits' => $pixelHits,
				];
			}
		}
	} catch (Throwable $e) {
	}

	try {
		$redirectStmt = db()->prepare(
			'SELECT redirect_key AS source_key, COUNT(*) AS hits
			 FROM pd_redirect_hits
			 WHERE ip_address = :ip_address AND hit_at >= :cutoff_utc
			 GROUP BY redirect_key
			 ORDER BY hits DESC, source_key ASC
			 LIMIT 1'
		);
		$redirectStmt->execute([
			'ip_address' => $ipAddress,
			'cutoff_utc' => $cutoffUtc,
		]);
		$redirectRow = $redirectStmt->fetch();
		if ($redirectRow) {
			$redirectHits = (int) ($redirectRow['hits'] ?? 0);
			if (!$bestSource || $redirectHits > (int) ($bestSource['hits'] ?? 0)) {
				$bestSource = [
					'source_type' => 'redirect',
					'source_key' => (string) ($redirectRow['source_key'] ?? ''),
					'hits' => $redirectHits,
				];
			}
		}
	} catch (Throwable $e) {
	}

	if (!$bestSource || trim((string) ($bestSource['source_key'] ?? '')) === '') {
		flash('error', 'No matching ad/pixel/redirect history found for that IP in selected period.');
		redirect('ad-analytics.php?period=' . urlencode($period));
	}

	$query = [
		'source_type' => (string) $bestSource['source_type'],
		'period' => $period,
		'ip' => $ipAddress,
	];
	if ((string) $bestSource['source_type'] === 'redirect') {
		$query['redirect_key'] = (string) $bestSource['source_key'];
	} elseif ((string) $bestSource['source_type'] === 'ad') {
		$query['ad_key'] = (string) $bestSource['source_key'];
	} else {
		$query['pixel_key'] = (string) $bestSource['source_key'];
	}

	redirect('ip-details.php?' . http_build_query($query));
}

if ($type === 'provider') {
	$provider = $value;
	if ($provider === '' || strlen($provider) > 255) {
		flash('error', 'Invalid provider selected for link-out.');
		redirect('ad-analytics.php?period=' . urlencode($period));
	}

	$bestSource = null;

	try {
		$pixelStmt = db()->prepare(
			'SELECT pixel_key AS source_key, COUNT(*) AS hits
			 FROM pd_hit_classification
			 WHERE isp_guess = :provider AND classified_at >= :cutoff_utc
			 GROUP BY pixel_key
			 ORDER BY hits DESC, source_key ASC
			 LIMIT 1'
		);
		$pixelStmt->execute([
			'provider' => $provider,
			'cutoff_utc' => $cutoffUtc,
		]);
		$pixelRow = $pixelStmt->fetch();
		if ($pixelRow) {
			$bestSource = [
				'source_type' => 'pixel',
				'source_key' => (string) ($pixelRow['source_key'] ?? ''),
				'hits' => (int) ($pixelRow['hits'] ?? 0),
			];
		}
	} catch (Throwable $e) {
	}

	try {
		$redirectStmt = db()->prepare(
			'SELECT redirect_key AS source_key, COUNT(*) AS hits
			 FROM pd_redirect_hit_classification
			 WHERE isp_guess = :provider AND classified_at >= :cutoff_utc
			 GROUP BY redirect_key
			 ORDER BY hits DESC, source_key ASC
			 LIMIT 1'
		);
		$redirectStmt->execute([
			'provider' => $provider,
			'cutoff_utc' => $cutoffUtc,
		]);
		$redirectRow = $redirectStmt->fetch();
		if ($redirectRow) {
			$redirectHits = (int) ($redirectRow['hits'] ?? 0);
			if (!$bestSource || $redirectHits > (int) ($bestSource['hits'] ?? 0)) {
				$bestSource = [
					'source_type' => 'redirect',
					'source_key' => (string) ($redirectRow['source_key'] ?? ''),
					'hits' => $redirectHits,
				];
			}
		}
	} catch (Throwable $e) {
	}

	if (!$bestSource || trim((string) ($bestSource['source_key'] ?? '')) === '') {
		flash('error', 'No matching analytics source found for that provider in selected period.');
		redirect('ad-analytics.php?period=' . urlencode($period));
	}

	$query = [
		'source_type' => (string) $bestSource['source_type'],
		'period' => $period,
		'provider' => $provider,
		'provider_page' => 1,
	];
	if ((string) $bestSource['source_type'] === 'redirect') {
		$query['redirect_key'] = (string) $bestSource['source_key'];
	} else {
		$query['pixel_key'] = (string) $bestSource['source_key'];
	}

	redirect('analytics.php?' . http_build_query($query));
}

flash('error', 'Unknown link-out target.');
redirect('ad-analytics.php?period=' . urlencode($period));
