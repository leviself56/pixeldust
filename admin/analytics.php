<?php

declare(strict_types=1);

require __DIR__ . '/../_libraries/core.php';

if (!is_installed()) {
	redirect('../install.php');
}

$token = trim((string) ($_GET['token'] ?? ''));
if ($token !== '' && !current_admin()) {
	$decoded = base64_decode($token, true);
	if ($decoded !== false && strpos($decoded, ':') !== false) {
		[$username, $password] = explode(':', $decoded, 2);
		$username = trim((string) $username);
		$password = (string) $password;

		if ($username !== '' && $password !== '') {
			$stmt = db()->prepare('SELECT id, password_hash FROM pd_admin_users WHERE username = :username LIMIT 1');
			$stmt->execute(['username' => $username]);
			$adminByToken = $stmt->fetch();

			if ($adminByToken && password_verify($password, (string) $adminByToken['password_hash'])) {
				$_SESSION['admin_user_id'] = (int) $adminByToken['id'];
			}
		}
	}
}

require_admin();

function render_simple_svg_chart(array $rows, string $valueKey = 'hits'): string
{
	if (!$rows) {
		return '<p class="muted">No data in selected period.</p>';
	}

	$width = 900;
	$height = 280;
	$padding = 36;
	$usableWidth = $width - ($padding * 2);
	$usableHeight = $height - ($padding * 2);

	$values = array_map(static fn($row): int => (int) ($row[$valueKey] ?? 0), $rows);
	$maxValue = max($values);
	if ($maxValue < 1) {
		$maxValue = 1;
	}

	$countRows = count($rows);
	$points = [];
	$labels = [];

	foreach ($rows as $index => $row) {
		$x = $padding + (($countRows <= 1 ? 0 : $index / ($countRows - 1)) * $usableWidth);
		$y = $height - $padding - (((int) ($row[$valueKey] ?? 0) / $maxValue) * $usableHeight);
		$points[] = round($x, 2) . ',' . round($y, 2);
		$labels[] = [
			'x' => $x,
			'y' => $height - ($padding - 14),
			'text' => substr((string) ($row['bucket'] ?? ''), 5),
		];
	}

	$svg = '<svg viewBox="0 0 ' . $width . ' ' . $height . '" width="100%" height="280" role="img">';
	$svg .= '<line x1="' . $padding . '" y1="' . ($height - $padding) . '" x2="' . ($width - $padding) . '" y2="' . ($height - $padding) . '" stroke="#ccc" />';
	$svg .= '<line x1="' . $padding . '" y1="' . $padding . '" x2="' . $padding . '" y2="' . ($height - $padding) . '" stroke="#ccc" />';
	$svg .= '<polyline fill="none" stroke="#1f4ea5" stroke-width="2" points="' . implode(' ', $points) . '" />';

	foreach ($points as $point) {
		[$cx, $cy] = explode(',', $point);
		$svg .= '<circle cx="' . $cx . '" cy="' . $cy . '" r="3" fill="#1f4ea5" />';
	}

	foreach ($labels as $label) {
		$svg .= '<text x="' . round((float) $label['x'], 2) . '" y="' . round((float) $label['y'], 2) . '" text-anchor="middle" font-size="10" fill="#666">' . e((string) $label['text']) . '</text>';
	}

	$svg .= '<text x="' . ($padding + 4) . '" y="' . ($padding + 10) . '" font-size="10" fill="#666">Max: ' . $maxValue . '</text>';
	$svg .= '</svg>';

	return $svg;
}

$pixelKey = trim((string) ($_GET['pixel_key'] ?? ''));
$pixelId = (int) ($_GET['pixel_id'] ?? 0);
$period = (string) ($_GET['period'] ?? '7d');
$validPeriods = ['24h', '7d', '30d'];
if (!in_array($period, $validPeriods, true)) {
	$period = '7d';
}

$periodIntervalSpec = $period === '24h' ? 'PT24H' : ($period === '30d' ? 'P30D' : 'P7D');
$cutoffUtc = (new DateTimeImmutable('now', new DateTimeZone('UTC')))
	->sub(new DateInterval($periodIntervalSpec))
	->format('Y-m-d H:i:s');

$pixels = db()->query('SELECT id, pixel_key, total_hits FROM pd_pixels ORDER BY pixel_key ASC')->fetchAll();
$selectedPixel = null;

if ($pixelId > 0) {
	$stmt = db()->prepare('SELECT id, pixel_key, total_hits, created_at FROM pd_pixels WHERE id = :id LIMIT 1');
	$stmt->execute(['id' => $pixelId]);
	$selectedPixel = $stmt->fetch();
	if ($selectedPixel) {
		$pixelKey = (string) $selectedPixel['pixel_key'];
	}
} elseif ($pixelKey !== '') {
	$stmt = db()->prepare('SELECT id, pixel_key, total_hits, created_at FROM pd_pixels WHERE pixel_key = :pixel_key LIMIT 1');
	$stmt->execute(['pixel_key' => $pixelKey]);
	$selectedPixel = $stmt->fetch();
	if ($selectedPixel) {
		$pixelId = (int) $selectedPixel['id'];
	}
}

$tableStatus = analytics_table_status();
$summary = [
	'total_hits' => 0,
	'unique_ips' => 0,
	'unique_referrers' => 0,
	'proxy_hits' => 0,
	'human_hits' => 0,
];
$topReferrers = [];
$topIsps = [];
$topCountries = [];
$clientMix = [];
$timelineRows = [];
$topIps = [];

if ($selectedPixel) {
	if ($tableStatus['hit_classification']) {
		try {
			backfill_hit_classification_for_pixel((int) $selectedPixel['id'], 80, true);
		} catch (Throwable $e) {
		}
	}

	$referrerDomainExpr = "CASE WHEN h.referrer IS NULL OR TRIM(h.referrer)='' THEN '-' ELSE LOWER(SUBSTRING_INDEX(SUBSTRING_INDEX(TRIM(h.referrer),'://',-1),'/',1)) END";
	$emailCaseExpr = "CASE WHEN h.user_agent LIKE '%GoogleImageProxy%' OR h.remote_host LIKE 'google-proxy-%' OR h.referrer LIKE '%mobile-webview.gmail.com%' OR h.referrer LIKE '%mail.google.com%' THEN 'gmail' WHEN h.user_agent LIKE 'YahooMailProxy%' OR h.remote_host LIKE 'ec%.ycpi.%yahoo.com' THEN 'yahoo_mail' WHEN h.referrer LIKE '%outlook.live.com%' OR h.user_agent LIKE '%OneOutlook/%' OR h.user_agent LIKE '%ms-office%' THEN 'outlook_family' WHEN h.referrer LIKE '%webmail.%' OR h.referrer LIKE '%mail.%' OR h.referrer LIKE '%neo.space%' OR h.referrer LIKE '%titan.email%' THEN 'other_webmail' ELSE 'unknown' END";
	$ispFallbackExpr = "CASE WHEN h.remote_host IS NULL OR TRIM(h.remote_host)='' THEN 'unknown' WHEN h.remote_host REGEXP '^[0-9]+(\\\\.[0-9]+){3}$' THEN 'ip_unresolved' WHEN h.remote_host LIKE 'google-proxy-%' OR h.remote_host LIKE '%.google.com' THEN 'Google' WHEN h.remote_host LIKE '%.yahoo.com' AND h.remote_host LIKE '%.ycpi.%' THEN 'Yahoo' ELSE LOWER(SUBSTRING_INDEX(TRIM(h.remote_host),'.',-2)) END";

	$joinClassification = $tableStatus['hit_classification'] ? ' LEFT JOIN pd_hit_classification c ON c.hit_id = h.id ' : '';
	$joinEnrichment = $tableStatus['ip_enrichment'] ? ' LEFT JOIN pd_ip_enrichment e ON e.ip_address = h.ip_address ' : '';
	$clientExpr = $tableStatus['hit_classification'] ? "COALESCE(NULLIF(c.email_client_guess,''), $emailCaseExpr)" : $emailCaseExpr;
	$trafficExpr = $tableStatus['hit_classification'] ? "COALESCE(NULLIF(c.traffic_type,''), 'unknown')" : "CASE WHEN $clientExpr IN ('gmail','yahoo_mail') THEN 'proxy' ELSE 'unknown' END";
	$ispExpr = $tableStatus['hit_classification'] && $tableStatus['ip_enrichment']
		? "COALESCE(NULLIF(c.isp_guess,''), NULLIF(e.isp_name,''), $ispFallbackExpr)"
		: ($tableStatus['hit_classification']
			? "COALESCE(NULLIF(c.isp_guess,''), $ispFallbackExpr)"
			: ($tableStatus['ip_enrichment'] ? "COALESCE(NULLIF(e.isp_name,''), $ispFallbackExpr)" : $ispFallbackExpr));

	$summarySql =
		"SELECT
			COUNT(*) AS total_hits,
			COUNT(DISTINCT h.ip_address) AS unique_ips,
			COUNT(DISTINCT $referrerDomainExpr) AS unique_referrers,
			SUM(CASE WHEN $trafficExpr = 'proxy' THEN 1 ELSE 0 END) AS proxy_hits,
			SUM(CASE WHEN $trafficExpr = 'human' THEN 1 ELSE 0 END) AS human_hits
		 FROM pd_pixel_hits h
		 $joinClassification
		 $joinEnrichment
		 WHERE h.pixel_id = :pixel_id AND h.hit_at >= :cutoff_utc";
	$summaryStmt = db()->prepare($summarySql);
	$summaryStmt->execute([
		'pixel_id' => (int) $selectedPixel['id'],
		'cutoff_utc' => $cutoffUtc,
	]);
	$summary = array_merge($summary, (array) $summaryStmt->fetch());

	$refSql =
		"SELECT $referrerDomainExpr AS ref_domain, COUNT(*) AS hits
		 FROM pd_pixel_hits h
		 WHERE h.pixel_id = :pixel_id AND h.hit_at >= :cutoff_utc
		 GROUP BY ref_domain
		 ORDER BY hits DESC
		 LIMIT 10";
	$refStmt = db()->prepare($refSql);
	$refStmt->execute([
		'pixel_id' => (int) $selectedPixel['id'],
		'cutoff_utc' => $cutoffUtc,
	]);
	$topReferrers = $refStmt->fetchAll();

	$ispSql =
		"SELECT $ispExpr AS isp, COUNT(*) AS hits, COUNT(DISTINCT h.ip_address) AS unique_ips
		 FROM pd_pixel_hits h
		 $joinClassification
		 $joinEnrichment
		 WHERE h.pixel_id = :pixel_id AND h.hit_at >= :cutoff_utc
		 GROUP BY isp
		 ORDER BY hits DESC
		 LIMIT 10";
	$ispStmt = db()->prepare($ispSql);
	$ispStmt->execute([
		'pixel_id' => (int) $selectedPixel['id'],
		'cutoff_utc' => $cutoffUtc,
	]);
	$topIsps = $ispStmt->fetchAll();

	if ($tableStatus['ip_enrichment']) {
		$geoSql =
			"SELECT COALESCE(NULLIF(e.country_code, ''), '??') AS country, COUNT(*) AS hits, COUNT(DISTINCT h.ip_address) AS unique_ips
			 FROM pd_pixel_hits h
			 LEFT JOIN pd_ip_enrichment e ON e.ip_address = h.ip_address
			 WHERE h.pixel_id = :pixel_id AND h.hit_at >= :cutoff_utc
			 GROUP BY country
			 ORDER BY hits DESC
			 LIMIT 10";
		$geoStmt = db()->prepare($geoSql);
		$geoStmt->execute([
			'pixel_id' => (int) $selectedPixel['id'],
			'cutoff_utc' => $cutoffUtc,
		]);
		$topCountries = $geoStmt->fetchAll();
	}

	$clientSql =
		"SELECT $clientExpr AS client_name, COUNT(*) AS hits
		 FROM pd_pixel_hits h
		 $joinClassification
		 WHERE h.pixel_id = :pixel_id AND h.hit_at >= :cutoff_utc
		 GROUP BY client_name
		 ORDER BY hits DESC";
	$clientStmt = db()->prepare($clientSql);
	$clientStmt->execute([
		'pixel_id' => (int) $selectedPixel['id'],
		'cutoff_utc' => $cutoffUtc,
	]);
	$clientMix = $clientStmt->fetchAll();

	if ($period === '24h') {
		$timelineSql =
			"SELECT DATE_FORMAT(h.hit_at, '%Y-%m-%d %H:00:00') AS bucket, COUNT(*) AS hits
			 FROM pd_pixel_hits h
			 WHERE h.pixel_id = :pixel_id AND h.hit_at >= :cutoff_utc
			 GROUP BY bucket
			 ORDER BY bucket ASC";
	} else {
		$timelineSql =
			"SELECT DATE(h.hit_at) AS bucket, COUNT(*) AS hits
			 FROM pd_pixel_hits h
			 WHERE h.pixel_id = :pixel_id AND h.hit_at >= :cutoff_utc
			 GROUP BY bucket
			 ORDER BY bucket ASC";
	}
	$timelineStmt = db()->prepare($timelineSql);
	$timelineStmt->execute([
		'pixel_id' => (int) $selectedPixel['id'],
		'cutoff_utc' => $cutoffUtc,
	]);
	$timelineRows = $timelineStmt->fetchAll();

	$ipSql =
		"SELECT h.ip_address, COUNT(*) AS hits
		 FROM pd_pixel_hits h
		 WHERE h.pixel_id = :pixel_id AND h.hit_at >= :cutoff_utc
		 GROUP BY h.ip_address
		 ORDER BY hits DESC
		 LIMIT 15";
	$ipStmt = db()->prepare($ipSql);
	$ipStmt->execute([
		'pixel_id' => (int) $selectedPixel['id'],
		'cutoff_utc' => $cutoffUtc,
	]);
	$topIps = $ipStmt->fetchAll();
}

render_header('Analytics');
?>
<div class="spaced card">
	<div>
		<h1>Pixel Analytics</h1>
		<p class="muted">Advanced analytics by pixel over selected time window.</p>
	</div>
	<div class="inline">
		<a class="nav-btn" href="index.php">Back to dashboard</a>
		<a class="nav-btn" href="stats.php<?php echo $pixelKey !== '' ? '?pixel_key=' . urlencode($pixelKey) . '&period=' . urlencode($period) : ''; ?>">Open stats</a>
		<a class="nav-btn logout" href="../logout.php">Logout</a>
	</div>
</div>

<div class="card">
	<form method="get" class="row">
		<div>
			<label>Pixel ID</label>
			<select name="pixel_key">
				<option value="">Select pixel</option>
				<?php foreach ($pixels as $pixel): ?>
					<option value="<?php echo e((string) $pixel['pixel_key']); ?>" <?php echo $pixelKey === (string) $pixel['pixel_key'] ? 'selected' : ''; ?>>
						<?php echo e((string) $pixel['pixel_key']); ?> (<?php echo e((string) $pixel['total_hits']); ?>)
					</option>
				<?php endforeach; ?>
			</select>
		</div>
		<div>
			<label>Period</label>
			<select name="period">
				<?php foreach ($validPeriods as $opt): ?>
					<option value="<?php echo e($opt); ?>" <?php echo $period === $opt ? 'selected' : ''; ?>><?php echo e($opt); ?></option>
				<?php endforeach; ?>
			</select>
		</div>
		<div style="align-self:end;"><button type="submit">Load Analytics</button></div>
	</form>
</div>

<?php if (!$tableStatus['hit_classification'] || !$tableStatus['ip_enrichment']): ?>
	<div class="error">Analytics enrichment tables are missing. Run <a href="../migrate.php">migrations</a> for full analytics data.</div>
<?php endif; ?>

<?php if ($pixelKey !== '' && !$selectedPixel): ?>
	<div class="error">Pixel not found.</div>
<?php endif; ?>

<?php if ($selectedPixel): ?>
	<div class="row">
		<div class="card"><h3>Total Hits</h3><p style="font-size:1.5rem;font-weight:bold;"><?php echo e((string) ((int) ($summary['total_hits'] ?? 0))); ?></p></div>
		<div class="card"><h3>Unique IPs</h3><p style="font-size:1.5rem;font-weight:bold;"><?php echo e((string) ((int) ($summary['unique_ips'] ?? 0))); ?></p></div>
		<div class="card"><h3>Unique Referrers</h3><p style="font-size:1.5rem;font-weight:bold;"><?php echo e((string) ((int) ($summary['unique_referrers'] ?? 0))); ?></p></div>
		<div class="card"><h3>Proxy Hits</h3><p style="font-size:1.5rem;font-weight:bold;"><?php echo e((string) ((int) ($summary['proxy_hits'] ?? 0))); ?></p></div>
	</div>

	<div class="card">
		<h2>Hit Timeline (<?php echo e($period); ?>)</h2>
		<p class="muted">Timezone shown in UTC for analytics consistency.</p>
		<?php echo render_simple_svg_chart($timelineRows, 'hits'); ?>
	</div>

	<div class="row">
		<div class="card">
			<h3>Top 10 Referrers</h3>
			<table>
				<thead><tr><th>Referrer Domain</th><th>Hits</th></tr></thead>
				<tbody>
				<?php if (!$topReferrers): ?>
					<tr><td colspan="2" class="muted">No data.</td></tr>
				<?php else: ?>
					<?php foreach ($topReferrers as $row): ?>
						<tr>
							<td><?php echo e((string) ($row['ref_domain'] ?? '-')); ?></td>
							<td><?php echo e((string) ($row['hits'] ?? 0)); ?></td>
						</tr>
					<?php endforeach; ?>
				<?php endif; ?>
				</tbody>
			</table>
		</div>

		<div class="card">
			<h3>Top 10 ISPs / Providers</h3>
			<table>
				<thead><tr><th>Provider</th><th>Hits</th><th>Unique IPs</th></tr></thead>
				<tbody>
				<?php if (!$topIsps): ?>
					<tr><td colspan="3" class="muted">No data.</td></tr>
				<?php else: ?>
					<?php foreach ($topIsps as $row): ?>
						<tr>
							<td><?php echo e((string) ($row['isp'] ?? 'unknown')); ?></td>
							<td><?php echo e((string) ($row['hits'] ?? 0)); ?></td>
							<td><?php echo e((string) ($row['unique_ips'] ?? 0)); ?></td>
						</tr>
					<?php endforeach; ?>
				<?php endif; ?>
				</tbody>
			</table>
		</div>
	</div>

	<div class="row">
		<div class="card">
			<h3>Email Client Mix</h3>
			<table>
				<thead><tr><th>Client</th><th>Hits</th></tr></thead>
				<tbody>
				<?php if (!$clientMix): ?>
					<tr><td colspan="2" class="muted">No data.</td></tr>
				<?php else: ?>
					<?php foreach ($clientMix as $row): ?>
						<tr>
							<td><?php echo e((string) ($row['client_name'] ?? 'unknown')); ?></td>
							<td><?php echo e((string) ($row['hits'] ?? 0)); ?></td>
						</tr>
					<?php endforeach; ?>
				<?php endif; ?>
				</tbody>
			</table>
		</div>

		<div class="card">
			<h3>Top Countries</h3>
			<table>
				<thead><tr><th>Country</th><th>Hits</th><th>Unique IPs</th></tr></thead>
				<tbody>
				<?php if (!$topCountries): ?>
					<tr><td colspan="3" class="muted">No geo data yet.</td></tr>
				<?php else: ?>
					<?php foreach ($topCountries as $row): ?>
						<tr>
							<td><?php echo e((string) ($row['country'] ?? '??')); ?></td>
							<td><?php echo e((string) ($row['hits'] ?? 0)); ?></td>
							<td><?php echo e((string) ($row['unique_ips'] ?? 0)); ?></td>
						</tr>
					<?php endforeach; ?>
				<?php endif; ?>
				</tbody>
			</table>
		</div>
	</div>

	<div class="card">
		<h3>Top IPs (click to drill down)</h3>
		<table>
			<thead><tr><th>IP Address</th><th>Hits</th></tr></thead>
			<tbody>
			<?php if (!$topIps): ?>
				<tr><td colspan="2" class="muted">No data.</td></tr>
			<?php else: ?>
				<?php foreach ($topIps as $row): ?>
					<tr>
						<td><a href="ip-details.php?pixel_key=<?php echo urlencode((string) $selectedPixel['pixel_key']); ?>&ip=<?php echo urlencode((string) ($row['ip_address'] ?? '')); ?>&period=<?php echo urlencode($period); ?>"><?php echo e((string) ($row['ip_address'] ?? '')); ?></a></td>
						<td><?php echo e((string) ($row['hits'] ?? 0)); ?></td>
					</tr>
				<?php endforeach; ?>
			<?php endif; ?>
			</tbody>
		</table>
	</div>
<?php endif; ?>
<?php
render_footer();
