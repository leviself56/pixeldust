<?php

declare(strict_types=1);

require __DIR__ . '/../_libraries/core.php';

require_admin();

$error = flash('error');
$success = flash('success');

$period = (string) ($_GET['period'] ?? '7d');
$adKeyFilter = sanitize_ad_key((string) ($_GET['ad_key'] ?? ''));
$providerFilter = trim((string) ($_GET['provider'] ?? ''));
$matchFilter = trim((string) ($_GET['match'] ?? 'all'));
$sort = trim((string) ($_GET['sort'] ?? 'latest'));
$heatmapMetric = trim((string) ($_GET['heatmap_metric'] ?? 'estimated_visits'));
$page = max(1, (int) ($_GET['page'] ?? 1));
$perPage = 25;

$validPeriods = ['24h', '7d', '30d', 'all'];
if (!in_array($period, $validPeriods, true)) {
	$period = '7d';
}
if (!in_array($matchFilter, ['all', 'matched', 'unmatched'], true)) {
	$matchFilter = 'all';
}
if (!in_array($sort, ['latest', 'matched_first', 'unmatched_first'], true)) {
	$sort = 'latest';
}
$validHeatmapMetrics = ['hits', 'estimated_visits'];
if (!in_array($heatmapMetric, $validHeatmapMetrics, true)) {
	$heatmapMetric = 'estimated_visits';
}
$displayTimezoneName = app_timezone_name();
$displayTimezone = app_timezone_object();
$appTimezoneOffsetMinutes = (int) floor((new DateTimeImmutable('now', $displayTimezone))->getOffset() / 60);
$formatStoredLocalTime = static function (?string $value) use ($displayTimezone): string {
	$raw = trim((string) $value);
	if ($raw === '') {
		return '-';
	}

	$dateTimeLocal = DateTimeImmutable::createFromFormat('Y-m-d H:i:s', $raw, $displayTimezone);
	if ($dateTimeLocal instanceof DateTimeImmutable) {
		return $dateTimeLocal->format('Y-m-d H:i:s');
	}

	try {
		return (new DateTimeImmutable($raw, $displayTimezone))->format('Y-m-d H:i:s');
	} catch (Throwable $e) {
		return '-';
	}
};

$schemaReady = false;
$schemaMissing = [];
$hasAdRulesTable = false;
$hasAdEntryColumns = false;
try {
	$pdo = db();
	$hasAdRulesTable = table_exists($pdo, 'pd_ad_rules');
	if (!table_exists($pdo, 'pd_ad_hit_logs')) {
		$schemaMissing[] = 'table pd_ad_hit_logs';
	} else {
		$requiredColumns = ['ad_key', 'hit_at', 'ip_address', 'isp_name', 'matched', 'matched_rule_name', 'matched_action_type'];
		foreach ($requiredColumns as $column) {
			if (!column_exists($pdo, 'pd_ad_hit_logs', $column)) {
				$schemaMissing[] = 'column pd_ad_hit_logs.' . $column;
			}
		}
		$hasAdEntryColumns = column_exists($pdo, 'pd_ad_hit_logs', 'entry_url') && column_exists($pdo, 'pd_ad_hit_logs', 'entry_referrer');
	}
	$schemaReady = count($schemaMissing) === 0;
} catch (Throwable $e) {
	$schemaMissing[] = 'database connection';
}

if ($period === 'all') {
	$cutoffUtc = '1970-01-01 00:00:00';
} else {
	$periodIntervalSpec = $period === '24h' ? 'PT24H' : ($period === '30d' ? 'P30D' : 'P7D');
	$cutoffUtc = (new DateTimeImmutable('now', new DateTimeZone('UTC')))
		->sub(new DateInterval($periodIntervalSpec))
		->format('Y-m-d H:i:s');
}

$adKeys = [];
$summary = [
	'total_hits' => 0,
	'matched_hits' => 0,
	'unmatched_hits' => 0,
	'unique_ips' => 0,
];
$topProviders = [];
$topIps = [];
$recentRows = [];
$ipTagMap = [];
$totalRows = 0;
$totalPages = 1;
$heatmapRows = [];
$heatmapGrid = [];
$heatmapMaxHits = 0;
$heatmapMode = 'date_hour';
$heatmapRowOrder = [];
$heatmapRowLabels = [];
$providerExprBase = "COALESCE(NULLIF(TRIM(isp_name), ''), NULLIF(TRIM((SELECT pe.isp_name FROM pd_ip_enrichment pe WHERE pe.ip_address = pd_ad_hit_logs.ip_address LIMIT 1)), ''), 'unknown')";
$providerExprRecent = "COALESCE(NULLIF(TRIM(l.isp_name), ''), NULLIF(TRIM((SELECT pe.isp_name FROM pd_ip_enrichment pe WHERE pe.ip_address = l.ip_address LIMIT 1)), ''), 'unknown')";
$providerExprHeatmap = "COALESCE(NULLIF(TRIM(h.isp_name), ''), NULLIF(TRIM((SELECT pe.isp_name FROM pd_ip_enrichment pe WHERE pe.ip_address = h.ip_address LIMIT 1)), ''), 'unknown')";

if ($schemaReady) {
	try {
		if ($hasAdRulesTable) {
			$adKeys = db()->query(
				'SELECT DISTINCT ad_key
				 FROM pd_ad_rules
				 WHERE ad_key IS NOT NULL AND TRIM(ad_key) <> ""
				 ORDER BY ad_key ASC'
			)->fetchAll();
		} else {
			$adKeys = db()->query(
				'SELECT DISTINCT ad_key
				 FROM pd_ad_hit_logs
				 WHERE ad_key IS NOT NULL AND TRIM(ad_key) <> ""
				 ORDER BY ad_key ASC'
			)->fetchAll();
		}
	} catch (Throwable $e) {
		$adKeys = [];
	}

	$where = ['hit_at >= :cutoff_utc'];
	$whereRecent = ['l.hit_at >= :cutoff_utc'];
	$whereHeatmap = ['h.hit_at >= :cutoff_utc'];
	$params = ['cutoff_utc' => $cutoffUtc];

	if ($adKeyFilter !== '') {
		$where[] = 'ad_key = :ad_key';
		$whereRecent[] = 'l.ad_key = :ad_key';
		$whereHeatmap[] = 'h.ad_key = :ad_key';
		$params['ad_key'] = $adKeyFilter;
	}
	if ($providerFilter !== '') {
		$where[] = "$providerExprBase = :provider";
		$whereRecent[] = "$providerExprRecent = :provider";
		$whereHeatmap[] = "$providerExprHeatmap = :provider";
		$params['provider'] = $providerFilter;
	}
	if ($matchFilter === 'matched') {
		$where[] = 'matched = 1';
		$whereRecent[] = 'l.matched = 1';
		$whereHeatmap[] = 'h.matched = 1';
	} elseif ($matchFilter === 'unmatched') {
		$where[] = 'matched = 0';
		$whereRecent[] = 'l.matched = 0';
		$whereHeatmap[] = 'h.matched = 0';
	}

	$whereSql = implode(' AND ', $where);
	$whereRecentSql = implode(' AND ', $whereRecent);
	$whereHeatmapSql = implode(' AND ', $whereHeatmap);

	$summaryStmt = db()->prepare(
		"SELECT
			COUNT(*) AS total_hits,
			SUM(CASE WHEN matched = 1 THEN 1 ELSE 0 END) AS matched_hits,
			SUM(CASE WHEN matched = 0 THEN 1 ELSE 0 END) AS unmatched_hits,
			COUNT(DISTINCT ip_address) AS unique_ips
		 FROM pd_ad_hit_logs
		 WHERE $whereSql"
	);
	$summaryStmt->execute($params);
	$summary = array_merge($summary, (array) $summaryStmt->fetch());

	$topProvidersStmt = db()->prepare(
		"SELECT $providerExprBase AS provider_name, COUNT(*) AS hits
		 FROM pd_ad_hit_logs
		 WHERE $whereSql
		 GROUP BY provider_name
		 ORDER BY hits DESC, provider_name ASC
		 LIMIT 20"
	);
	$topProvidersStmt->execute($params);
	$topProviders = $topProvidersStmt->fetchAll();

	if ($providerFilter === '' && $topProviders) {
		$unknownIndex = null;
		foreach ($topProviders as $idx => $providerRow) {
			if (strcasecmp((string) ($providerRow['provider_name'] ?? ''), 'unknown') === 0) {
				$unknownIndex = $idx;
				break;
			}
		}

		if ($unknownIndex !== null) {
			$unknownWhere = ['l.hit_at >= :cutoff_utc'];
			$unknownWhereAlias2 = ['l2.hit_at >= :cutoff_utc'];
			$unknownParams = ['cutoff_utc' => $cutoffUtc];

			if ($adKeyFilter !== '') {
				$unknownWhere[] = 'l.ad_key = :ad_key';
				$unknownWhereAlias2[] = 'l2.ad_key = :ad_key';
				$unknownParams['ad_key'] = $adKeyFilter;
			}
			if ($matchFilter === 'matched') {
				$unknownWhere[] = 'l.matched = 1';
				$unknownWhereAlias2[] = 'l2.matched = 1';
			} elseif ($matchFilter === 'unmatched') {
				$unknownWhere[] = 'l.matched = 0';
				$unknownWhereAlias2[] = 'l2.matched = 0';
			}

			$unknownWhereSql = implode(' AND ', $unknownWhere);
			$unknownWhereAlias2Sql = implode(' AND ', $unknownWhereAlias2);

			$strictUnknownStmt = db()->prepare(
				"SELECT
					l.ip_address,
					SUM(CASE WHEN COALESCE(NULLIF(TRIM(l.isp_name), ''), 'unknown') = 'unknown' THEN 1 ELSE 0 END) AS unknown_hits
				 FROM pd_ad_hit_logs l
				 LEFT JOIN pd_ip_enrichment pe ON pe.ip_address = l.ip_address
				 WHERE $unknownWhereSql
				 GROUP BY l.ip_address
				 HAVING SUM(CASE WHEN COALESCE(NULLIF(TRIM(l.isp_name), ''), 'unknown') = 'unknown' THEN 1 ELSE 0 END) > 0
				    AND SUM(CASE WHEN COALESCE(NULLIF(TRIM(l.isp_name), ''), 'unknown') <> 'unknown' THEN 1 ELSE 0 END) = 0
				    AND MAX(CASE WHEN pe.isp_name IS NOT NULL AND TRIM(pe.isp_name) <> '' THEN 1 ELSE 0 END) = 0
				    AND NOT EXISTS (
						SELECT 1
						FROM pd_ad_hit_logs l2
						WHERE l2.ip_address = l.ip_address
						  AND $unknownWhereAlias2Sql
						  AND COALESCE(NULLIF(TRIM(l2.isp_name), ''), 'unknown') <> 'unknown'
					)"
			);
			$strictUnknownStmt->execute($unknownParams);
			$strictUnknownRows = $strictUnknownStmt->fetchAll();

			$strictUnknownHits = 0;
			foreach ($strictUnknownRows as $strictUnknownRow) {
				$strictUnknownHits += (int) ($strictUnknownRow['unknown_hits'] ?? 0);
			}

			if ($strictUnknownHits > 0) {
				$topProviders[$unknownIndex]['hits'] = $strictUnknownHits;
			} else {
				unset($topProviders[$unknownIndex]);
				$topProviders = array_values($topProviders);
			}
		}
	}

	$topIpsStmt = db()->prepare(
		"SELECT ip_address, COUNT(*) AS hits,
			SUM(CASE WHEN matched = 1 THEN 1 ELSE 0 END) AS matched_hits,
			MAX(hit_at) AS last_seen
		 FROM pd_ad_hit_logs
		 WHERE $whereSql
		 GROUP BY ip_address
		 ORDER BY hits DESC, ip_address ASC
		 LIMIT 30"
	);
	$topIpsStmt->execute($params);
	$topIps = $topIpsStmt->fetchAll();

	$totalStmt = db()->prepare("SELECT COUNT(*) AS total FROM pd_ad_hit_logs WHERE $whereSql");
	$totalStmt->execute($params);
	$totalRows = (int) (($totalStmt->fetch()['total'] ?? 0));
	$totalPages = max(1, (int) ceil($totalRows / $perPage));
	if ($page > $totalPages) {
		$page = $totalPages;
	}
	$offset = ($page - 1) * $perPage;

	$orderBy = 'hit_at DESC, id DESC';
	$recentOrderBy = 'l.hit_at DESC, l.id DESC';
	if ($sort === 'matched_first') {
		$orderBy = 'matched DESC, hit_at DESC, id DESC';
		$recentOrderBy = 'l.matched DESC, l.hit_at DESC, l.id DESC';
	} elseif ($sort === 'unmatched_first') {
		$orderBy = 'matched ASC, hit_at DESC, id DESC';
		$recentOrderBy = 'l.matched ASC, l.hit_at DESC, l.id DESC';
	}

	$recentSql =
		"SELECT l.id, l.hit_at, l.ad_key, l.ip_address, l.traffic_type, l.country_code, $providerExprRecent AS provider_name, l.matched, l.matched_action_type, "
		. ($hasAdEntryColumns ? 'l.entry_url, l.entry_referrer, ' : 'NULL AS entry_url, NULL AS entry_referrer, ')
		. ($hasAdRulesTable ? 'r.priority AS matched_priority' : 'NULL AS matched_priority')
		. " FROM pd_ad_hit_logs l "
		. ($hasAdRulesTable ? 'LEFT JOIN pd_ad_rules r ON r.id = l.matched_rule_id ' : '')
		. "WHERE $whereRecentSql ORDER BY $recentOrderBy LIMIT :offset, :limit";

	$recentStmt = db()->prepare($recentSql);
	foreach ($params as $key => $value) {
		$recentStmt->bindValue(':' . $key, $value, PDO::PARAM_STR);
	}
	$recentStmt->bindValue(':offset', $offset, PDO::PARAM_INT);
	$recentStmt->bindValue(':limit', $perPage, PDO::PARAM_INT);
	$recentStmt->execute();
	$recentRows = $recentStmt->fetchAll();

	$ipsForTagLookup = [];
	foreach ($topIps as $topIpRow) {
		$ipValue = trim((string) ($topIpRow['ip_address'] ?? ''));
		if ($ipValue !== '') {
			$ipsForTagLookup[] = $ipValue;
		}
	}
	foreach ($recentRows as $recentRow) {
		$ipValue = trim((string) ($recentRow['ip_address'] ?? ''));
		if ($ipValue !== '') {
			$ipsForTagLookup[] = $ipValue;
		}
	}
	$ipTagMap = fetch_ip_operator_tags($ipsForTagLookup);

	if ($period !== 'all') {
		$heatmapMode = 'date_hour';
		$cutoffLocalDay = (new DateTimeImmutable($cutoffUtc, new DateTimeZone('UTC')))
			->setTimezone($displayTimezone)
			->setTime(0, 0, 0);
		$todayLocalDay = (new DateTimeImmutable('now', $displayTimezone))->setTime(0, 0, 0);
		for ($cursor = $cutoffLocalDay; $cursor <= $todayLocalDay; $cursor = $cursor->add(new DateInterval('P1D'))) {
			$key = $cursor->format('Y-m-d');
			$heatmapRowOrder[] = $key;
			$heatmapRowLabels[$key] = $key;
		}

		$localHitExpr = "IFNULL(CONVERT_TZ(h.hit_at, '+00:00', :tz_name), DATE_ADD(h.hit_at, INTERVAL :tz_offset_minute MINUTE))";
		if ($heatmapMetric === 'estimated_visits') {
			$heatmapFingerprintExpr = "CONCAT(COALESCE(h.ip_address, ''), '|', MD5(CONCAT(COALESCE(h.user_agent, ''), '|', COALESCE(h.accept_language, ''))))";
			$heatmapSql =
				"WITH ordered_hits AS (
					SELECT
						$localHitExpr AS local_hit_at,
						h.hit_at,
						LAG(h.hit_at) OVER (PARTITION BY $heatmapFingerprintExpr ORDER BY h.hit_at) AS prev_hit
					FROM pd_ad_hit_logs h
					WHERE $whereHeatmapSql
				)
				SELECT DATE(local_hit_at) AS day_bucket, HOUR(local_hit_at) AS hour_idx,
					COALESCE(SUM(CASE WHEN prev_hit IS NULL OR TIMESTAMPDIFF(MINUTE, prev_hit, hit_at) > 30 THEN 1 ELSE 0 END), 0) AS hits
				FROM ordered_hits
				GROUP BY day_bucket, hour_idx
				ORDER BY day_bucket ASC, hour_idx ASC";
		} else {
			$heatmapSql =
				"SELECT DATE($localHitExpr) AS day_bucket, HOUR($localHitExpr) AS hour_idx, COUNT(*) AS hits
				 FROM pd_ad_hit_logs h
				 WHERE $whereHeatmapSql
				 GROUP BY day_bucket, hour_idx
				 ORDER BY day_bucket ASC, hour_idx ASC";
		}

		$heatmapStmt = db()->prepare($heatmapSql);
		$heatmapStmt->bindValue(':tz_name', $displayTimezoneName, PDO::PARAM_STR);
		$heatmapStmt->bindValue(':tz_offset_minute', $appTimezoneOffsetMinutes, PDO::PARAM_INT);
		foreach ($params as $key => $value) {
			$heatmapStmt->bindValue(':' . $key, $value, PDO::PARAM_STR);
		}
		$heatmapStmt->execute();
		$heatmapRows = $heatmapStmt->fetchAll();

		foreach ($heatmapRowOrder as $rowKey) {
			$heatmapGrid[$rowKey] = [];
			for ($hour = 0; $hour < 24; $hour++) {
				$heatmapGrid[$rowKey][$hour] = 0;
			}
		}

		foreach ($heatmapRows as $heatmapRow) {
			$rowKey = (string) ($heatmapRow['day_bucket'] ?? '');
			$hourIdx = (int) ($heatmapRow['hour_idx'] ?? -1);
			$hits = (int) ($heatmapRow['hits'] ?? 0);
			if (!isset($heatmapGrid[$rowKey]) || $hourIdx < 0 || $hourIdx > 23) {
				continue;
			}
			$heatmapGrid[$rowKey][$hourIdx] = $hits;
			if ($hits > $heatmapMaxHits) {
				$heatmapMaxHits = $hits;
			}
		}
	}
}

$displayStart = 0;
$displayEnd = 0;
if ($totalRows > 0) {
	$displayStart = (($page - 1) * $perPage) + 1;
	$displayEnd = min((($page - 1) * $perPage) + count($recentRows), $totalRows);
}

$matchRate = 0.0;
$totalHits = (int) ($summary['total_hits'] ?? 0);
if ($totalHits > 0) {
	$matchRate = ((int) ($summary['matched_hits'] ?? 0) / $totalHits) * 100;
}

render_header('Targeted Ad Analytics');
?>
<style>
	.summary-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(170px,1fr));gap:10px;margin-bottom:12px}
	.summary-bubble{border:1px solid #dbe4f5;background:#f6f9ff;border-radius:999px;padding:12px 14px;line-height:1.2}
	.summary-bubble strong{display:block;font-size:1.15rem;color:#1f4ea5}
	.summary-bubble .muted{font-size:.82rem}
</style>
<div class="spaced card">
	<div>
		<h1>Targeted Ad Analytics</h1>
		<p class="muted">Matched/unmatched tracking for ad.js visibility events.</p>
	</div>
	<div class="inline">
		<a class="nav-btn" href="index.php">Back to dashboard</a>
		<a class="nav-btn" href="ads.php">Manage targeted ads</a>
		<a class="nav-btn logout" href="../logout.php">Logout</a>
	</div>
</div>

<?php if ($success): ?>
	<div class="success"><?php echo e($success); ?></div>
<?php endif; ?>
<?php if ($error): ?>
	<div class="error"><?php echo e($error); ?></div>
<?php endif; ?>

<?php if (!$schemaReady): ?>
	<div class="error">Targeted ad analytics schema is not ready. Missing: <?php echo e(implode(', ', $schemaMissing)); ?>.</div>
	<div class="card">
		<p><a class="nav-btn" href="../migrate.php">Run migrations</a></p>
	</div>
	<?php render_footer(); return; ?>
<?php endif; ?>

<div class="card">
	<form method="get" class="row">
		<div>
			<label>Ad ID</label>
			<select name="ad_key">
				<option value="">All ads</option>
				<?php foreach ($adKeys as $keyRow): ?>
					<?php $keyValue = (string) ($keyRow['ad_key'] ?? ''); ?>
					<option value="<?php echo e($keyValue); ?>" <?php echo $adKeyFilter === $keyValue ? 'selected' : ''; ?>><?php echo e($keyValue); ?></option>
				<?php endforeach; ?>
			</select>
		</div>
		<div>
			<label>Period</label>
			<select name="period">
				<option value="24h" <?php echo $period === '24h' ? 'selected' : ''; ?>>Last 24 hours</option>
				<option value="7d" <?php echo $period === '7d' ? 'selected' : ''; ?>>Last 7 days</option>
				<option value="30d" <?php echo $period === '30d' ? 'selected' : ''; ?>>Last 30 days</option>
				<option value="all" <?php echo $period === 'all' ? 'selected' : ''; ?>>All time</option>
			</select>
		</div>
		<div>
			<label>Match Filter</label>
			<select name="match">
				<option value="all" <?php echo $matchFilter === 'all' ? 'selected' : ''; ?>>All events</option>
				<option value="matched" <?php echo $matchFilter === 'matched' ? 'selected' : ''; ?>>Matched only</option>
				<option value="unmatched" <?php echo $matchFilter === 'unmatched' ? 'selected' : ''; ?>>Unmatched only</option>
			</select>
		</div>
		<div>
			<label>Sort</label>
			<select name="sort">
				<option value="latest" <?php echo $sort === 'latest' ? 'selected' : ''; ?>>Latest first</option>
				<option value="matched_first" <?php echo $sort === 'matched_first' ? 'selected' : ''; ?>>Matched first</option>
				<option value="unmatched_first" <?php echo $sort === 'unmatched_first' ? 'selected' : ''; ?>>Unmatched first</option>
			</select>
		</div>
		<div style="align-self:end;">
			<button type="submit">Apply</button>
		</div>
	</form>
</div>

<div class="card">
	<h2>Summary</h2>
	<div class="summary-grid">
		<div class="summary-bubble"><strong><?php echo number_format((int) ($summary['total_hits'] ?? 0)); ?></strong><span class="muted">Total requests</span></div>
		<div class="summary-bubble"><strong><?php echo number_format((int) ($summary['matched_hits'] ?? 0)); ?></strong><span class="muted">Matched</span></div>
		<div class="summary-bubble"><strong><?php echo number_format((int) ($summary['unmatched_hits'] ?? 0)); ?></strong><span class="muted">Unmatched</span></div>
		<div class="summary-bubble"><strong><?php echo number_format((int) ($summary['unique_ips'] ?? 0)); ?></strong><span class="muted">Unique IPs</span></div>
		<div class="summary-bubble"><strong><?php echo number_format($matchRate, 2); ?>%</strong><span class="muted">Match rate</span></div>
	</div>
</div>

<?php if ($period !== 'all'): ?>
	<div class="card">
		<h3>Time-of-Day Heatmap (<?php echo e($displayTimezoneName); ?>)</h3>
		<p class="muted">Visibility event concentration by date and hour. Metric: <?php echo e($heatmapMetric === 'estimated_visits' ? 'Estimated Visits (Balanced)' : 'Hits'); ?>. Darker cells indicate higher volume.</p>
		<div style="width:100%;overflow-x:auto;">
			<table style="min-width:980px;table-layout:fixed;font-size:0.78rem;">
				<thead>
					<tr>
						<th style="width:92px;padding:4px 6px;">Date</th>
						<?php for ($hour = 0; $hour < 24; $hour++): ?>
							<th style="text-align:center;padding:4px 3px;"><?php echo e(str_pad((string) $hour, 2, '0', STR_PAD_LEFT)); ?></th>
						<?php endfor; ?>
					</tr>
				</thead>
				<tbody>
				<?php foreach ($heatmapRowOrder as $rowKey): ?>
					<tr>
						<td style="padding:4px 6px;"><strong><?php echo e((string) ($heatmapRowLabels[$rowKey] ?? (string) $rowKey)); ?></strong></td>
						<?php for ($hour = 0; $hour < 24; $hour++): ?>
							<?php
							$cellHits = (int) ($heatmapGrid[$rowKey][$hour] ?? 0);
							$intensity = $heatmapMaxHits > 0 ? ($cellHits / $heatmapMaxHits) : 0;
							$alpha = $intensity > 0 ? (0.08 + ($intensity * 0.82)) : 0;
							$textColor = $alpha >= 0.58 ? '#ffffff' : '#1f2937';
							$bgColor = $cellHits > 0 ? 'rgba(31, 78, 165, ' . number_format($alpha, 3, '.', '') . ')' : 'transparent';
							?>
							<td style="text-align:center;padding:4px 3px;background:<?php echo e($bgColor); ?>;color:<?php echo e($textColor); ?>;font-weight:<?php echo $cellHits > 0 ? '600' : '400'; ?>;">
								<?php echo e((string) $cellHits); ?>
							</td>
						<?php endfor; ?>
					</tr>
				<?php endforeach; ?>
				</tbody>
			</table>
		</div>
		<p class="muted">Peak cell value in window: <?php echo e((string) $heatmapMaxHits); ?></p>
	</div>
<?php else: ?>
	<div class="card">
		<h3>Time-of-Day Heatmap</h3>
		<p class="muted">Hidden for All Time period. Select 24h, 7d, or 30d to view hourly concentration.</p>
	</div>
<?php endif; ?>

<div class="row" style="display:grid;grid-template-columns:repeat(auto-fit,minmax(320px,1fr));gap:16px;">
	<div class="card">
		<h2>Top Providers</h2>
		<table>
			<thead><tr><th>Provider</th><th>Hits</th></tr></thead>
			<tbody>
			<?php if (!$topProviders): ?>
				<tr><td colspan="2" class="muted">No provider data.</td></tr>
			<?php else: ?>
				<?php foreach ($topProviders as $row): ?>
					<?php $providerName = (string) ($row['provider_name'] ?? 'unknown'); ?>
					<tr>
						<td><a href="provider-details.php?provider=<?php echo urlencode($providerName); ?>&amp;period=<?php echo urlencode($period); ?>"><?php echo e($providerName); ?></a></td>
						<td><?php echo number_format((int) ($row['hits'] ?? 0)); ?></td>
					</tr>
				<?php endforeach; ?>
			<?php endif; ?>
			</tbody>
		</table>
	</div>
	<div class="card">
		<h2>Top IPs</h2>
		<table>
			<thead><tr><th>IP Address</th><th>Hits</th><th>Matched</th></tr></thead>
			<tbody>
			<?php if (!$topIps): ?>
				<tr><td colspan="3" class="muted">No IP data.</td></tr>
			<?php else: ?>
				<?php foreach ($topIps as $row): ?>
					<?php $ipValue = (string) ($row['ip_address'] ?? ''); ?>
					<?php $ipDisplay = format_ip_with_operator_tag($ipValue, (string) ($ipTagMap[$ipValue] ?? '')); ?>
					<?php $ipLinkQuery = ['type' => 'ip', 'value' => $ipValue, 'period' => $period]; ?>
					<?php if ($adKeyFilter !== '') { $ipLinkQuery['ad_key'] = $adKeyFilter; } ?>
					<tr>
						<td><a href="ad-linkout.php?<?php echo e(http_build_query($ipLinkQuery)); ?>"><?php echo e($ipDisplay !== '' ? $ipDisplay : $ipValue); ?></a></td>
						<td><?php echo number_format((int) ($row['hits'] ?? 0)); ?></td>
						<td><?php echo number_format((int) ($row['matched_hits'] ?? 0)); ?></td>
					</tr>
				<?php endforeach; ?>
			<?php endif; ?>
			</tbody>
		</table>
	</div>
</div>

<div class="card">
	<h2>Recent Visibility Events</h2>
	<p class="muted">Showing <?php echo number_format($displayStart); ?>-<?php echo number_format($displayEnd); ?> of <?php echo number_format($totalRows); ?> hits.</p>
	<table>
		<thead>
		<tr>
			<th>Time</th>
			<th>Ad ID</th>
			<th>Match</th>
			<th>Priority</th>
			<th>Action</th>
			<th>IP</th>
			<th>Entry URL</th>
			<th>Entry Referrer</th>
			<th>Provider</th>
			<th>Traffic</th>
			<th>Country</th>
		</tr>
		</thead>
		<tbody>
		<?php if (!$recentRows): ?>
			<tr><td colspan="11" class="muted">No tracked events in selected filters.</td></tr>
		<?php else: ?>
			<?php foreach ($recentRows as $row): ?>
				<?php
				$ipValue = (string) ($row['ip_address'] ?? '');
				$ipDisplay = format_ip_with_operator_tag($ipValue, (string) ($ipTagMap[$ipValue] ?? ''));
				$entryUrl = trim((string) ($row['entry_url'] ?? ''));
				$entryReferrer = trim((string) ($row['entry_referrer'] ?? ''));
				$recentRowAdKey = sanitize_ad_key((string) ($row['ad_key'] ?? ''));
				$recentIpLinkQuery = ['type' => 'ip', 'value' => $ipValue, 'period' => $period];
				if ($recentRowAdKey !== '') {
					$recentIpLinkQuery['ad_key'] = $recentRowAdKey;
				}
				$priorityLabel = (int) ($row['matched'] ?? 0) === 1 && isset($row['matched_priority']) && $row['matched_priority'] !== null
					? (string) ((int) $row['matched_priority'])
					: '-';
				?>
				<tr>
					<td><?php echo e($formatStoredLocalTime((string) ($row['hit_at'] ?? ''))); ?></td>
					<td><?php echo e((string) ($row['ad_key'] ?? '')); ?></td>
					<td><?php echo (int) ($row['matched'] ?? 0) === 1 ? 'Matched' : 'Unmatched'; ?></td>
					<td><?php echo e($priorityLabel); ?></td>
					<td><?php echo e((string) ($row['matched_action_type'] ?? '-')); ?></td>
					<td><a href="ad-linkout.php?<?php echo e(http_build_query($recentIpLinkQuery)); ?>"><?php echo e($ipDisplay !== '' ? $ipDisplay : $ipValue); ?></a></td>
					<td style="max-width:280px; overflow-wrap:anywhere; word-break:break-word;"><?php echo e($entryUrl !== '' ? $entryUrl : '-'); ?></td>
					<td style="max-width:280px; overflow-wrap:anywhere; word-break:break-word;"><?php echo e($entryReferrer !== '' ? $entryReferrer : '-'); ?></td>
					<td><?php echo e((string) (($row['provider_name'] ?? '') !== '' ? $row['provider_name'] : 'unknown')); ?></td>
					<td><?php echo e((string) ($row['traffic_type'] ?? 'unknown')); ?></td>
					<td><?php echo e((string) (($row['country_code'] ?? '') !== '' ? $row['country_code'] : '-')); ?></td>
				</tr>
			<?php endforeach; ?>
		<?php endif; ?>
		</tbody>
	</table>

	<?php if ($totalPages > 1): ?>
		<?php
		$baseParams = [
			'ad_key' => $adKeyFilter,
			'provider' => $providerFilter,
			'period' => $period,
			'match' => $matchFilter,
			'sort' => $sort,
			'heatmap_metric' => $heatmapMetric,
		];
		?>
		<div class="inline" style="margin-top:10px;">
			<?php if ($page > 1): ?>
				<?php $firstParams = $baseParams; $firstParams['page'] = 1; ?>
				<a class="nav-btn" href="ad-analytics.php?<?php echo http_build_query($firstParams); ?>">First</a>
			<?php endif; ?>
			<?php if ($page > 1): ?>
				<?php $prevParams = $baseParams; $prevParams['page'] = $page - 1; ?>
				<a class="nav-btn" href="ad-analytics.php?<?php echo http_build_query($prevParams); ?>">Previous</a>
			<?php endif; ?>
			<span class="muted">Page <?php echo (int) $page; ?> of <?php echo (int) $totalPages; ?></span>
			<?php if ($page < $totalPages): ?>
				<?php $nextParams = $baseParams; $nextParams['page'] = $page + 1; ?>
				<a class="nav-btn" href="ad-analytics.php?<?php echo http_build_query($nextParams); ?>">Next</a>
			<?php endif; ?>
			<?php if ($page < $totalPages): ?>
				<?php $lastParams = $baseParams; $lastParams['page'] = $totalPages; ?>
				<a class="nav-btn" href="ad-analytics.php?<?php echo http_build_query($lastParams); ?>">Last</a>
			<?php endif; ?>
			<form method="get" class="inline" style="margin:0;">
				<input type="hidden" name="ad_key" value="<?php echo e($adKeyFilter); ?>">
				<input type="hidden" name="provider" value="<?php echo e($providerFilter); ?>">
				<input type="hidden" name="period" value="<?php echo e($period); ?>">
				<input type="hidden" name="match" value="<?php echo e($matchFilter); ?>">
				<input type="hidden" name="sort" value="<?php echo e($sort); ?>">
				<input type="hidden" name="heatmap_metric" value="<?php echo e($heatmapMetric); ?>">
				<label style="display:flex;align-items:center;gap:6px;">
					<span class="muted">Go to page</span>
					<input type="number" name="page" min="1" max="<?php echo (int) $totalPages; ?>" value="<?php echo (int) $page; ?>" style="width:88px;">
				</label>
				<button type="submit">Go</button>
			</form>
		</div>
	<?php endif; ?>
</div>

<?php render_footer();
