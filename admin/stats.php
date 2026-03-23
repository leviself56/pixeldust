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

$pixelKey = trim((string) ($_GET['pixel_key'] ?? ''));
$period = (string) ($_GET['period'] ?? '7d');
$validPeriods = ['24h', '7d', '30d'];
if (!in_array($period, $validPeriods, true)) {
	$period = '7d';
}

if ($period === '24h') {
	$intervalExpr = 'INTERVAL 24 HOUR';
	$groupFmt = '%Y-%m-%d %H:00:00';
} elseif ($period === '30d') {
	$intervalExpr = 'INTERVAL 30 DAY';
	$groupFmt = '%Y-%m-%d';
} else {
	$intervalExpr = 'INTERVAL 7 DAY';
	$groupFmt = '%Y-%m-%d';
}

$pixels = db()->query('SELECT pixel_key, total_hits FROM pd_pixels ORDER BY pixel_key ASC')->fetchAll();

$selectedPixel = null;
if ($pixelKey !== '') {
	$stmt = db()->prepare('SELECT id, pixel_key, total_hits, created_at, updated_at FROM pd_pixels WHERE pixel_key = :pixel_key LIMIT 1');
	$stmt->execute(['pixel_key' => $pixelKey]);
	$selectedPixel = $stmt->fetch();
}

$chartData = [];
$recentHits = [];
$recentHitsPage = max(1, (int) ($_GET['page'] ?? 1));
$recentHitsPerPage = 100;
$recentHitsTotal = 0;
$recentHitsTotalPages = 1;

if ($selectedPixel) {
	$chartSql =
		'SELECT DATE_FORMAT(hit_at, :group_fmt) AS bucket, COUNT(*) AS hit_count
		 FROM pd_pixel_hits
		 WHERE pixel_id = :pixel_id AND hit_at >= (NOW() - ' . $intervalExpr . ')
		 GROUP BY bucket
		 ORDER BY bucket ASC';

	$chartStmt = db()->prepare($chartSql);
	$chartStmt->execute([
		'group_fmt' => $groupFmt,
		'pixel_id' => (int) $selectedPixel['id'],
	]);
	$chartData = $chartStmt->fetchAll();

	$totalStmt = db()->prepare(
		'SELECT COUNT(*) AS total
		 FROM pd_pixel_hits
		 WHERE pixel_id = :pixel_id'
	);
	$totalStmt->execute(['pixel_id' => (int) $selectedPixel['id']]);
	$recentHitsTotal = (int) ($totalStmt->fetch()['total'] ?? 0);
	$recentHitsTotalPages = max(1, (int) ceil($recentHitsTotal / $recentHitsPerPage));
	if ($recentHitsPage > $recentHitsTotalPages) {
		$recentHitsPage = $recentHitsTotalPages;
	}
	$recentHitsOffset = ($recentHitsPage - 1) * $recentHitsPerPage;

	$recentStmt = db()->prepare(
		'SELECT hit_at, ip_address, user_agent, referrer, accept_language, remote_host
		 FROM pd_pixel_hits
		 WHERE pixel_id = :pixel_id
		 ORDER BY hit_at DESC
		 LIMIT :offset, :limit'
	);
	$recentStmt->bindValue(':pixel_id', (int) $selectedPixel['id'], PDO::PARAM_INT);
	$recentStmt->bindValue(':offset', $recentHitsOffset, PDO::PARAM_INT);
	$recentStmt->bindValue(':limit', $recentHitsPerPage, PDO::PARAM_INT);
	$recentStmt->execute();
	$recentHits = $recentStmt->fetchAll();
}

function render_svg_chart(array $rows): string
{
	if (!$rows) {
		return '<p class="muted">No data in selected period.</p>';
	}

	$width = 900;
	$height = 280;
	$padding = 36;
	$usableWidth = $width - ($padding * 2);
	$usableHeight = $height - ($padding * 2);

	$counts = array_map(static fn($row): int => (int) $row['hit_count'], $rows);
	$maxCount = max($counts);
	if ($maxCount < 1) {
		$maxCount = 1;
	}

	$points = [];
	$labels = [];
	$countRows = count($rows);

	foreach ($rows as $index => $row) {
		$x = $padding + (($countRows <= 1 ? 0 : $index / ($countRows - 1)) * $usableWidth);
		$y = $height - $padding - (((int) $row['hit_count'] / $maxCount) * $usableHeight);
		$points[] = round($x, 2) . ',' . round($y, 2);
		$labels[] = [
			'x' => $x,
			'y' => $height - ($padding - 14),
			'text' => substr((string) $row['bucket'], 5),
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

	$svg .= '<text x="' . ($padding + 4) . '" y="' . ($padding + 10) . '" font-size="10" fill="#666">Max: ' . $maxCount . '</text>';
	$svg .= '</svg>';

	return $svg;
}

render_header('Stats');
?>
<div class="spaced card">
	<div>
		<h1>Pixel Statistics</h1>
		<p class="muted">View hit volume and request details per pixel id.</p>
	</div>
	<div class="inline">
		<a class="nav-btn" href="index.php">Back to dashboard</a>
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
		<div style="align-self:end;"><button type="submit">Load Stats</button></div>
	</form>
</div>

<?php if ($pixelKey !== '' && !$selectedPixel): ?>
	<div class="error">Pixel not found.</div>
<?php endif; ?>

<?php if ($selectedPixel): ?>
	<div class="card">
		<h2><?php echo e((string) $selectedPixel['pixel_key']); ?></h2>
		<p class="muted">Total hits: <?php echo e((string) $selectedPixel['total_hits']); ?> | Created: <?php echo e((string) $selectedPixel['created_at']); ?></p>
		<?php echo render_svg_chart($chartData); ?>
	</div>

	<div class="card">
		<h3>Recent Hits</h3>
		<p class="muted">Showing <?php echo e((string) ($recentHitsTotal === 0 ? 0 : (($recentHitsPage - 1) * $recentHitsPerPage + 1))); ?>-
			<?php echo e((string) min($recentHitsPage * $recentHitsPerPage, $recentHitsTotal)); ?> of
			<?php echo e((string) $recentHitsTotal); ?></p>
		<table>
			<thead>
			<tr>
				<th>Date/Time</th>
				<th>IP</th>
				<th>Referrer</th>
				<th>User Agent</th>
				<th>Language</th>
				<th>Host</th>
			</tr>
			</thead>
			<tbody>
			<?php if (!$recentHits): ?>
				<tr><td colspan="6" class="muted">No hits yet.</td></tr>
			<?php else: ?>
				<?php foreach ($recentHits as $hit): ?>
					<tr>
						<td><?php echo e((string) $hit['hit_at']); ?></td>
						<td><?php echo e((string) $hit['ip_address']); ?></td>
						<td><?php echo e((string) ($hit['referrer'] ?: '-')); ?></td>
						<td><?php echo e((string) ($hit['user_agent'] ?: '-')); ?></td>
						<td><?php echo e((string) ($hit['accept_language'] ?: '-')); ?></td>
						<td><?php echo e((string) ($hit['remote_host'] ?: '-')); ?></td>
					</tr>
				<?php endforeach; ?>
			<?php endif; ?>
			</tbody>
		</table>
		<?php if ($recentHitsTotalPages > 1): ?>
			<div class="inline" style="margin-top:12px;">
				<?php if ($recentHitsPage > 1): ?>
					<a href="stats.php?pixel_key=<?php echo urlencode((string) $selectedPixel['pixel_key']); ?>&period=<?php echo urlencode($period); ?>&page=<?php echo (int) ($recentHitsPage - 1); ?>">&laquo; Prev</a>
				<?php endif; ?>
				<span class="muted">Page <?php echo e((string) $recentHitsPage); ?> of <?php echo e((string) $recentHitsTotalPages); ?></span>
				<?php if ($recentHitsPage < $recentHitsTotalPages): ?>
					<a href="stats.php?pixel_key=<?php echo urlencode((string) $selectedPixel['pixel_key']); ?>&period=<?php echo urlencode($period); ?>&page=<?php echo (int) ($recentHitsPage + 1); ?>">Next &raquo;</a>
				<?php endif; ?>
			</div>
		<?php endif; ?>
	</div>
<?php endif; ?>
<?php
render_footer();
