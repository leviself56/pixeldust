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

$admin = current_admin();
$error = null;
$successMsg = flash('success');
$createdPixelKey = null;
$createdRedirectKey = null;
$editRedirectId = max(0, (int) ($_GET['edit_redirect_id'] ?? 0));
$editingRedirect = null;

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
	$action = (string) ($_POST['action'] ?? 'create_pixel');

	if ($action === 'create_redirect') {
		$rawRedirectKey = trim((string) ($_POST['redirect_key'] ?? ''));
		$redirectKey = sanitize_redirect_key($rawRedirectKey);
		$destinationUrl = trim((string) ($_POST['destination_url'] ?? ''));

		if ($redirectKey === '') {
			$error = 'Redirect id is required and must contain letters and/or numbers.';
		} else {
			try {
				create_redirect_link($redirectKey, $destinationUrl, (int) ($admin['id'] ?? 0));
				$successMsg = 'Redirect URL created: ' . $redirectKey;
				$createdRedirectKey = $redirectKey;
			} catch (Throwable $e) {
				$error = 'Could not create redirect URL: ' . $e->getMessage();
			}
		}
	} elseif ($action === 'save_redirect') {
		$redirectId = max(0, (int) ($_POST['redirect_id'] ?? 0));
		$rawRedirectKey = trim((string) ($_POST['redirect_key'] ?? ''));
		$redirectKey = sanitize_redirect_key($rawRedirectKey);
		$destinationUrl = trim((string) ($_POST['destination_url'] ?? ''));
		$isActive = isset($_POST['is_active']) ? 1 : 0;

		if ($redirectId < 1) {
			$error = 'Invalid redirect selected for editing.';
		} elseif ($redirectKey === '') {
			$error = 'Redirect id is required and must contain letters and/or numbers.';
		} elseif ($destinationUrl === '' || !filter_var($destinationUrl, FILTER_VALIDATE_URL)) {
			$error = 'Destination URL must be valid.';
		} else {
			$scheme = strtolower((string) parse_url($destinationUrl, PHP_URL_SCHEME));
			if (!in_array($scheme, ['http', 'https'], true)) {
				$error = 'Destination URL must use http or https.';
			}
		}

		if ($error === null) {
			try {
				$dupStmt = db()->prepare('SELECT id FROM pd_redirect_links WHERE redirect_key = :redirect_key AND id <> :id LIMIT 1');
				$dupStmt->execute([
					'redirect_key' => $redirectKey,
					'id' => $redirectId,
				]);
				if ($dupStmt->fetch()) {
					throw new RuntimeException('Redirect id already exists.');
				}

				$updateStmt = db()->prepare(
					'UPDATE pd_redirect_links
					 SET redirect_key = :redirect_key,
					     destination_url = :destination_url,
					     is_active = :is_active,
					     updated_at = NOW()
					 WHERE id = :id'
				);
				$updateStmt->execute([
					'redirect_key' => $redirectKey,
					'destination_url' => $destinationUrl,
					'is_active' => $isActive,
					'id' => $redirectId,
				]);

				$syncHitsStmt = db()->prepare('UPDATE pd_redirect_hits SET redirect_key = :redirect_key WHERE redirect_id = :redirect_id');
				$syncHitsStmt->execute([
					'redirect_key' => $redirectKey,
					'redirect_id' => $redirectId,
				]);

				$syncClassStmt = db()->prepare('UPDATE pd_redirect_hit_classification SET redirect_key = :redirect_key WHERE redirect_id = :redirect_id');
				$syncClassStmt->execute([
					'redirect_key' => $redirectKey,
					'redirect_id' => $redirectId,
				]);

				$successMsg = 'Redirect URL updated: ' . $redirectKey;
				$createdRedirectKey = $redirectKey;
				$editRedirectId = 0;
			} catch (Throwable $e) {
				$error = 'Could not update redirect URL: ' . $e->getMessage();
			}
		}
	} elseif ($action === 'toggle_redirect') {
		$redirectId = max(0, (int) ($_POST['redirect_id'] ?? 0));
		$newState = (int) ($_POST['new_state'] ?? 0) === 1 ? 1 : 0;

		if ($redirectId < 1) {
			$error = 'Invalid redirect selected.';
		} else {
			try {
				$toggleStmt = db()->prepare('UPDATE pd_redirect_links SET is_active = :is_active, updated_at = NOW() WHERE id = :id');
				$toggleStmt->execute([
					'is_active' => $newState,
					'id' => $redirectId,
				]);
				$successMsg = $newState === 1 ? 'Redirect activated.' : 'Redirect deactivated.';
			} catch (Throwable $e) {
				$error = 'Could not update redirect status: ' . $e->getMessage();
			}
		}
	} elseif ($action === 'delete_redirect') {
		$redirectId = max(0, (int) ($_POST['redirect_id'] ?? 0));

		if ($redirectId < 1) {
			$error = 'Invalid redirect selected.';
		} else {
			try {
				$deleteClassStmt = db()->prepare('DELETE FROM pd_redirect_hit_classification WHERE redirect_id = :redirect_id');
				$deleteClassStmt->execute(['redirect_id' => $redirectId]);

				$deleteHitsStmt = db()->prepare('DELETE FROM pd_redirect_hits WHERE redirect_id = :redirect_id');
				$deleteHitsStmt->execute(['redirect_id' => $redirectId]);

				$deleteLinkStmt = db()->prepare('DELETE FROM pd_redirect_links WHERE id = :id');
				$deleteLinkStmt->execute(['id' => $redirectId]);

				$successMsg = 'Redirect URL deleted.';
				if ($editRedirectId === $redirectId) {
					$editRedirectId = 0;
				}
			} catch (Throwable $e) {
				$error = 'Could not delete redirect URL: ' . $e->getMessage();
			}
		}
	} else {
		$rawPixelKey = trim((string) ($_POST['pixel_key'] ?? ''));
		$pixelKey = sanitize_pixel_key($rawPixelKey);

		if ($pixelKey === '') {
			$error = 'Pixel id is required and must contain letters and/or numbers.';
		} else {
			try {
				$existingStmt = db()->prepare('SELECT id, created_at FROM pd_pixels WHERE pixel_key = :pixel_key LIMIT 1');
				$existingStmt->execute(['pixel_key' => $pixelKey]);
				$existingPixel = $existingStmt->fetch();

				create_pixel_if_missing($pixelKey, (int) $admin['id']);
				$_SESSION['created_pixel_key'] = $pixelKey;

				if ($existingPixel) {
					$successMsg = 'Pixel already existed: ' . $pixelKey . ' (it may have been auto-created by a prior /pix.php?id= request).';
				} else {
					$successMsg = 'Pixel created: ' . $pixelKey;
				}

				$createdPixelKey = $pixelKey;
			} catch (Throwable $e) {
				$error = 'Could not create pixel: ' . $e->getMessage();
			}
		}
	}
}

$pixels = [];
$redirectLinks = [];
try {
	$pixels = db()->query(
		'SELECT id, pixel_key, label, total_hits, created_at, updated_at
		 FROM pd_pixels
		 ORDER BY updated_at DESC, id DESC'
	)->fetchAll();

	$lastHitMap = [];
	$lastHitRows = db()->query(
		'SELECT pixel_id, MAX(hit_at) AS last_hit_at
		 FROM pd_pixel_hits
		 GROUP BY pixel_id'
	)->fetchAll();

	foreach ($lastHitRows as $lastHitRow) {
		$lastHitMap[(int) $lastHitRow['pixel_id']] = (string) ($lastHitRow['last_hit_at'] ?? '');
	}

	foreach ($pixels as &$pixel) {
		$pixelId = (int) $pixel['id'];
		$pixel['last_hit_at'] = $lastHitMap[$pixelId] ?? '';
	}
	unset($pixel);

	$redirectLinks = db()->query(
		'SELECT id, redirect_key, destination_url, is_active, total_hits, created_at, updated_at
		 FROM pd_redirect_links
		 ORDER BY updated_at DESC, id DESC'
	)->fetchAll();

	$lastRedirectHitMap = [];
	$lastRedirectRows = db()->query(
		'SELECT redirect_id, MAX(hit_at) AS last_hit_at
		 FROM pd_redirect_hits
		 GROUP BY redirect_id'
	)->fetchAll();

	foreach ($lastRedirectRows as $lastRedirectRow) {
		$lastRedirectHitMap[(int) $lastRedirectRow['redirect_id']] = (string) ($lastRedirectRow['last_hit_at'] ?? '');
	}

	foreach ($redirectLinks as &$redirectLink) {
		$redirectId = (int) $redirectLink['id'];
		$redirectLink['last_hit_at'] = $lastRedirectHitMap[$redirectId] ?? '';
	}
	unset($redirectLink);

	if ($editRedirectId > 0) {
		foreach ($redirectLinks as $redirectLinkRow) {
			if ((int) ($redirectLinkRow['id'] ?? 0) === $editRedirectId) {
				$editingRedirect = $redirectLinkRow;
				break;
			}
		}
	}
} catch (Throwable $e) {
	$error = 'Could not load pixel table: ' . $e->getMessage();
}

$totalPixels = count($pixels);
$totalHits = (int) (db()->query('SELECT COALESCE(SUM(total_hits), 0) AS total FROM pd_pixels')->fetch()['total'] ?? 0);
$totalRedirectLinks = count($redirectLinks);
$totalRedirectHits = (int) (db()->query('SELECT COALESCE(SUM(total_hits), 0) AS total FROM pd_redirect_links')->fetch()['total'] ?? 0);

$defaultTriggerId = null;
try {
	$defaultTriggerStmt = db()->query('SELECT trigger_id FROM pd_trigger_actions WHERE is_default = 1 AND is_active = 1 ORDER BY updated_at DESC, id DESC LIMIT 1');
	$defaultTrigger = $defaultTriggerStmt->fetch();
	if ($defaultTrigger && isset($defaultTrigger['trigger_id'])) {
		$defaultTriggerId = (string) $defaultTrigger['trigger_id'];
	}
} catch (Throwable $e) {
}

render_header('Admin Dashboard');
?>
<div class="spaced card">
	<div>
		<h1>Pixel Dust Admin</h1>
		<p class="muted">Logged in as <?php echo e((string) $admin['username']); ?></p>
	</div>
	<div class="inline">
		<a class="nav-btn" href="stats.php">View detailed stats</a>
		<a class="nav-btn" href="analytics.php">View analytics</a>
		<a class="nav-btn" href="users.php">Manage users</a>
		<a class="nav-btn" href="triggers.php">Manage triggers</a>
		<a class="nav-btn" href="../migrate.php">Run migrations</a>
		<a class="nav-btn logout" href="../logout.php">Logout</a>
	</div>
</div>

<?php if ($successMsg): ?>
	<div class="success"><?php echo e($successMsg); ?></div>
<?php endif; ?>
<?php if ($error): ?>
	<div class="error"><?php echo e($error); ?></div>
<?php endif; ?>

<?php if ($createdPixelKey !== null): ?>
	<?php
	$createdPixelUrl = base_url() . '/pix.php?id=' . urlencode($createdPixelKey);
	if ($defaultTriggerId !== null && $defaultTriggerId !== '') {
		$createdPixelUrl .= '&trigger=' . urlencode($defaultTriggerId);
	}
	?>
	<?php $createdPixelTag = '<img src="' . $createdPixelUrl . '" width="1" height="1" style="display:none;" alt="" />'; ?>
	<div class="card">
		<h2>Embed Code</h2>
		<p class="muted">Use this pixel URL/snippet in blog posts, emails, or websites.</p>
		<?php if ($defaultTriggerId !== null && $defaultTriggerId !== ''): ?>
			<p class="muted">Default trigger applied: <?php echo e($defaultTriggerId); ?></p>
		<?php endif; ?>
		<p>
			<label>Direct Pixel URL</label>
			<span class="inline" style="display:flex;align-items:center;gap:8px;">
				<input id="created-pixel-url" value="<?php echo e($createdPixelUrl); ?>" readonly onclick="this.select()" style="flex:1;min-width:260px;width:auto;">
				<button type="button" onclick="copyToClipboard('created-pixel-url', this)">Copy Link</button>
			</span>
		</p>
		<p><label>HTML Embed Snippet</label><input value="<?php echo e($createdPixelTag); ?>" readonly onclick="this.select()"></p>
	</div>
<?php endif; ?>

<?php if ($createdRedirectKey !== null): ?>
	<?php
	$createdRedirectUrl = base_url() . '/link.php?id=' . urlencode($createdRedirectKey);
	if ($defaultTriggerId !== null && $defaultTriggerId !== '') {
		$createdRedirectUrl .= '&trigger=' . urlencode($defaultTriggerId);
	}
	?>
	<div class="card">
		<h2>Redirect Link</h2>
		<p class="muted">Share this redirect URL to track and forward users.</p>
		<p>
			<label>Tracked Redirect URL</label>
			<span class="inline" style="display:flex;align-items:center;gap:8px;">
				<input id="created-redirect-url" value="<?php echo e($createdRedirectUrl); ?>" readonly onclick="this.select()" style="flex:1;min-width:260px;width:auto;">
				<button type="button" onclick="copyToClipboard('created-redirect-url', this)">Copy Link</button>
			</span>
		</p>
	</div>
<?php endif; ?>

<div class="row">
	<div class="card">
		<h3>Total Pixels</h3>
		<p style="font-size:1.6rem;font-weight:bold;"><?php echo e((string) $totalPixels); ?></p>
	</div>
	<div class="card">
		<h3>Total Hits</h3>
		<p style="font-size:1.6rem;font-weight:bold;"><?php echo e((string) $totalHits); ?></p>
	</div>
	<div class="card">
		<h3>Total Redirect URLs</h3>
		<p style="font-size:1.6rem;font-weight:bold;"><?php echo e((string) $totalRedirectLinks); ?></p>
	</div>
	<div class="card">
		<h3>Total Redirect Hits</h3>
		<p style="font-size:1.6rem;font-weight:bold;"><?php echo e((string) $totalRedirectHits); ?></p>
	</div>
</div>

<div class="card">
	<h2>Create Pixel</h2>
	<form method="post" class="inline">
		<input type="hidden" name="action" value="create_pixel">
		<div style="flex:1;min-width:240px;">
			<label>Pixel ID (example: blog_post_title)</label>
			<input type="text" id="pixel_key" name="pixel_key" required maxlength="191" placeholder="blog_post_title" oninput="sanitizePixelKeyInput(this)">
			<p class="muted">Spaces become underscores. Only letters, numbers, and underscores are kept.</p>
		</div>
		<div style="padding-top:22px;">
			<button type="submit">Create</button>
		</div>
	</form>
</div>

<div class="card">
	<h2>Pixels</h2>	
	<p>
		<label for="pixel-search">Search Pixel IDs</label>
		<input type="text" id="pixel-search" placeholder="Type or paste a pixel id to filter" oninput="filterPixelRows(this.value)">
	</p>
	<?php if ($pixels): ?>
		<?php
		$quickIds = [];
		foreach ($pixels as $quickPixel) {
			$quickIds[] = (string) $quickPixel['pixel_key'];
		}
		?>		
	<?php endif; ?>
	<div style="width:100%;overflow-x:auto;">
	<table style="min-width:100%;table-layout:fixed;">
		<thead>
			<tr>
				<th>ID</th>
				<th>Hits</th>
				<th>Last Hit</th>
				<th>Embed</th>
				<th>Stats</th>
				<th>Analytics</th>
			</tr>
		</thead>
		<tbody>
			<?php if (!$pixels): ?>
				<tr id="pixel-empty-row"><td colspan="6" class="muted">No pixels yet.</td></tr>
			<?php else: ?>
				<?php foreach ($pixels as $pixel): ?>
						<?php
						$embed = base_url() . '/pix.php?id=' . urlencode((string) $pixel['pixel_key']);
						if ($defaultTriggerId !== null && $defaultTriggerId !== '') {
							$embed .= '&trigger=' . urlencode($defaultTriggerId);
						}
						?>
					<tr class="pixel-row" data-pixel-key="<?php echo e((string) $pixel['pixel_key']); ?>">
						<td style="word-break:break-word;"><?php echo e((string) $pixel['pixel_key']); ?></td>
						<td style="word-break:break-word;"><?php echo e((string) $pixel['total_hits']); ?></td>
						<td style="word-break:break-word;"><?php echo e(format_db_datetime((string) ($pixel['last_hit_at'] ?? ''), 'Y-m-d H:i:s', '-')); ?></td>
						<td>
							<button type="button" onclick='copyTextValue(<?php echo json_encode($embed, JSON_HEX_TAG | JSON_HEX_APOS | JSON_HEX_AMP | JSON_HEX_QUOT); ?>, this)'>Copy Embed Link</button>
						</td>
						<td><a class="nav-btn" href="stats.php?pixel_key=<?php echo urlencode((string) $pixel['pixel_key']); ?>">Open</a></td>
						<td><a class="nav-btn" href="analytics.php?pixel_key=<?php echo urlencode((string) $pixel['pixel_key']); ?>">Open</a></td>
					</tr>
				<?php endforeach; ?>
			<?php endif; ?>
		</tbody>
	</table>
	</div>
</div>

<div class="card">
	<h2><?php echo $editingRedirect ? 'Edit Redirect URL' : 'Create Redirect URL'; ?></h2>
	<form method="post" class="inline">
		<input type="hidden" name="action" value="<?php echo $editingRedirect ? 'save_redirect' : 'create_redirect'; ?>">
		<?php if ($editingRedirect): ?>
			<input type="hidden" name="redirect_id" value="<?php echo (int) ($editingRedirect['id'] ?? 0); ?>">
		<?php endif; ?>
		<div style="flex:1;min-width:220px;">
			<label>Redirect ID (example: getairlink)</label>
			<input type="text" id="redirect_key" name="redirect_key" required maxlength="191" placeholder="getairlink" oninput="sanitizeRedirectKeyInput(this)" value="<?php echo e((string) ($editingRedirect['redirect_key'] ?? '')); ?>">
		</div>
		<div style="flex:2;min-width:320px;">
			<label>Destination URL</label>
			<input type="url" name="destination_url" required placeholder="https://airlinkrb.com" value="<?php echo e((string) ($editingRedirect['destination_url'] ?? '')); ?>">
		</div>
		<div style="padding-top:26px;min-width:140px;">
			<label style="display:flex;align-items:center;gap:6px;"><input type="checkbox" name="is_active" value="1" <?php echo !$editingRedirect || (int) ($editingRedirect['is_active'] ?? 0) === 1 ? 'checked' : ''; ?> style="width:auto;"> Active</label>
		</div>
		<div style="padding-top:22px;">
			<button type="submit"><?php echo $editingRedirect ? 'Save' : 'Create'; ?></button>
			<?php if ($editingRedirect): ?>
				<a class="nav-btn" href="index.php" style="margin-left:8px;">Cancel</a>
			<?php endif; ?>
		</div>
	</form>
</div>

<div class="card">
	<h2>Redirect URLs</h2>
	<div style="width:100%;overflow-x:auto;">
	<table style="min-width:100%;table-layout:fixed;">
		<thead>
			<tr>
				<th>ID</th>
				<th>Hits</th>
				<th>Last Hit</th>
				<th>Status</th>
				<th>Link</th>
				<th>Stats</th>
				<th>Analytics</th>
				<th>Actions</th>
			</tr>
		</thead>
		<tbody>
			<?php if (!$redirectLinks): ?>
				<tr><td colspan="8" class="muted">No redirect URLs yet.</td></tr>
			<?php else: ?>
				<?php foreach ($redirectLinks as $redirectLink): ?>
					<?php
					$redirectRowId = (int) ($redirectLink['id'] ?? 0);
					$trackedLink = base_url() . '/link.php?id=' . urlencode((string) $redirectLink['redirect_key']);
					if ($defaultTriggerId !== null && $defaultTriggerId !== '') {
						$trackedLink .= '&trigger=' . urlencode($defaultTriggerId);
					}
					?>
					<tr>
						<td style="word-break:break-word;"><?php echo e((string) $redirectLink['redirect_key']); ?></td>
						<td><?php echo e((string) $redirectLink['total_hits']); ?></td>
						<td><?php echo e(format_db_datetime((string) ($redirectLink['last_hit_at'] ?? ''), 'Y-m-d H:i:s', '-')); ?></td>
						<td><?php echo (int) ($redirectLink['is_active'] ?? 0) === 1 ? 'Active' : 'Inactive'; ?></td>
						<td><button type="button" onclick='copyTextValue(<?php echo json_encode($trackedLink, JSON_HEX_TAG | JSON_HEX_APOS | JSON_HEX_AMP | JSON_HEX_QUOT); ?>, this)'>Copy Link</button></td>
						<td><a class="nav-btn" href="stats.php?source_type=redirect&redirect_key=<?php echo urlencode((string) $redirectLink['redirect_key']); ?>">Open</a></td>
						<td><a class="nav-btn" href="analytics.php?source_type=redirect&redirect_key=<?php echo urlencode((string) $redirectLink['redirect_key']); ?>">Open</a></td>
						<td>
							<div style="position:relative;display:inline-block;">
								<button type="button" aria-label="Actions" onclick="toggleActionMenu('action-menu-<?php echo $redirectRowId; ?>', event)" style="padding:6px 10px;line-height:1;min-width:34px;">&#8942;</button>
								<div id="action-menu-<?php echo $redirectRowId; ?>" class="redirect-action-menu" style="display:none;position:absolute;right:0;top:36px;background:#fff;border:1px solid #ddd;border-radius:6px;box-shadow:0 4px 12px rgba(0,0,0,0.12);min-width:150px;z-index:30;padding:6px;">
									<a href="index.php?edit_redirect_id=<?php echo $redirectRowId; ?>" style="display:block;padding:8px 10px;border-radius:4px;">Edit</a>
									<form method="post" style="margin:0;">
										<input type="hidden" name="action" value="toggle_redirect">
										<input type="hidden" name="redirect_id" value="<?php echo $redirectRowId; ?>">
										<input type="hidden" name="new_state" value="<?php echo (int) ($redirectLink['is_active'] ?? 0) === 1 ? '0' : '1'; ?>">
										<button type="submit" style="display:block;width:100%;text-align:left;background:transparent;color:#1f4ea5;border:0;padding:8px 10px;border-radius:4px;"><?php echo (int) ($redirectLink['is_active'] ?? 0) === 1 ? 'Disable' : 'Enable'; ?></button>
									</form>
									<form method="post" style="margin:0;" onsubmit="return confirm('Delete this redirect URL and all its hits?');">
										<input type="hidden" name="action" value="delete_redirect">
										<input type="hidden" name="redirect_id" value="<?php echo $redirectRowId; ?>">
										<button type="submit" style="display:block;width:100%;text-align:left;background:transparent;color:#8b1e1e;border:0;padding:8px 10px;border-radius:4px;">Delete</button>
									</form>
								</div>
							</div>
						</td>
					</tr>
				<?php endforeach; ?>
			<?php endif; ?>
		</tbody>
	</table>
	</div>
</div>
<script>
function sanitizePixelKeyValue(value) {
	var sanitized = (value || '').trim().toLowerCase();
	sanitized = sanitized.replace(/\s+/g, '_');
	sanitized = sanitized.replace(/[^a-z0-9_]/g, '');
	sanitized = sanitized.replace(/_+/g, '_');
	sanitized = sanitized.replace(/^_+|_+$/g, '');
	return sanitized;
}

function sanitizePixelKeyInput(inputEl) {
	if (!inputEl) {
		return;
	}
	inputEl.value = sanitizePixelKeyValue(inputEl.value);
}

function sanitizeRedirectKeyInput(inputEl) {
	sanitizePixelKeyInput(inputEl);
}

function copyToClipboard(inputId, buttonEl) {
	var input = document.getElementById(inputId);
	if (!input) {
		return;
	}
	input.select();
	input.setSelectionRange(0, 99999);
	var originalText = buttonEl.textContent;
	try {
		var copied = false;
		if (navigator.clipboard && window.isSecureContext) {
			navigator.clipboard.writeText(input.value);
			copied = true;
		} else {
			copied = document.execCommand('copy');
		}
		if (copied) {
			buttonEl.textContent = 'Copied';
			setTimeout(function () { buttonEl.textContent = originalText; }, 1200);
		}
	} catch (e) {
		document.execCommand('copy');
	}
}

function copyTextValue(textValue, buttonEl) {
	var text = (textValue || '').toString();
	if (!text) {
		return;
	}

	var originalText = buttonEl.textContent;
	var copied = false;

	if (navigator.clipboard && window.isSecureContext) {
		navigator.clipboard.writeText(text).then(function () {
			buttonEl.textContent = 'Copied!';
			setTimeout(function () { buttonEl.textContent = originalText; }, 1200);
		}).catch(function () {
			buttonEl.textContent = 'Copy failed';
			setTimeout(function () { buttonEl.textContent = originalText; }, 1200);
		});
		return;
	}

	var tempInput = document.createElement('input');
	tempInput.type = 'text';
	tempInput.value = text;
	tempInput.style.position = 'fixed';
	tempInput.style.opacity = '0';
	document.body.appendChild(tempInput);
	tempInput.focus();
	tempInput.select();
	try {
		copied = document.execCommand('copy');
	} catch (e) {
		copied = false;
	}
	document.body.removeChild(tempInput);

	buttonEl.textContent = copied ? 'Copied!' : 'Copy failed';
	setTimeout(function () { buttonEl.textContent = originalText; }, 1200);
}

function closeActionMenus() {
	var menus = document.querySelectorAll('.redirect-action-menu');
	for (var i = 0; i < menus.length; i++) {
		menus[i].style.display = 'none';
	}
}

function toggleActionMenu(menuId, event) {
	if (event) {
		event.stopPropagation();
	}
	var menu = document.getElementById(menuId);
	if (!menu) {
		return;
	}
	var isVisible = menu.style.display === 'block';
	closeActionMenus();
	menu.style.display = isVisible ? 'none' : 'block';
}

document.addEventListener('click', function () {
	closeActionMenus();
});

var pixelKeyInput = document.getElementById('pixel_key');
if (pixelKeyInput) {
	pixelKeyInput.value = sanitizePixelKeyValue(pixelKeyInput.value);
}

var redirectKeyInput = document.getElementById('redirect_key');
if (redirectKeyInput) {
	redirectKeyInput.value = sanitizePixelKeyValue(redirectKeyInput.value);
}

function filterPixelRows(term) {
	var query = (term || '').toLowerCase().trim();
	var rows = document.querySelectorAll('tr.pixel-row');
	for (var i = 0; i < rows.length; i++) {
		var row = rows[i];
		var pixelKey = (row.getAttribute('data-pixel-key') || '').toLowerCase();
		var isMatch = query === '' || pixelKey.indexOf(query) !== -1;
		row.style.display = isMatch ? '' : 'none';
	}
}

var pixelSearchInput = document.getElementById('pixel-search');
if (pixelSearchInput) {
	pixelSearchInput.addEventListener('paste', function () {
		var self = this;
		setTimeout(function () {
			filterPixelRows(self.value);
		}, 0);
	});
}
</script>
<?php
render_footer();
