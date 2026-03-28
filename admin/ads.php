<?php

declare(strict_types=1);

require __DIR__ . '/../_libraries/core.php';

require_admin();

$admin = current_admin();
$error = null;
$success = flash('success');
$editingRule = null;
$editId = max(0, (int) ($_GET['edit_id'] ?? 0));

$runOncePeriods = [
	3600 => '1 hour',
	21600 => '6 hours',
	43200 => '12 hours',
	86400 => '24 hours',
	604800 => '7 days',
	2592000 => '30 days',
];

$actionTypes = [
	'custom_js' => 'Custom JS',
	'inline_image' => 'Inline picture (URL)',
	'popup_image' => 'Shadow box fullscreen popup image (URL)',
	'popup_text_html' => 'Shadow box fullscreen popup with text (markup/html)',
];

$schemaReady = false;
$schemaMissingParts = [];
try {
	$pdo = db();
	if (!table_exists($pdo, 'pd_ad_rules')) {
		$schemaMissingParts[] = 'table pd_ad_rules';
	} else {
		$requiredColumns = [
			'ad_key',
			'rule_name',
			'priority',
			'match_conditions',
			'custom_js',
			'action_type',
			'action_value',
			'run_once_enabled',
			'run_once_period_seconds',
			'trigger_on_match',
			'trigger_id',
			'is_active',
			'updated_at',
		];
		foreach ($requiredColumns as $requiredColumn) {
			if (!column_exists($pdo, 'pd_ad_rules', $requiredColumn)) {
				$schemaMissingParts[] = 'column pd_ad_rules.' . $requiredColumn;
			}
		}
	}

	if (!table_exists($pdo, 'pd_trigger_actions')) {
		$schemaMissingParts[] = 'table pd_trigger_actions';
	}

	$schemaReady = count($schemaMissingParts) === 0;
} catch (Throwable $e) {
	$schemaMissingParts[] = 'database connection';
	$schemaReady = false;
}

if (!$schemaReady) {
	$error = 'Ads schema is not ready yet. Run migrations to continue. Missing: ' . implode(', ', $schemaMissingParts) . '.';
}

$operatorTags = [];
if ($schemaReady) {
	try {
	$status = analytics_table_status();
	if ((bool) ($status['ip_enrichment'] ?? false)) {
		$tagRows = db()->query(
			"SELECT DISTINCT TRIM(operator_tag) AS operator_tag
			 FROM pd_ip_enrichment
			 WHERE operator_tag IS NOT NULL AND TRIM(operator_tag) <> ''
			 ORDER BY operator_tag ASC"
		)->fetchAll();
		foreach ($tagRows as $tagRow) {
			$tag = trim((string) ($tagRow['operator_tag'] ?? ''));
			if ($tag !== '') {
				$operatorTags[] = $tag;
			}
		}
	}
	} catch (Throwable $e) {
	}
}

if ($schemaReady && $_SERVER['REQUEST_METHOD'] === 'POST') {
	$action = (string) ($_POST['action'] ?? '');

	try {
		if ($action === 'save_rule') {
			$ruleId = max(0, (int) ($_POST['rule_id'] ?? 0));
			$adKey = sanitize_ad_key((string) ($_POST['ad_key'] ?? ''));
			$ruleName = trim((string) ($_POST['rule_name'] ?? ''));
			$priority = (int) ($_POST['priority'] ?? 100);
			$isActive = isset($_POST['is_active']) ? 1 : 0;

			$actionType = trim((string) ($_POST['action_type'] ?? 'custom_js'));
			$actionValue = trim((string) ($_POST['action_value'] ?? ''));
			$customJs = trim((string) ($_POST['custom_js'] ?? ''));
			if (!array_key_exists($actionType, $actionTypes)) {
				$actionType = 'custom_js';
			}

			$runOnceEnabled = isset($_POST['run_once_enabled']) ? 1 : 0;
			$runOncePeriodSeconds = (int) ($_POST['run_once_period_seconds'] ?? 0);

			$triggerOnMatch = isset($_POST['trigger_on_match']) ? 1 : 0;
			$triggerId = normalize_trigger_id((string) ($_POST['trigger_id'] ?? ''));

			$conditions = normalize_ad_match_conditions([
				'traffic_type' => (string) ($_POST['traffic_type'] ?? ''),
				'user_agent_op' => (string) ($_POST['user_agent_op'] ?? 'equals'),
				'user_agent_value' => (string) ($_POST['user_agent_value'] ?? ''),
				'ip_address_op' => (string) ($_POST['ip_address_op'] ?? 'equals'),
				'ip_address_value' => (string) ($_POST['ip_address_value'] ?? ''),
				'operator_tag' => (string) ($_POST['operator_tag'] ?? ''),
				'country_code_op' => (string) ($_POST['country_code_op'] ?? 'equals'),
				'country_code_value' => (string) ($_POST['country_code_value'] ?? ''),
				'region_op' => (string) ($_POST['region_op'] ?? 'equals'),
				'region_value' => (string) ($_POST['region_value'] ?? ''),
				'city_op' => (string) ($_POST['city_op'] ?? 'equals'),
				'city_value' => (string) ($_POST['city_value'] ?? ''),
				'asn_op' => 'equals',
				'asn_value' => (string) ($_POST['asn_value'] ?? ''),
				'asn_org_op' => (string) ($_POST['asn_org_op'] ?? 'equals'),
				'asn_org_value' => (string) ($_POST['asn_org_value'] ?? ''),
				'isp_name_op' => (string) ($_POST['isp_name_op'] ?? 'equals'),
				'isp_name_value' => (string) ($_POST['isp_name_value'] ?? ''),
				'reverse_host_op' => (string) ($_POST['reverse_host_op'] ?? 'equals'),
				'reverse_host_value' => (string) ($_POST['reverse_host_value'] ?? ''),
			]);

			if ($adKey === '' || !preg_match('/^[a-z0-9_-]{2,191}$/', $adKey)) {
				throw new RuntimeException('Ad ID must be 2-191 chars and use only letters, numbers, underscore, or dash.');
			}

			if ($ruleName === '') {
				throw new RuntimeException('Rule name is required.');
			}

			if ($priority < -9999) {
				$priority = -9999;
			} elseif ($priority > 9999) {
				$priority = 9999;
			}

			if ($actionType === 'custom_js') {
				if ($customJs === '') {
					throw new RuntimeException('Custom JS is required when action type is Custom JS.');
				}
				$actionValue = '';
			} elseif ($actionType === 'inline_image' || $actionType === 'popup_image') {
				if ($actionValue === '' || !filter_var($actionValue, FILTER_VALIDATE_URL)) {
					throw new RuntimeException('A valid image URL is required for selected action type.');
				}
			} elseif ($actionType === 'popup_text_html') {
				if ($actionValue === '') {
					throw new RuntimeException('Markup/HTML is required for popup text action.');
				}
			}

			if ($runOnceEnabled === 1) {
				if (!array_key_exists($runOncePeriodSeconds, $runOncePeriods)) {
					throw new RuntimeException('Select a valid time period for Run once option.');
				}
			} else {
				$runOncePeriodSeconds = 0;
			}

			if ($triggerOnMatch === 1) {
				if ($triggerId === '') {
					throw new RuntimeException('Select a trigger when Trigger on match is enabled.');
				}
				$triggerExistsStmt = db()->prepare('SELECT id FROM pd_trigger_actions WHERE trigger_id = :trigger_id AND is_active = 1 LIMIT 1');
				$triggerExistsStmt->execute(['trigger_id' => $triggerId]);
				if (!$triggerExistsStmt->fetch()) {
					throw new RuntimeException('Selected trigger is missing or inactive.');
				}
			} else {
				$triggerId = '';
			}

			$conditionsJson = json_encode($conditions, JSON_UNESCAPED_SLASHES);
			if (!is_string($conditionsJson)) {
				$conditionsJson = '{}';
			}

			if ($ruleId > 0) {
				$stmt = db()->prepare(
					'UPDATE pd_ad_rules
					 SET ad_key = :ad_key,
					     rule_name = :rule_name,
					     priority = :priority,
					     match_conditions = :match_conditions,
					     custom_js = :custom_js,
					     action_type = :action_type,
					     action_value = :action_value,
					     run_once_enabled = :run_once_enabled,
					     run_once_period_seconds = :run_once_period_seconds,
					     trigger_on_match = :trigger_on_match,
					     trigger_id = :trigger_id,
					     is_active = :is_active,
					     updated_at = NOW()
					 WHERE id = :id'
				);
				$stmt->execute([
					'ad_key' => $adKey,
					'rule_name' => $ruleName,
					'priority' => $priority,
					'match_conditions' => $conditionsJson,
					'custom_js' => $customJs,
					'action_type' => $actionType,
					'action_value' => $actionValue !== '' ? $actionValue : null,
					'run_once_enabled' => $runOnceEnabled,
					'run_once_period_seconds' => $runOnceEnabled === 1 ? $runOncePeriodSeconds : null,
					'trigger_on_match' => $triggerOnMatch,
					'trigger_id' => $triggerOnMatch === 1 ? $triggerId : null,
					'is_active' => $isActive,
					'id' => $ruleId,
				]);

				if ($runOnceEnabled === 1) {
					try {
						$clearRunOnceStmt = db()->prepare('DELETE FROM pd_ad_hit_logs WHERE matched_rule_id = :rule_id');
						$clearRunOnceStmt->execute(['rule_id' => $ruleId]);
					} catch (Throwable $e) {
					}
				}

				flash('success', 'Ad rule updated.');
			} else {
				$stmt = db()->prepare(
					'INSERT INTO pd_ad_rules
					 (ad_key, rule_name, priority, match_conditions, custom_js, action_type, action_value, run_once_enabled, run_once_period_seconds, trigger_on_match, trigger_id, is_active, created_by, created_at, updated_at)
					 VALUES
					 (:ad_key, :rule_name, :priority, :match_conditions, :custom_js, :action_type, :action_value, :run_once_enabled, :run_once_period_seconds, :trigger_on_match, :trigger_id, :is_active, :created_by, NOW(), NOW())'
				);
				$stmt->execute([
					'ad_key' => $adKey,
					'rule_name' => $ruleName,
					'priority' => $priority,
					'match_conditions' => $conditionsJson,
					'custom_js' => $customJs,
					'action_type' => $actionType,
					'action_value' => $actionValue !== '' ? $actionValue : null,
					'run_once_enabled' => $runOnceEnabled,
					'run_once_period_seconds' => $runOnceEnabled === 1 ? $runOncePeriodSeconds : null,
					'trigger_on_match' => $triggerOnMatch,
					'trigger_id' => $triggerOnMatch === 1 ? $triggerId : null,
					'is_active' => $isActive,
					'created_by' => (int) ($admin['id'] ?? 0),
				]);
				flash('success', 'Ad rule created.');
			}

			redirect('ads.php');
		}

		if ($action === 'delete_rule') {
			$ruleId = max(0, (int) ($_POST['rule_id'] ?? 0));
			if ($ruleId < 1) {
				throw new RuntimeException('Invalid rule selected.');
			}

			$deleteStmt = db()->prepare('DELETE FROM pd_ad_rules WHERE id = :id');
			$deleteStmt->execute(['id' => $ruleId]);
			flash('success', 'Ad rule deleted.');
			redirect('ads.php');
		}
	} catch (Throwable $e) {
		$error = $e->getMessage();
	}
}

if ($schemaReady && $editId > 0) {
	$editStmt = db()->prepare('SELECT * FROM pd_ad_rules WHERE id = :id LIMIT 1');
	$editStmt->execute(['id' => $editId]);
	$editingRule = $editStmt->fetch();
}


$activeTriggers = [];
if ($schemaReady) {
	try {
		$activeTriggers = db()->query(
			'SELECT trigger_id, name
			 FROM pd_trigger_actions
			 WHERE is_active = 1
			 ORDER BY trigger_id ASC'
		)->fetchAll();
	} catch (Throwable $e) {
		$error = $error ?? ('Unable to load triggers: ' . $e->getMessage());
	}
}

$rules = [];
if ($schemaReady) {
	try {
		$rules = db()->query(
			'SELECT id, ad_key, rule_name, priority, match_conditions, custom_js, action_type, action_value, run_once_enabled, run_once_period_seconds, trigger_on_match, trigger_id, is_active, updated_at
			 FROM pd_ad_rules
			 ORDER BY ad_key ASC, priority ASC, id ASC'
		)->fetchAll();
	} catch (Throwable $e) {
		$error = $error ?? ('Unable to load ad rules: ' . $e->getMessage());
	}
}

$editingConditions = normalize_ad_match_conditions((array) decode_ad_match_conditions((string) ($editingRule['match_conditions'] ?? '')));

$editingActionType = trim((string) ($editingRule['action_type'] ?? 'custom_js'));
if (!array_key_exists($editingActionType, $actionTypes)) {
	$editingActionType = 'custom_js';
}
$editingActionValue = (string) ($editingRule['action_value'] ?? '');
$editingCustomJs = (string) ($editingRule['custom_js'] ?? '');

$op = static function (array $conditions, string $field, string $default = 'equals'): string {
	$rule = $conditions[$field] ?? null;
	if (!is_array($rule)) {
		return $default;
	}
	$operator = trim((string) ($rule['op'] ?? $default));
	return $operator !== '' ? $operator : $default;
};
$val = static function (array $conditions, string $field): string {
	$rule = $conditions[$field] ?? null;
	if (!is_array($rule)) {
		return '';
	}
	return trim((string) ($rule['value'] ?? ''));
};

render_header('Targeted Advertising');
?>
<div class="spaced card">
	<div>
		<h1>Targeted Advertising</h1>
		<p class="muted">Define match rules and choose how ad.js responds.</p>
	</div>
	<div class="inline">
		<a class="nav-btn" href="index.php">Back to dashboard</a>
		<a class="nav-btn" href="ad-analytics.php">Ad analytics</a>
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
	<div class="card">
		<h2>Migration Required</h2>
		<p class="muted">The targeted ads schema is missing required columns/tables.</p>
		<p><a class="nav-btn" href="../migrate.php">Run migrations</a></p>
	</div>
	<?php render_footer(); return; ?>
<?php endif; ?>

<div class="card">
	<h2><?php echo $editingRule ? 'Edit Ad Rule' : 'Create Ad Rule'; ?></h2>
	<form method="post">
		<input type="hidden" name="action" value="save_rule">
		<input type="hidden" name="rule_id" value="<?php echo e((string) ($editingRule['id'] ?? 0)); ?>">

		<div class="row">
			<div>
				<label>Ad ID (for ad.js?id=...)</label>
				<input type="text" name="ad_key" maxlength="191" required value="<?php echo e((string) ($editingRule['ad_key'] ?? '')); ?>" placeholder="homepage_banner">
			</div>
			<div>
				<label>Rule Name</label>
				<input type="text" name="rule_name" maxlength="191" required value="<?php echo e((string) ($editingRule['rule_name'] ?? '')); ?>" placeholder="Homepage traffic match">
			</div>
			<div>
				<label>Priority (lower runs first)</label>
				<input type="number" name="priority" value="<?php echo e((string) ((int) ($editingRule['priority'] ?? 100))); ?>" min="-9999" max="9999">
			</div>
		</div>

		<h3>Match Conditions</h3>
		<p class="muted">All match conditions are optional. Leave a value blank to treat it as Any.</p>
		<div style="overflow-x:auto;">
			<table style="min-width:900px;">
				<thead>
				<tr>
					<th>Field</th>
					<th>Operator</th>
					<th>Value</th>
					<th>Notes</th>
				</tr>
				</thead>
				<tbody>
				<tr>
					<td>traffic_type</td>
					<td>equals</td>
					<td>
						<select name="traffic_type">
							<option value="">Any</option>
							<option value="human" <?php echo $val($editingConditions, 'traffic_type') === 'human' ? 'selected' : ''; ?>>human</option>
							<option value="proxy" <?php echo $val($editingConditions, 'traffic_type') === 'proxy' ? 'selected' : ''; ?>>proxy</option>
						</select>
					</td>
					<td class="muted">Matches inferred traffic classification.</td>
				</tr>
				<tr>
					<td>user_agent</td>
					<td>
						<select name="user_agent_op">
							<option value="equals" <?php echo $op($editingConditions, 'user_agent') === 'equals' ? 'selected' : ''; ?>>equals</option>
							<option value="like" <?php echo $op($editingConditions, 'user_agent') === 'like' ? 'selected' : ''; ?>>LIKE</option>
						</select>
					</td>
					<td><input type="text" name="user_agent_value" maxlength="255" value="<?php echo e($val($editingConditions, 'user_agent')); ?>" placeholder="Mozilla/5.0 or %iPhone%"></td>
					<td class="muted">Match browser/client user-agent string.</td>
				</tr>
				<tr>
					<td>ip_address</td>
					<td>
						<select name="ip_address_op">
							<option value="equals" <?php echo $op($editingConditions, 'ip_address') === 'equals' ? 'selected' : ''; ?>>equals</option>
							<option value="like" <?php echo $op($editingConditions, 'ip_address') === 'like' ? 'selected' : ''; ?>>LIKE</option>
						</select>
					</td>
					<td><input type="text" name="ip_address_value" maxlength="191" value="<?php echo e($val($editingConditions, 'ip_address')); ?>" placeholder="76.8.147.84 or 76.8.%"></td>
					<td class="muted">Use exact IP or pattern when using LIKE.</td>
				</tr>
				<tr>
					<td>operator_tag</td>
					<td>equals</td>
					<td>
						<select name="operator_tag">
							<option value="">Any</option>
							<?php foreach ($operatorTags as $tag): ?>
								<option value="<?php echo e($tag); ?>" <?php echo $val($editingConditions, 'operator_tag') === $tag ? 'selected' : ''; ?>><?php echo e($tag); ?></option>
							<?php endforeach; ?>
						</select>
					</td>
					<td class="muted"><?php echo $operatorTags ? 'Values come from saved IP operator tags.' : 'No operator tags found yet.'; ?></td>
				</tr>
				<tr>
					<td>country_code</td>
					<td>
						<select name="country_code_op">
							<option value="equals" <?php echo $op($editingConditions, 'country_code') === 'equals' ? 'selected' : ''; ?>>equals</option>
							<option value="like" <?php echo $op($editingConditions, 'country_code') === 'like' ? 'selected' : ''; ?>>LIKE</option>
						</select>
					</td>
					<td><input type="text" name="country_code_value" maxlength="2" value="<?php echo e($val($editingConditions, 'country_code')); ?>" placeholder="US"></td>
					<td class="muted">2-letter country code.</td>
				</tr>
				<tr>
					<td>region</td>
					<td>
						<select name="region_op">
							<option value="equals" <?php echo $op($editingConditions, 'region') === 'equals' ? 'selected' : ''; ?>>equals</option>
							<option value="like" <?php echo $op($editingConditions, 'region') === 'like' ? 'selected' : ''; ?>>LIKE</option>
						</select>
					</td>
					<td><input type="text" name="region_value" maxlength="120" value="<?php echo e($val($editingConditions, 'region')); ?>" placeholder="Missouri"></td>
					<td class="muted">Region/state from enrichment data.</td>
				</tr>
				<tr>
					<td>city</td>
					<td>
						<select name="city_op">
							<option value="equals" <?php echo $op($editingConditions, 'city') === 'equals' ? 'selected' : ''; ?>>equals</option>
							<option value="like" <?php echo $op($editingConditions, 'city') === 'like' ? 'selected' : ''; ?>>LIKE</option>
						</select>
					</td>
					<td><input type="text" name="city_value" maxlength="120" value="<?php echo e($val($editingConditions, 'city')); ?>" placeholder="Brookfield"></td>
					<td class="muted">City from enrichment data.</td>
				</tr>
				<tr>
					<td>asn</td>
					<td>equals</td>
					<td><input type="text" name="asn_value" maxlength="20" value="<?php echo e($val($editingConditions, 'asn')); ?>" placeholder="AS54579"></td>
					<td class="muted">Exact ASN match only.</td>
				</tr>
				<tr>
					<td>asn_org</td>
					<td>
						<select name="asn_org_op">
							<option value="equals" <?php echo $op($editingConditions, 'asn_org') === 'equals' ? 'selected' : ''; ?>>equals</option>
							<option value="like" <?php echo $op($editingConditions, 'asn_org') === 'like' ? 'selected' : ''; ?>>LIKE</option>
						</select>
					</td>
					<td><input type="text" name="asn_org_value" maxlength="255" value="<?php echo e($val($editingConditions, 'asn_org')); ?>" placeholder="Air Link"></td>
					<td class="muted">Organization name tied to ASN.</td>
				</tr>
				<tr>
					<td>isp_name</td>
					<td>
						<select name="isp_name_op">
							<option value="equals" <?php echo $op($editingConditions, 'isp_name') === 'equals' ? 'selected' : ''; ?>>equals</option>
							<option value="like" <?php echo $op($editingConditions, 'isp_name') === 'like' ? 'selected' : ''; ?>>LIKE</option>
						</select>
					</td>
					<td><input type="text" name="isp_name_value" maxlength="255" value="<?php echo e($val($editingConditions, 'isp_name')); ?>" placeholder="Chariton Valley"></td>
					<td class="muted">ISP/provider name from enrichment data.</td>
				</tr>
				<tr>
					<td>reverse_host</td>
					<td>
						<select name="reverse_host_op">
							<option value="equals" <?php echo $op($editingConditions, 'reverse_host') === 'equals' ? 'selected' : ''; ?>>equals</option>
							<option value="like" <?php echo $op($editingConditions, 'reverse_host') === 'like' ? 'selected' : ''; ?>>LIKE</option>
						</select>
					</td>
					<td><input type="text" name="reverse_host_value" maxlength="255" value="<?php echo e($val($editingConditions, 'reverse_host')); ?>" placeholder="mail.example.com or %.example.com"></td>
					<td class="muted">Reverse DNS hostname (if available).</td>
				</tr>
				</tbody>
			</table>
		</div>

		<h3>Action</h3>
		<p>
			<label>Javascript action type</label>
			<select name="action_type" id="action_type">
				<?php foreach ($actionTypes as $typeKey => $typeLabel): ?>
					<option value="<?php echo e($typeKey); ?>" <?php echo $editingActionType === $typeKey ? 'selected' : ''; ?>><?php echo e($typeLabel); ?></option>
				<?php endforeach; ?>
			</select>
		</p>
		<p id="action_value_wrap" style="display:<?php echo $editingActionType === 'custom_js' ? 'none' : 'block'; ?>;">
			<label id="action_value_label">Action value (URL or HTML)</label>
			<textarea name="action_value" id="action_value" rows="6" style="width:100%;padding:8px;border:1px solid #bbb;border-radius:4px;box-sizing:border-box;font-family:monospace;"><?php echo e($editingActionValue); ?></textarea>
		</p>
		<p id="custom_js_wrap" style="display:<?php echo $editingActionType === 'custom_js' ? 'block' : 'none'; ?>;">
			<label>Custom JS</label>
			<textarea name="custom_js" id="custom_js" rows="10" style="width:100%;padding:8px;border:1px solid #bbb;border-radius:4px;box-sizing:border-box;font-family:monospace;"><?php echo e($editingCustomJs); ?></textarea>
		</p>
		<p class="inline">
			<button type="button" id="test_action_button">Test JS</button>
			<span id="test_action_status" class="muted"></span>
		</p>

		<p>
			<label><input type="checkbox" id="run_once_enabled" name="run_once_enabled" value="1" style="width:auto;" <?php echo ((int) ($editingRule['run_once_enabled'] ?? 0) === 1) ? 'checked' : ''; ?>> Run once in time period?</label>
		</p>
		<p id="run_once_period_wrap" style="display:<?php echo ((int) ($editingRule['run_once_enabled'] ?? 0) === 1) ? 'block' : 'none'; ?>;">
			<label>Time period</label>
			<select name="run_once_period_seconds" id="run_once_period_seconds">
				<option value="">Select period</option>
				<?php foreach ($runOncePeriods as $periodSeconds => $periodLabel): ?>
					<option value="<?php echo e((string) $periodSeconds); ?>" <?php echo (int) ($editingRule['run_once_period_seconds'] ?? 0) === $periodSeconds ? 'selected' : ''; ?>><?php echo e($periodLabel); ?></option>
				<?php endforeach; ?>
			</select>
		</p>

		<p>
			<label><input type="checkbox" id="trigger_on_match" name="trigger_on_match" value="1" style="width:auto;" <?php echo ((int) ($editingRule['trigger_on_match'] ?? 0) === 1) ? 'checked' : ''; ?>> Trigger on match?</label>
		</p>
		<p id="trigger_select_wrap" style="display:<?php echo ((int) ($editingRule['trigger_on_match'] ?? 0) === 1) ? 'block' : 'none'; ?>;">
			<label>Select Trigger</label>
			<select name="trigger_id" id="trigger_id">
				<option value="">Select trigger</option>
				<?php foreach ($activeTriggers as $trigger): ?>
					<option value="<?php echo e((string) $trigger['trigger_id']); ?>" <?php echo ((string) ($editingRule['trigger_id'] ?? '') === (string) $trigger['trigger_id']) ? 'selected' : ''; ?>><?php echo e((string) $trigger['trigger_id']); ?> - <?php echo e((string) $trigger['name']); ?></option>
				<?php endforeach; ?>
			</select>
		</p>

		<p>
			<label><input type="checkbox" name="is_active" value="1" style="width:auto;" <?php echo (!isset($editingRule['is_active']) || (int) ($editingRule['is_active'] ?? 0) === 1) ? 'checked' : ''; ?>> Rule is active</label>
		</p>

		<p class="inline">
			<button type="submit">Save Rule</button>
			<?php if ($editingRule): ?><a class="nav-btn" href="ads.php">Cancel Edit</a><?php endif; ?>
		</p>
	</form>
</div>

<div class="card">
	<h2>Rules</h2>
	<table>
		<thead>
		<tr>
			<th>Ad ID</th>
			<th>Rule</th>
			<th>Priority</th>
			<th>Action</th>
			<th>Run Once</th>
			<th>Trigger</th>
			<th>Status</th>
			<th>Updated</th>
			<th>Embed</th>
			<th>Analytics</th>
			<th>Actions</th>
		</tr>
		</thead>
		<tbody>
		<?php if (!$rules): ?>
			<tr><td colspan="11" class="muted">No ad rules yet.</td></tr>
		<?php else: ?>
			<?php foreach ($rules as $row): ?>
				<?php $embedUrl = base_url() . '/ad.js?id=' . urlencode((string) $row['ad_key']); ?>
				<?php
				$runOnceSeconds = (int) ($row['run_once_period_seconds'] ?? 0);
				$runOnceLabel = '-';
				if ((int) ($row['run_once_enabled'] ?? 0) === 1 && isset($runOncePeriods[$runOnceSeconds])) {
					$runOnceLabel = $runOncePeriods[$runOnceSeconds];
				}
				$rowActionType = trim((string) ($row['action_type'] ?? 'custom_js'));
				$rowActionLabel = $actionTypes[$rowActionType] ?? $rowActionType;
				?>
				<tr>
					<td><?php echo e((string) $row['ad_key']); ?></td>
					<td><?php echo e((string) $row['rule_name']); ?></td>
					<td><?php echo e((string) ((int) ($row['priority'] ?? 100))); ?></td>
					<td><?php echo e($rowActionLabel); ?></td>
					<td><?php echo e($runOnceLabel); ?></td>
					<td><?php echo (int) ($row['trigger_on_match'] ?? 0) === 1 ? e((string) ($row['trigger_id'] ?? '-')) : '-'; ?></td>
					<td><?php echo (int) ($row['is_active'] ?? 0) === 1 ? 'Active' : 'Inactive'; ?></td>
					<td><?php echo e(format_db_datetime((string) ($row['updated_at'] ?? ''), 'Y-m-d H:i:s', '-')); ?></td>
					<td><input readonly onclick="this.select()" value="<?php echo e('<script src=\'' . $embedUrl . '\'></script>'); ?>"></td>
					<td><a class="nav-btn" href="ad-analytics.php?ad_key=<?php echo urlencode((string) $row['ad_key']); ?>">View</a></td>
					<td>
						<div class="inline">
							<a class="nav-btn" href="ads.php?edit_id=<?php echo (int) $row['id']; ?>">Edit</a>
							<form method="post" style="margin:0;" onsubmit="return confirm('Delete this ad rule?');">
								<input type="hidden" name="action" value="delete_rule">
								<input type="hidden" name="rule_id" value="<?php echo (int) $row['id']; ?>">
								<button type="submit">Delete</button>
							</form>
						</div>
					</td>
				</tr>
			<?php endforeach; ?>
		<?php endif; ?>
		</tbody>
	</table>
</div>

<script>
(function () {
	var runOnceCheckbox = document.getElementById('run_once_enabled');
	var runOnceWrap = document.getElementById('run_once_period_wrap');
	var runOnceSelect = document.getElementById('run_once_period_seconds');
	var triggerCheckbox = document.getElementById('trigger_on_match');
	var triggerWrap = document.getElementById('trigger_select_wrap');
	var triggerSelect = document.getElementById('trigger_id');
	var actionType = document.getElementById('action_type');
	var actionValueWrap = document.getElementById('action_value_wrap');
	var actionValueLabel = document.getElementById('action_value_label');
	var actionValue = document.getElementById('action_value');
	var customJsWrap = document.getElementById('custom_js_wrap');
	var customJs = document.getElementById('custom_js');
	var testActionButton = document.getElementById('test_action_button');
	var testActionStatus = document.getElementById('test_action_status');

	if (!runOnceCheckbox || !runOnceWrap || !runOnceSelect || !triggerCheckbox || !triggerWrap || !triggerSelect || !actionType || !actionValueWrap || !actionValueLabel || !actionValue || !customJsWrap || !customJs || !testActionButton || !testActionStatus) {
		return;
	}

	var syncRunOnce = function () {
		var enabled = runOnceCheckbox.checked;
		runOnceWrap.style.display = enabled ? 'block' : 'none';
		runOnceSelect.required = enabled;
		if (!enabled) {
			runOnceSelect.value = '';
		}
	};

	var syncTrigger = function () {
		var enabled = triggerCheckbox.checked;
		triggerWrap.style.display = enabled ? 'block' : 'none';
		triggerSelect.required = enabled;
		if (!enabled) {
			triggerSelect.value = '';
		}
	};

	var syncAction = function () {
		var type = actionType.value || 'custom_js';
		var isCustom = type === 'custom_js';
		customJsWrap.style.display = isCustom ? 'block' : 'none';
		actionValueWrap.style.display = isCustom ? 'none' : 'block';
		customJs.required = isCustom;
		actionValue.required = !isCustom;

		if (type === 'inline_image') {
			actionValueLabel.textContent = 'Inline picture URL';
		} else if (type === 'popup_image') {
			actionValueLabel.textContent = 'Fullscreen popup image URL';
		} else if (type === 'popup_text_html') {
			actionValueLabel.textContent = 'Fullscreen popup text (markup/html)';
		} else {
			actionValueLabel.textContent = 'Action value';
		}
	};

	var clearTestOverlay = function () {
		var existing = document.getElementById('pd-ad-test-overlay');
		if (existing) {
			existing.remove();
		}
	};

	var showStatus = function (message, isError) {
		testActionStatus.textContent = message;
		testActionStatus.style.color = isError ? '#7f1d1d' : '#666';
	};

	var runActionTest = function () {
		clearTestOverlay();
		showStatus('', false);

		var type = actionType.value || 'custom_js';
		var value = (actionValue.value || '').trim();
		var jsCode = (customJs.value || '').trim();

		try {
			if (type === 'custom_js') {
				if (!jsCode) {
					showStatus('Custom JS is empty.', true);
					return;
				}
				(new Function(jsCode))();
				showStatus('Custom JS executed.', false);
				return;
			}

			if (type === 'inline_image') {
				if (!value) {
					showStatus('Image URL is required.', true);
					return;
				}
				var img = document.createElement('img');
				img.src = value;
				img.alt = '';
				img.style.maxWidth = '100%';
				img.style.height = 'auto';
				img.style.display = 'block';
				img.style.margin = '12px auto';
				(document.body || document.documentElement).appendChild(img);
				showStatus('Inline image inserted into page.', false);
				return;
			}

			if (type === 'popup_image' || type === 'popup_text_html') {
				if (!value) {
					showStatus(type === 'popup_image' ? 'Image URL is required.' : 'Popup markup/html is required.', true);
					return;
				}

				var overlay = document.createElement('div');
				overlay.id = 'pd-ad-test-overlay';
				overlay.style.position = 'fixed';
				overlay.style.inset = '0';
				overlay.style.background = 'rgba(0,0,0,.75)';
				overlay.style.display = 'flex';
				overlay.style.alignItems = 'center';
				overlay.style.justifyContent = 'center';
				overlay.style.zIndex = '2147483647';

				if (type === 'popup_image') {
					var popupImg = document.createElement('img');
					popupImg.src = value;
					popupImg.alt = '';
					popupImg.style.maxWidth = '92vw';
					popupImg.style.maxHeight = '92vh';
					popupImg.style.boxShadow = '0 16px 40px rgba(0,0,0,.45)';
					popupImg.style.borderRadius = '8px';
					popupImg.style.background = '#fff';
					popupImg.style.padding = '6px';
					overlay.appendChild(popupImg);
				} else {
					var box = document.createElement('div');
					box.style.width = 'min(92vw, 700px)';
					box.style.height = 'min(70vh, 450px)';
					box.style.maxWidth = '92vw';
					box.style.maxHeight = '70vh';
					box.style.overflow = 'auto';
					box.style.background = '#f3f4f6';
					box.style.color = '#111';
					box.style.padding = '20px';
					box.style.borderRadius = '10px';
					box.style.boxShadow = '0 16px 40px rgba(0,0,0,.45)';
					box.innerHTML = value;
					overlay.appendChild(box);
				}

				overlay.addEventListener('click', function (event) {
					if (event.target === overlay) {
						overlay.remove();
					}
				});
				(document.body || document.documentElement).appendChild(overlay);
				showStatus('Popup preview opened. Click outside to close.', false);
				return;
			}

			showStatus('Unsupported action type selected.', true);
		} catch (error) {
			showStatus('Test failed: ' + (error && error.message ? error.message : 'Unknown error'), true);
		}
	};

	runOnceCheckbox.addEventListener('change', syncRunOnce);
	triggerCheckbox.addEventListener('change', syncTrigger);
	actionType.addEventListener('change', syncAction);
	testActionButton.addEventListener('click', runActionTest);

	syncRunOnce();
	syncTrigger();
	syncAction();
})();
</script>
<?php
render_footer();
