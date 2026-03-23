<?php

declare(strict_types=1);

require __DIR__ . '/../_libraries/core.php';

require_admin();

$admin = current_admin();
$error = null;
$success = flash('success');

$editingTrigger = null;
$editId = (int) ($_GET['edit_id'] ?? 0);

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
	$action = (string) ($_POST['action'] ?? '');

	try {
		if ($action === 'save_trigger') {
			$triggerId = normalize_trigger_id((string) ($_POST['trigger_id'] ?? ''));
			$name = trim((string) ($_POST['name'] ?? ''));
			$webhookUrl = trim((string) ($_POST['webhook_url'] ?? ''));
			$payloadTemplate = trim((string) ($_POST['payload_template'] ?? ''));
			$isActive = isset($_POST['is_active']) ? 1 : 0;
			$isDefault = isset($_POST['is_default']) ? 1 : 0;
			$triggerDbId = (int) ($_POST['trigger_db_id'] ?? 0);

			if ($isActive === 0) {
				$isDefault = 0;
			} elseif ($isDefault === 1) {
				$isActive = 1;
			}

			if ($triggerId === '' || $name === '' || $webhookUrl === '') {
				throw new RuntimeException('Trigger ID, Name, and Webhook URL are required.');
			}

			if (!preg_match('/^[A-Za-z0-9_-]{2,191}$/', $triggerId)) {
				throw new RuntimeException('Trigger ID must use only letters, numbers, underscore, or dash.');
			}

			if (!filter_var($webhookUrl, FILTER_VALIDATE_URL)) {
				throw new RuntimeException('Webhook URL is invalid.');
			}

			if ($triggerDbId > 0) {
				db()->beginTransaction();
				$update = db()->prepare(
					'UPDATE pd_trigger_actions
					 SET trigger_id = :trigger_id,
					     name = :name,
					     webhook_url = :webhook_url,
					     payload_template = :payload_template,
					     is_active = :is_active,
					     is_default = :is_default,
					     updated_at = NOW()
					 WHERE id = :id'
				);
				$update->execute([
					'trigger_id' => $triggerId,
					'name' => $name,
					'webhook_url' => $webhookUrl,
					'payload_template' => $payloadTemplate,
					'is_active' => $isActive,
					'is_default' => $isDefault,
					'id' => $triggerDbId,
				]);

				if ($isDefault === 1) {
					$clearDefault = db()->prepare('UPDATE pd_trigger_actions SET is_default = 0 WHERE id <> :id');
					$clearDefault->execute(['id' => $triggerDbId]);
				}

				db()->commit();
				flash('success', 'Trigger updated: ' . $triggerId);
			} else {
				db()->beginTransaction();
				$insert = db()->prepare(
					'INSERT INTO pd_trigger_actions
					 (trigger_id, name, webhook_url, payload_template, is_active, is_default, created_by, created_at, updated_at)
					 VALUES
					 (:trigger_id, :name, :webhook_url, :payload_template, :is_active, :is_default, :created_by, NOW(), NOW())'
				);
				$insert->execute([
					'trigger_id' => $triggerId,
					'name' => $name,
					'webhook_url' => $webhookUrl,
					'payload_template' => $payloadTemplate,
					'is_active' => $isActive,
					'is_default' => $isDefault,
					'created_by' => (int) ($admin['id'] ?? 0),
				]);

				$newTriggerId = (int) db()->lastInsertId();
				if ($isDefault === 1) {
					$clearDefault = db()->prepare('UPDATE pd_trigger_actions SET is_default = 0 WHERE id <> :id');
					$clearDefault->execute(['id' => $newTriggerId]);
				}

				db()->commit();
				flash('success', 'Trigger created: ' . $triggerId);
			}

			redirect('triggers.php');
		}

		if ($action === 'delete_trigger') {
			$triggerDbId = (int) ($_POST['trigger_db_id'] ?? 0);
			if ($triggerDbId < 1) {
				throw new RuntimeException('Invalid trigger selected.');
			}

			$deleteTrigger = db()->prepare('DELETE FROM pd_trigger_actions WHERE id = :id');
			$deleteTrigger->execute(['id' => $triggerDbId]);

			flash('success', 'Trigger deleted.');
			redirect('triggers.php');
		}
	} catch (Throwable $e) {
		if (db()->inTransaction()) {
			db()->rollBack();
		}
		$error = $e->getMessage();
	}
}

if ($editId > 0) {
	$editStmt = db()->prepare('SELECT * FROM pd_trigger_actions WHERE id = :id LIMIT 1');
	$editStmt->execute(['id' => $editId]);
	$editingTrigger = $editStmt->fetch();
}

$triggers = db()->query(
	'SELECT id, trigger_id, name, webhook_url, payload_template, is_active, is_default, created_at, updated_at
	 FROM pd_trigger_actions
	 ORDER BY updated_at DESC, id DESC'
)->fetchAll();

$defaultPayloadTemplate = '{"event":"pixel_loaded","pixel_id":"{{pixel_id}}","hits":"{{hits}}","trigger_id":"{{trigger_id}}","hit_at":"{{hit_at}}","ip_address":"{{ip_address}}","user_agent":"{{user_agent}}"}';
$rawPayloadTemplate = (string) ($editingTrigger['payload_template'] ?? $defaultPayloadTemplate);
$decodedPayloadTemplate = json_decode($rawPayloadTemplate, true);
if (is_array($decodedPayloadTemplate)) {
	$prettyPayloadTemplate = json_encode($decodedPayloadTemplate, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
	$payloadTemplateForTextarea = is_string($prettyPayloadTemplate) ? $prettyPayloadTemplate : $rawPayloadTemplate;
} else {
	$payloadTemplateForTextarea = $rawPayloadTemplate;
}

render_header('Trigger Actions');
?>
<div class="spaced card">
	<div>
		<h1>Trigger Actions</h1>
		<p class="muted">Create reusable webhook trigger templates and invoke them per pixel load.</p>
	</div>
	<div class="inline">
		<a class="nav-btn" href="index.php">Back to dashboard</a>
		<a class="nav-btn logout" href="../logout.php">Logout</a>
	</div>
</div>

<?php if ($success): ?>
	<div class="success"><?php echo e($success); ?></div>
<?php endif; ?>
<?php if ($error): ?>
	<div class="error"><?php echo e($error); ?></div>
<?php endif; ?>

<div class="card">
	<h2><?php echo $editingTrigger ? 'Edit Trigger' : 'Create Trigger'; ?></h2>
	<form method="post">
		<input type="hidden" name="action" value="save_trigger">
		<input type="hidden" name="trigger_db_id" value="<?php echo e((string) ($editingTrigger['id'] ?? 0)); ?>">
		<div class="row">
			<div>
				<label>Trigger ID (template key)</label>
				<input type="text" name="trigger_id" required maxlength="191" value="<?php echo e((string) ($editingTrigger['trigger_id'] ?? '')); ?>" placeholder="ticket_notification">
			</div>
			<div>
				<label>Name</label>
				<input type="text" name="name" required maxlength="191" value="<?php echo e((string) ($editingTrigger['name'] ?? '')); ?>" placeholder="Ticket Notification">
			</div>
			<div>
				<label>Webhook URL</label>
				<input type="url" name="webhook_url" required value="<?php echo e((string) ($editingTrigger['webhook_url'] ?? '')); ?>" placeholder="https://example.com/webhook">
			</div>
		</div>
		<p>
			<label>Payload Template (JSON; placeholders: {{pixel_id}}, {{pixel_db_id}}, {{hit_id}}, {{hits}}, {{trigger_id}}, {{hit_at}}, {{ip_address}}, {{user_agent}}, {{referrer}}, {{request_uri}}, {{query_string}}, {{accept_language}}, {{remote_host}})</label>
			<textarea name="payload_template" rows="12" style="width:100%;padding:8px;border:1px solid #bbb;border-radius:4px;box-sizing:border-box;font-family:monospace;"><?php echo e($payloadTemplateForTextarea); ?></textarea>
		</p>
		<p>
			<label><input type="checkbox" name="is_active" value="1" <?php echo (!isset($editingTrigger['is_active']) || (int) $editingTrigger['is_active'] === 1) ? 'checked' : ''; ?> style="width:auto;"> Active</label>
		</p>
		<p>
			<label><input type="checkbox" name="is_default" value="1" <?php echo (isset($editingTrigger['is_default']) && (int) $editingTrigger['is_default'] === 1) ? 'checked' : ''; ?> style="width:auto;"> Default Trigger for Embed Links</label>
		</p>
		<p class="inline">
			<button type="submit">Save Trigger</button>
			<?php if ($editingTrigger): ?><a class="nav-btn" href="triggers.php">Cancel Edit</a><?php endif; ?>
		</p>
	</form>
</div>

<div class="card">
	<h2>Usage</h2>
	<p class="muted">Use any trigger template with any pixel by appending trigger parameter in the pixel URL.</p>
	<p><input readonly onclick="this.select()" value="/pix.php?id=ticket_id1122&trigger=ticket_notification"></p>
	<p class="muted">trigger_id is also supported for compatibility: /pix.php?id=ticket_id1122&trigger_id=ticket_notification</p>
</div>

<div class="card">
	<h2>Trigger Templates</h2>
	<table>
		<thead>
		<tr>
			<th>Trigger ID</th>
			<th>Name</th>
			<th>URL</th>
			<th>Default</th>
			<th>Status</th>
			<th>Actions</th>
		</tr>
		</thead>
		<tbody>
		<?php if (!$triggers): ?>
			<tr><td colspan="6" class="muted">No triggers created yet.</td></tr>
		<?php else: ?>
			<?php foreach ($triggers as $trigger): ?>
				<tr>
					<td><?php echo e((string) $trigger['trigger_id']); ?></td>
					<td><?php echo e((string) $trigger['name']); ?></td>
					<td><?php echo e((string) $trigger['webhook_url']); ?></td>
					<td><?php echo (int) $trigger['is_default'] === 1 ? 'Yes' : 'No'; ?></td>
					<td><?php echo (int) $trigger['is_active'] === 1 ? 'Active' : 'Inactive'; ?></td>
					<td>
						<div class="inline">
							<a class="nav-btn" href="triggers.php?edit_id=<?php echo (int) $trigger['id']; ?>">Edit</a>
							<form method="post" onsubmit="return confirm('Delete this trigger?');" style="margin:0;">
								<input type="hidden" name="action" value="delete_trigger">
								<input type="hidden" name="trigger_db_id" value="<?php echo (int) $trigger['id']; ?>">
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
<?php
render_footer();
