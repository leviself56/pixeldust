<?php

declare(strict_types=1);

require __DIR__ . '/_libraries/core.php';

if (!is_installed()) {
	redirect('install.php');
}

if (current_admin()) {
	redirect('admin/index.php');
}

redirect('login.php');
