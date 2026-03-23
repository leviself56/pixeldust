<?php

declare(strict_types=1);

require __DIR__ . '/_libraries/core.php';

unset($_SESSION['admin_user_id']);
flash('success', 'You have been logged out.');
redirect('login.php');
