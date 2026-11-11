<?php
/**
 * Plugin Name:       NodeThemes Security AI
 * Description:       WordPress security with a firewall, login protection and lockouts, two-factor login, a WordPress core file check, a malware scan, known-vulnerability alerts, an activity log and safe one-click hardening that is tested before it stays on.
 * Version:           1.0.0
 * Requires at least: 6.0
 * Requires PHP:      7.4
 * Author:            NodeThemes
 * Author URI:        https://nodethemes.com/
 * License:           GPL-2.0-or-later
 * License URI:       https://www.gnu.org/licenses/gpl-2.0.html
 * Update URI:        https://nodethemes.com/nodethemes-security-ai
 * Text Domain:       nodethemes-security-ai
 *
 * @package NodeThemes_Security_AI
 */

defined( 'ABSPATH' ) || exit;

if ( defined( 'NTSA_VERSION' ) ) {
	return;
}

define( 'NTSA_VERSION', '1.0.0' );
define( 'NTSA_FILE', __FILE__ );
define( 'NTSA_DIR', plugin_dir_path( __FILE__ ) );
define( 'NTSA_URL', plugin_dir_url( __FILE__ ) );
define( 'NTSA_BASENAME', plugin_basename( __FILE__ ) );
if ( ! defined( 'NTSA_DATA_DIR' ) ) {
	define( 'NTSA_DATA_DIR', WP_CONTENT_DIR . '/nodethemes-security' );
}
if ( ! defined( 'NTSA_PRO_URL' ) ) {
	define( 'NTSA_PRO_URL', 'https://nodethemes.com/product/nodethemes-security-ai-pro/' );
}

// Free version limits (Pro removes them).
define( 'NTSA_FREE_2FA_USERS', 1 );          // Users who can use two-factor login.
define( 'NTSA_FREE_SCAN_DAYS', 7 );          // One manual malware scan per this many days.
define( 'NTSA_FREE_VULN_DAYS', 7 );          // One vulnerability check per this many days.
define( 'NTSA_FREE_LOG_DAYS', 7 );           // Activity log kept for this many days...
define( 'NTSA_FREE_LOG_ROWS', 500 );         // ...and at most this many events.

require_once NTSA_DIR . 'waf/rules.php';
require_once NTSA_DIR . 'includes/class-ntsa-settings.php';
require_once NTSA_DIR . 'includes/class-ntsa-ip.php';
require_once NTSA_DIR . 'includes/class-ntsa-db.php';
require_once NTSA_DIR . 'includes/class-ntsa-data.php';
require_once NTSA_DIR . 'includes/class-ntsa-firewall.php';
require_once NTSA_DIR . 'includes/class-ntsa-login.php';
require_once NTSA_DIR . 'includes/class-ntsa-totp.php';
require_once NTSA_DIR . 'includes/class-ntsa-twofa.php';
require_once NTSA_DIR . 'includes/class-ntsa-log.php';
require_once NTSA_DIR . 'includes/class-ntsa-files.php';
require_once NTSA_DIR . 'includes/class-ntsa-integrity.php';
require_once NTSA_DIR . 'includes/class-ntsa-malware.php';
require_once NTSA_DIR . 'includes/class-ntsa-vuln.php';
require_once NTSA_DIR . 'includes/class-ntsa-hardening.php';
require_once NTSA_DIR . 'includes/class-ntsa-admin.php';
require_once NTSA_DIR . 'includes/class-ntsa-updater.php';
NTSA_Free_Updater::boot( NTSA_FILE, NTSA_VERSION, NTSA_PRO_URL );

/**
 * Is the Pro add-on installed (active or not)?
 *
 * @return bool
 */
function ntsa_pro_installed() {
	return (bool) apply_filters( 'ntsa_pro_installed', false );
}

/**
 * Are the Pro features unlocked (add-on active with a valid license)?
 *
 * @return bool
 */
function ntsa_is_pro() {
	return (bool) apply_filters( 'ntsa_is_pro', false );
}

/**
 * Where a locked PRO button should go.
 *
 * @return string
 */
function ntsa_upgrade_url() {
	if ( ntsa_pro_installed() ) {
		return admin_url( 'admin.php?page=ntsa-license' );
	}
	return NTSA_PRO_URL;
}

/**
 * Rescue switch: define( 'NTSA_SAFE_MODE', true ); in wp-config.php turns off the firewall,
 * lockouts, two-factor login and hardening rules that run in PHP, so you can always get back in.
 *
 * @return bool
 */
function ntsa_safe_mode() {
	return defined( 'NTSA_SAFE_MODE' ) && NTSA_SAFE_MODE;
}

register_activation_hook( __FILE__, array( 'NTSA_DB', 'activate' ) );
register_deactivation_hook( __FILE__, array( 'NTSA_DB', 'deactivate' ) );

// The firewall runs as early as a plugin can: before other plugins and the theme see the request.
NTSA_Firewall::boot();

add_action(
	'plugins_loaded',
	function () {
		NTSA_DB::maybe_upgrade();
		NTSA_Login::init();
		NTSA_TwoFA::init();
		NTSA_Log::init();
		NTSA_Integrity::init();
		NTSA_Malware::init();
		NTSA_Vuln::init();
		NTSA_Hardening::init();
		NTSA_Admin::init();
		do_action( 'ntsa_loaded' );
	},
	5
);
