<?php
/**
 * Private data folder (wp-content/nodethemes-security): scan lists and the early firewall's
 * configuration. Every file in it is either a PHP file that exits when opened in a browser,
 * or blocked by .htaccess, so nothing in it can be read from the web.
 *
 * @package NodeThemes_Security_AI
 */

defined( 'ABSPATH' ) || exit;

/**
 * Data folder helper.
 */
class NTSA_Data {

	/**
	 * Create the folder with its protection files.
	 *
	 * @return bool
	 */
	public static function ensure_dir() {
		if ( ! is_dir( NTSA_DATA_DIR ) && ! wp_mkdir_p( NTSA_DATA_DIR ) ) {
			return false;
		}
		$files = array(
			'index.php' => "<?php\n// Silence is golden.\n",
			'.htaccess' => "# NodeThemes Security AI: private data.\n<IfModule mod_authz_core.c>\nRequire all denied\n</IfModule>\n<IfModule !mod_authz_core.c>\nOrder deny,allow\nDeny from all\n</IfModule>\n",
		);
		foreach ( $files as $name => $body ) {
			$path = NTSA_DATA_DIR . '/' . $name;
			if ( ! file_exists( $path ) ) {
				file_put_contents( $path, $body ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_file_put_contents
			}
		}
		return is_writable( NTSA_DATA_DIR ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_is_writable
	}

	/**
	 * Save a value as a PHP file that returns it (and exits when opened in a browser).
	 *
	 * @param string $name  File name (no path).
	 * @param mixed  $value Value (arrays, strings, numbers).
	 * @return bool
	 */
	public static function write( $name, $value ) {
		if ( ! self::ensure_dir() ) {
			return false;
		}
		$name = sanitize_file_name( $name );
		$path = NTSA_DATA_DIR . '/' . $name;
		$tmp  = $path . '.' . wp_generate_password( 6, false ) . '.tmp';
		$body = "<?php\nif ( ! defined( 'ABSPATH' ) && ! defined( 'NTSA_WAF_EARLY' ) ) { exit; }\nreturn " . var_export( $value, true ) . ";\n"; // phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_var_export
		if ( false === file_put_contents( $tmp, $body, LOCK_EX ) ) { // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_file_put_contents
			return false;
		}
		$ok = rename( $tmp, $path ); // phpcs:ignore WordPress.WP.AlternativeFunctions.rename_rename
		if ( function_exists( 'opcache_invalidate' ) ) {
			@opcache_invalidate( $path, true ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged
		}
		return $ok;
	}

	/**
	 * Read a value saved with write().
	 *
	 * @param string $name    File name.
	 * @param mixed  $default Fallback.
	 * @return mixed
	 */
	public static function read( $name, $default = null ) {
		$path = NTSA_DATA_DIR . '/' . sanitize_file_name( $name );
		if ( ! is_file( $path ) ) {
			return $default;
		}
		$v = include $path;
		return null === $v ? $default : $v;
	}

	/**
	 * Delete a data file.
	 *
	 * @param string $name File name.
	 */
	public static function delete( $name ) {
		$path = NTSA_DATA_DIR . '/' . sanitize_file_name( $name );
		if ( is_file( $path ) ) {
			wp_delete_file( $path );
		}
	}

	/**
	 * Remove the early-firewall lines (added by the Pro add-on) from .user.ini and .htaccess.
	 * waf.php itself is left in place: PHP may keep reading .user.ini for a few minutes, and a
	 * missing prepend file would stop the whole site. waf.php does nothing once its settings are gone.
	 */
	public static function remove_prepend() {
		$ini = ABSPATH . '.user.ini';
		if ( is_file( $ini ) && is_writable( $ini ) ) { // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_is_writable
			$body = (string) file_get_contents( $ini ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents
			$new  = preg_replace( '/\n?; BEGIN NodeThemes Security AI.*?; END NodeThemes Security AI\n?/s', "\n", $body );
			if ( null !== $new && $new !== $body ) {
				file_put_contents( $ini, ltrim( $new ) ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_file_put_contents
			}
		}
		$ht = ABSPATH . '.htaccess';
		if ( is_file( $ht ) && is_writable( $ht ) && false !== strpos( (string) file_get_contents( $ht ), '# BEGIN NodeThemes Early Firewall' ) ) { // phpcs:ignore WordPress.WP.AlternativeFunctions
			require_once ABSPATH . 'wp-admin/includes/misc.php';
			insert_with_markers( $ht, 'NodeThemes Early Firewall', array() );
		}
		$cfg = self::read( 'waf-config.php', array() );
		if ( is_array( $cfg ) && ! empty( $cfg['early'] ) ) {
			$cfg['early'] = 0;
			self::write( 'waf-config.php', $cfg );
		}
	}
}
