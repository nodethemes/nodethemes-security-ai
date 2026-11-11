<?php
/**
 * Settings.
 *
 * @package NodeThemes_Security_AI
 */

defined( 'ABSPATH' ) || exit;

/**
 * Settings store (one option).
 */
class NTSA_Settings {

	const OPTION = 'ntsa_settings';

	/**
	 * Cached settings.
	 *
	 * @var array|null
	 */
	private static $cache = null;

	/**
	 * Defaults.
	 *
	 * @return array
	 */
	public static function defaults() {
		return array(
			'fw_mode'        => 'block',       // block|monitor|off.
			'fw_allow_ips'   => '',            // One IP or CIDR per line: never blocked or locked out.
			'fw_block_ips'   => '',            // One IP or CIDR per line: always blocked.
			'fw_exceptions'  => array(),       // "rule-id|/path/prefix".
			'ip_source'      => 'REMOTE_ADDR', // Where the visitor IP comes from.
			'login_on'       => 1,
			'login_max'      => 5,             // Failed logins...
			'login_window'   => 15,            // ...within this many minutes...
			'login_lock'     => 30,            // ...lock the IP for this many minutes.
			'login_long'     => 3,             // After this many lockouts in 24 hours...
			'login_long_hrs' => 24,            // ...lock for this many hours.
			'strong_pw'      => 'admins',      // off|admins (Pro adds "all").
			'vuln_enabled'   => 0,             // Known-vulnerability check (sends plugin/theme names to WPVulnerability): off until the owner turns it on.
			'hardening'      => array(),       // item id => 1.
		);
	}

	/**
	 * All settings.
	 *
	 * @return array
	 */
	public static function all() {
		if ( null === self::$cache ) {
			$s           = get_option( self::OPTION, array() );
			self::$cache = wp_parse_args( is_array( $s ) ? $s : array(), self::defaults() );
		}
		return self::$cache;
	}

	/**
	 * One setting.
	 *
	 * @param string $key     Key.
	 * @param mixed  $default Fallback.
	 * @return mixed
	 */
	public static function get( $key, $default = null ) {
		$s = self::all();
		return array_key_exists( $key, $s ) ? $s[ $key ] : $default;
	}

	/**
	 * Save some settings (merged).
	 *
	 * @param array $data Data.
	 */
	public static function update( $data ) {
		$s           = array_merge( self::all(), $data );
		self::$cache = $s;
		update_option( self::OPTION, $s, true );
		do_action( 'ntsa_settings_saved', $s );
	}

	/**
	 * Clean a list of IPs / CIDR ranges typed by the owner (one per line).
	 *
	 * @param string $text Text.
	 * @return string
	 */
	public static function clean_ip_list( $text ) {
		$out = array();
		foreach ( preg_split( '/[\r\n,]+/', (string) $text ) as $line ) {
			$line = trim( $line );
			if ( '' === $line ) {
				continue;
			}
			$ip   = $line;
			$bits = null;
			if ( false !== strpos( $line, '/' ) ) {
				list( $ip, $bits ) = explode( '/', $line, 2 );
			}
			if ( ! filter_var( $ip, FILTER_VALIDATE_IP ) ) {
				continue;
			}
			if ( null !== $bits ) {
				$max = false !== strpos( $ip, ':' ) ? 128 : 32;
				if ( ! ctype_digit( $bits ) || (int) $bits > $max ) {
					continue;
				}
				$line = $ip . '/' . (int) $bits;
			}
			$out[] = $line;
		}
		return implode( "\n", array_unique( $out ) );
	}

	/**
	 * A stored IP list as an array.
	 *
	 * @param string $key fw_allow_ips|fw_block_ips.
	 * @return array
	 */
	public static function ip_list( $key ) {
		return array_values( array_filter( array_map( 'trim', explode( "\n", (string) self::get( $key, '' ) ) ) ) );
	}
}
