<?php
/**
 * Firewall inside WordPress.
 *
 * Runs while plugins load, before other plugins and the theme handle the request. Visitors who are
 * not logged in are checked right away; for logged-in users we wait a moment until WordPress knows
 * who they are, so administrators and editors are never blocked while they work.
 * The Pro add-on can also run the same rules before WordPress loads (early firewall).
 *
 * @package NodeThemes_Security_AI
 */

defined( 'ABSPATH' ) || exit;

/**
 * Firewall.
 */
class NTSA_Firewall {

	/**
	 * Boot (called when the plugin file loads).
	 */
	public static function boot() {
		if ( ntsa_safe_mode() || ( defined( 'WP_CLI' ) && WP_CLI ) || 'off' === NTSA_Settings::get( 'fw_mode' ) ) {
			return;
		}
		if ( self::has_login_cookie() ) {
			add_action( 'plugins_loaded', array( __CLASS__, 'check' ), 6 );
		} else {
			self::check( false );
			// Checks added by the Pro add-on (countries, custom rules, rate limits) run once it has loaded.
			add_action( 'plugins_loaded', array( __CLASS__, 'check_extra' ), 6 );
		}
	}

	/**
	 * Does the request carry a login cookie (not verified yet)?
	 *
	 * @return bool
	 */
	public static function has_login_cookie() {
		foreach ( array_keys( $_COOKIE ) as $k ) {
			if ( 0 === strpos( (string) $k, 'wordpress_logged_in_' ) ) {
				return true;
			}
		}
		return false;
	}

	/**
	 * The current request in the shape the rules expect. The firewall runs before WordPress adds
	 * slashes to the request data (wp_magic_quotes runs after plugins_loaded), so values are read as they arrived.
	 *
	 * @return array
	 */
	public static function request() {
		$uri  = isset( $_SERVER['REQUEST_URI'] ) ? (string) $_SERVER['REQUEST_URI'] : '/'; // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- inspected, never output.
		$path = (string) wp_parse_url( $uri, PHP_URL_PATH );
		$json = '';
		$type = isset( $_SERVER['CONTENT_TYPE'] ) ? strtolower( sanitize_text_field( (string) $_SERVER['CONTENT_TYPE'] ) ) : '';
		if ( false !== strpos( $type, 'json' ) ) {
			$json = (string) file_get_contents( 'php://input', false, null, 0, 262144 ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents
		}
		return array(
			'uri'  => substr( (string) $uri, 0, 255 ),
			'path' => '' === $path ? '/' : $path,
			'get'  => $_GET, // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- inspected, never stored as-is.
			'post' => $_POST, // phpcs:ignore WordPress.Security.NonceVerification.Missing -- inspected, never stored as-is.
			'json' => $json,
			'ua'   => isset( $_SERVER['HTTP_USER_AGENT'] ) ? substr( sanitize_text_field( (string) $_SERVER['HTTP_USER_AGENT'] ), 0, 255 ) : '',
		);
	}

	/**
	 * Pro checks for visitors (when the early firewall did not already run them).
	 */
	public static function check_extra() {
		if ( defined( 'NTSA_WAF_DONE' ) || NTSA_IP::allowed() ) {
			return;
		}
		$req   = self::request();
		$ip    = NTSA_IP::get();
		$extra = apply_filters( 'ntsa_firewall_extra', null, $req, $ip );
		if ( is_array( $extra ) && 2 <= count( $extra ) ) {
			self::hit( (string) $extra[0], (string) $extra[1], $req, $ip, isset( $extra[2] ) ? (int) $extra[2] : 403 );
		}
	}

	/**
	 * Check the request.
	 *
	 * @param bool $with_extra Also run the Pro checks (logged-in requests, after WordPress knows the user).
	 */
	public static function check( $with_extra = true ) {
		if ( defined( 'NTSA_WAF_DONE' ) ) {
			return; // The Pro early firewall already checked this request.
		}
		$ip = NTSA_IP::get();
		if ( NTSA_IP::allowed() ) {
			return;
		}
		$req = self::request();

		if ( ntsa_ip_in_list( $ip, NTSA_Settings::ip_list( 'fw_block_ips' ) ) ) {
			self::hit( 'ip-block', 'IP address on your block list', $req, $ip ); // Not translated: this can run before translations load.
			return;
		}

		$opts = array( 'exceptions' => (array) NTSA_Settings::get( 'fw_exceptions', array() ) );
		if ( did_action( 'plugins_loaded' ) || doing_action( 'plugins_loaded' ) ) {
			if ( current_user_can( 'manage_options' ) ) {
				return; // Administrators are never blocked by the rules (they may save code on purpose).
			}
			if ( current_user_can( 'unfiltered_html' ) ) {
				$opts['skip_post'] = true; // Editors may post HTML with scripts.
			}
		}

		if ( $with_extra ) {
			$extra = apply_filters( 'ntsa_firewall_extra', null, $req, $ip );
			if ( is_array( $extra ) && 2 <= count( $extra ) ) {
				self::hit( (string) $extra[0], (string) $extra[1], $req, $ip, isset( $extra[2] ) ? (int) $extra[2] : 403 );
				return;
			}
		}

		$m = ntsa_waf_check( $req, $opts );
		if ( $m ) {
			self::hit( $m[0], $m[1], $req, $ip, 403, $m[2] );
		}
	}

	/**
	 * A rule matched: log it and block (or only log in monitor mode).
	 *
	 * @param string $rule   Rule id.
	 * @param string $label  Rule name.
	 * @param array  $req    Request.
	 * @param string $ip     IP.
	 * @param int    $code   HTTP status.
	 * @param string $sample Matched value.
	 */
	public static function hit( $rule, $label, $req, $ip, $code = 403, $sample = '' ) {
		$monitor = 'monitor' === NTSA_Settings::get( 'fw_mode' );
		$ref     = strtoupper( substr( md5( $ip . microtime() ), 0, 8 ) );
		self::log( $monitor ? 'monitor' : 'block', $rule, $req['uri'], $req['ua'], $ref . ' ' . $label . ( '' !== $sample ? ': ' . $sample : '' ), $ip );
		do_action( 'ntsa_firewall_hit', $rule, $ip, $req, $monitor );
		if ( ! $monitor ) {
			ntsa_waf_block_page( $ref, $code );
		}
	}

	/**
	 * Write a firewall / lockout row.
	 *
	 * @param string $action block|monitor|lockout|ratelimit.
	 * @param string $rule   Rule id.
	 * @param string $uri    URL.
	 * @param string $ua     User agent.
	 * @param string $detail Detail.
	 * @param string $ip     IP (defaults to the visitor).
	 */
	public static function log( $action, $rule, $uri, $ua, $detail, $ip = null ) {
		global $wpdb;
		$wpdb->insert( // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery
			NTSA_DB::table( 'fw' ),
			array(
				'ts'     => time(),
				'ip'     => null === $ip ? NTSA_IP::get() : $ip,
				'action' => substr( $action, 0, 12 ),
				'rule'   => substr( $rule, 0, 40 ),
				'uri'    => substr( (string) $uri, 0, 255 ),
				'ua'     => substr( (string) $ua, 0, 255 ),
				'detail' => substr( wp_check_invalid_utf8( (string) $detail, true ), 0, 255 ),
			)
		);
	}

	/**
	 * Blocks in the last N days (for the dashboard).
	 *
	 * @param int $days Days.
	 * @return array action => count.
	 */
	public static function counts( $days = 7 ) {
		global $wpdb;
		$rows = $wpdb->get_results( $wpdb->prepare( 'SELECT action, COUNT(*) AS n FROM ' . NTSA_DB::table( 'fw' ) . ' WHERE ts > %d GROUP BY action', time() - $days * DAY_IN_SECONDS ), ARRAY_A ); // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared,WordPress.DB.DirectDatabaseQuery
		$out  = array();
		foreach ( (array) $rows as $r ) {
			$out[ $r['action'] ] = (int) $r['n'];
		}
		return $out;
	}

	/**
	 * Add an exception (rule off for one path prefix), e.g. after a false alarm.
	 *
	 * @param string $rule Rule id.
	 * @param string $path Path prefix.
	 */
	public static function add_exception( $rule, $path ) {
		$ex   = (array) NTSA_Settings::get( 'fw_exceptions', array() );
		$ex[] = sanitize_key( $rule ) . '|' . substr( preg_replace( '#[^A-Za-z0-9/_.\-]#', '', (string) $path ), 0, 190 );
		NTSA_Settings::update( array( 'fw_exceptions' => array_values( array_unique( $ex ) ) ) );
	}
}
