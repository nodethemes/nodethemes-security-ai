<?php
/**
 * Login protection: failed-login limits, IP lockouts and strong passwords.
 * Works for wp-login.php, WooCommerce My Account and XML-RPC (all use the same WordPress login).
 *
 * @package NodeThemes_Security_AI
 */

defined( 'ABSPATH' ) || exit;

/**
 * Login protection.
 */
class NTSA_Login {

	/**
	 * Hooks.
	 */
	public static function init() {
		if ( ntsa_safe_mode() ) {
			return;
		}
		if ( NTSA_Settings::get( 'login_on' ) ) {
			add_filter( 'authenticate', array( __CLASS__, 'stop_locked' ), 1, 3 );
			add_action( 'wp_login_failed', array( __CLASS__, 'failed' ), 10, 1 );
			add_action( 'wp_login', array( __CLASS__, 'success' ), 0, 1 );
		}
		if ( 'off' !== NTSA_Settings::get( 'strong_pw' ) ) {
			add_action( 'user_profile_update_errors', array( __CLASS__, 'check_profile_password' ), 10, 3 );
			add_action( 'validate_password_reset', array( __CLASS__, 'check_reset_password' ), 10, 2 );
			add_action( 'woocommerce_save_account_details_errors', array( __CLASS__, 'check_wc_password' ), 10, 2 );
		}
	}

	/**
	 * Row for an IP.
	 *
	 * @param string $ip IP.
	 * @return array|null
	 */
	private static function row( $ip ) {
		global $wpdb;
		return $wpdb->get_row( $wpdb->prepare( 'SELECT * FROM ' . NTSA_DB::table( 'ip' ) . ' WHERE ip = %s', $ip ), ARRAY_A ); // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared,WordPress.DB.DirectDatabaseQuery
	}

	/**
	 * Seconds left on a lockout (0 = not locked).
	 *
	 * @param string $ip IP.
	 * @return int
	 */
	public static function locked_for( $ip ) {
		$r = self::row( $ip );
		return $r ? max( 0, (int) $r['locked_until'] - time() ) : 0;
	}

	/**
	 * Refuse logins from a locked IP before the password is even checked.
	 *
	 * @param WP_User|WP_Error|null $user     Result so far.
	 * @param string                $username Username.
	 * @param string                $password Password.
	 * @return WP_User|WP_Error|null
	 */
	public static function stop_locked( $user, $username, $password ) {
		if ( '' === (string) $username && '' === (string) $password ) {
			return $user; // Not a login attempt (e.g. just opening the login page).
		}
		$ip = NTSA_IP::get();
		if ( NTSA_IP::allowed() ) {
			return $user;
		}
		$left = self::locked_for( $ip );
		if ( $left > 0 ) {
			remove_filter( 'authenticate', 'wp_authenticate_username_password', 20 );
			remove_filter( 'authenticate', 'wp_authenticate_email_password', 20 );
			return new WP_Error(
				'ntsa_locked',
				sprintf(
					/* translators: %s: time such as "25 minutes" */
					__( '<strong>Too many failed login attempts.</strong> For your security, logins from your network are paused. Please try again in %s.', 'nodethemes-security-ai' ),
					human_time_diff( time(), time() + $left )
				)
			);
		}
		return $user;
	}

	/**
	 * Count a failed login and lock the IP when the limit is reached.
	 *
	 * @param string $username Username tried.
	 */
	public static function failed( $username ) {
		global $wpdb;
		$ip = NTSA_IP::get();
		if ( NTSA_IP::allowed() ) {
			return;
		}
		$now    = time();
		$max    = max( 2, (int) NTSA_Settings::get( 'login_max', 5 ) );
		$window = max( 1, (int) NTSA_Settings::get( 'login_window', 15 ) ) * MINUTE_IN_SECONDS;
		$r      = self::row( $ip );
		if ( ! $r ) {
			$r = array(
				'ip'             => $ip,
				'fails'          => 0,
				'window_start'   => $now,
				'locked_until'   => 0,
				'lockouts'       => 0,
				'lockouts_since' => $now,
				'last_user'      => '',
				'updated'        => $now,
			);
		}
		if ( (int) $r['window_start'] < $now - $window ) {
			$r['fails']        = 0;
			$r['window_start'] = $now;
		}
		if ( (int) $r['lockouts_since'] < $now - DAY_IN_SECONDS ) {
			$r['lockouts']       = 0;
			$r['lockouts_since'] = $now;
		}
		$r['fails']     = (int) $r['fails'] + 1;
		$r['last_user'] = substr( sanitize_user( (string) $username ), 0, 60 );
		$r['updated']   = $now;

		$locked = false;
		if ( $r['fails'] >= $max ) {
			$r['lockouts'] = (int) $r['lockouts'] + 1;
			$long          = $r['lockouts'] >= max( 2, (int) NTSA_Settings::get( 'login_long', 3 ) );
			$len           = $long ? max( 1, (int) NTSA_Settings::get( 'login_long_hrs', 24 ) ) * HOUR_IN_SECONDS : max( 1, (int) NTSA_Settings::get( 'login_lock', 30 ) ) * MINUTE_IN_SECONDS;
			$r['locked_until'] = $now + $len;
			$r['fails']        = 0;
			$r['window_start'] = $now;
			$locked            = true;
		}
		$wpdb->replace( NTSA_DB::table( 'ip' ), $r ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery

		if ( $locked ) {
			$uri = isset( $_SERVER['REQUEST_URI'] ) ? esc_url_raw( wp_unslash( $_SERVER['REQUEST_URI'] ) ) : '';
			$ua  = isset( $_SERVER['HTTP_USER_AGENT'] ) ? sanitize_text_field( wp_unslash( $_SERVER['HTTP_USER_AGENT'] ) ) : '';
			NTSA_Firewall::log(
				'lockout',
				'login',
				$uri,
				$ua,
				/* translators: 1: username, 2: minutes */
				sprintf( __( 'Too many failed logins (last username tried: %1$s). Locked for %2$d minutes.', 'nodethemes-security-ai' ), $r['last_user'], (int) round( ( $r['locked_until'] - $now ) / 60 ) ),
				$ip
			);
			NTSA_Log::add( 'lockout', $r['last_user'], array( 'ip' => $ip ), 2 );
			do_action( 'ntsa_lockout', $ip, $r['last_user'], (int) $r['locked_until'] );
		}
	}

	/**
	 * A successful login clears the failed-login counter for that IP (lockouts are kept).
	 *
	 * @param string $login Username.
	 */
	public static function success( $login ) {
		global $wpdb;
		$wpdb->update( NTSA_DB::table( 'ip' ), array( 'fails' => 0 ), array( 'ip' => NTSA_IP::get() ) ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery
	}

	/**
	 * Unlock an IP (from the admin screen).
	 *
	 * @param string $ip IP.
	 */
	public static function unlock( $ip ) {
		global $wpdb;
		$wpdb->delete( NTSA_DB::table( 'ip' ), array( 'ip' => $ip ) ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery
	}

	/**
	 * IPs locked right now.
	 *
	 * @return array
	 */
	public static function locked_list() {
		global $wpdb;
		return (array) $wpdb->get_results( $wpdb->prepare( 'SELECT * FROM ' . NTSA_DB::table( 'ip' ) . ' WHERE locked_until > %d ORDER BY locked_until DESC LIMIT 100', time() ), ARRAY_A ); // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared,WordPress.DB.DirectDatabaseQuery
	}

	/* ---------------------------------------------------------------------
	 * Strong passwords
	 * ------------------------------------------------------------------ */

	/**
	 * Must this user use a strong password?
	 *
	 * @param WP_User|object|null $user  User (may be a new user without ID).
	 * @param string              $role  Role being set, if known.
	 * @return bool
	 */
	public static function needs_strong( $user, $role = '' ) {
		$mode = NTSA_Settings::get( 'strong_pw' );
		if ( 'off' === $mode ) {
			return false;
		}
		if ( 'all' === $mode && ntsa_is_pro() ) {
			return true;
		}
		$roles = array();
		if ( $user instanceof WP_User ) {
			$roles = (array) $user->roles;
		} elseif ( is_object( $user ) && ! empty( $user->ID ) ) {
			$u     = get_userdata( $user->ID );
			$roles = $u ? (array) $u->roles : array();
		}
		if ( '' !== $role ) {
			$roles[] = $role;
		}
		$strict = apply_filters( 'ntsa_strong_password_roles', array( 'administrator', 'editor', 'shop_manager' ) );
		return (bool) array_intersect( $roles, $strict );
	}

	/**
	 * Why a password is weak (empty string = fine).
	 *
	 * @param string $pass  Password.
	 * @param string $login Username / e-mail, which must not be inside the password.
	 * @return string
	 */
	public static function weakness( $pass, $login = '' ) {
		$pass = (string) $pass;
		if ( strlen( $pass ) < 12 ) {
			return __( 'Please use at least 12 characters.', 'nodethemes-security-ai' );
		}
		$kinds = 0;
		foreach ( array( '/[a-z]/', '/[A-Z]/', '/[0-9]/', '/[^A-Za-z0-9]/' ) as $re ) {
			$kinds += preg_match( $re, $pass ) ? 1 : 0;
		}
		if ( $kinds < 3 ) {
			return __( 'Please mix at least three of: lowercase letters, capital letters, numbers and symbols.', 'nodethemes-security-ai' );
		}
		$l = strtolower( $pass );
		if ( '' !== $login && strlen( $login ) >= 3 && false !== strpos( $l, strtolower( (string) $login ) ) ) {
			return __( 'The password must not contain the username.', 'nodethemes-security-ai' );
		}
		foreach ( array( 'password', 'qwerty', '123456', 'letmein', 'welcome', 'admin', 'iloveyou', 'abc123', 'wordpress' ) as $bad ) {
			if ( false !== strpos( $l, $bad ) ) {
				return __( 'The password contains a very common word or sequence. Please choose another one.', 'nodethemes-security-ai' );
			}
		}
		return '';
	}

	/**
	 * Profile / new user screen.
	 *
	 * @param WP_Error $errors Errors.
	 * @param bool     $update Updating.
	 * @param object   $user   User data.
	 */
	public static function check_profile_password( $errors, $update, $user ) {
		if ( empty( $user->user_pass ) ) {
			return;
		}
		$role = isset( $user->role ) ? (string) $user->role : '';
		if ( ! self::needs_strong( $user, $role ) ) {
			return;
		}
		$why = self::weakness( $user->user_pass, isset( $user->user_login ) ? $user->user_login : '' );
		if ( '' !== $why ) {
			$errors->add( 'ntsa_weak_password', '<strong>' . esc_html__( 'Password too weak.', 'nodethemes-security-ai' ) . '</strong> ' . esc_html( $why ) );
		}
	}

	/**
	 * Password reset screen.
	 *
	 * @param WP_Error         $errors Errors.
	 * @param WP_User|WP_Error $user   User.
	 */
	public static function check_reset_password( $errors, $user ) {
		if ( ! $user instanceof WP_User || empty( $_POST['pass1'] ) ) { // phpcs:ignore WordPress.Security.NonceVerification.Missing -- WordPress checked the reset key.
			return;
		}
		if ( ! self::needs_strong( $user ) ) {
			return;
		}
		$why = self::weakness( wp_unslash( $_POST['pass1'] ), $user->user_login ); // phpcs:ignore WordPress.Security.NonceVerification.Missing,WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- password, checked only.
		if ( '' !== $why ) {
			$errors->add( 'ntsa_weak_password', esc_html__( 'Password too weak.', 'nodethemes-security-ai' ) . ' ' . esc_html( $why ) );
		}
	}

	/**
	 * WooCommerce My Account › Account details.
	 *
	 * @param WP_Error $errors Errors.
	 * @param object   $user   User data.
	 */
	public static function check_wc_password( $errors, $user ) {
		if ( empty( $user->user_pass ) || ! self::needs_strong( $user ) ) {
			return;
		}
		$why = self::weakness( $user->user_pass, isset( $user->user_login ) ? $user->user_login : '' );
		if ( '' !== $why ) {
			$errors->add( 'ntsa_weak_password', esc_html__( 'Password too weak.', 'nodethemes-security-ai' ) . ' ' . esc_html( $why ) );
		}
	}
}
