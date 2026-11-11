<?php
/**
 * Two-factor login with an authenticator app (plus one-time backup codes).
 *
 * After the password is accepted, the login is paused and the user is asked for the 6-digit code
 * from their app. This works for wp-login.php and the WooCommerce My Account login. Password logins
 * over XML-RPC are refused for these users (they cannot enter a code there). Application passwords,
 * which WordPress creates for apps and integrations, are separate and keep working.
 *
 * @package NodeThemes_Security_AI
 */

defined( 'ABSPATH' ) || exit;

/**
 * Two-factor login.
 */
class NTSA_TwoFA {

	/**
	 * Session token created by the password login (destroyed until the code is entered).
	 *
	 * @var string
	 */
	private static $token = '';

	/**
	 * True after the code was accepted, so our own wp_login call is not stopped again.
	 *
	 * @var bool
	 */
	private static $passed = false;

	/**
	 * Hooks.
	 */
	public static function init() {
		add_action( 'show_user_profile', array( __CLASS__, 'profile' ) );
		add_action( 'edit_user_profile', array( __CLASS__, 'profile' ) );
		add_action( 'admin_enqueue_scripts', array( __CLASS__, 'assets' ) );
		foreach ( array( 'start', 'confirm', 'disable', 'backup' ) as $a ) {
			add_action( 'wp_ajax_ntsa_2fa_' . $a, array( __CLASS__, 'ajax_' . $a ) );
		}
		if ( ntsa_safe_mode() || ( defined( 'NTSA_DISABLE_2FA' ) && NTSA_DISABLE_2FA ) ) {
			return;
		}
		add_action( 'set_logged_in_cookie', array( __CLASS__, 'remember_token' ), 10, 6 );
		add_action( 'wp_login', array( __CLASS__, 'intercept' ), -100, 2 );
		add_action( 'login_form_ntsa_2fa', array( __CLASS__, 'screen' ) );
		add_filter( 'authenticate', array( __CLASS__, 'no_xmlrpc_password' ), 99, 1 );
		add_filter( 'wp_login_errors', array( __CLASS__, 'expired_message' ) );
	}

	/**
	 * Message when the code step timed out or had too many wrong codes.
	 *
	 * @param WP_Error $errors Errors.
	 * @return WP_Error
	 */
	public static function expired_message( $errors ) {
		if ( isset( $_GET['ntsa_2fa_expired'] ) && $errors instanceof WP_Error ) { // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- message only.
			$errors->add( 'ntsa_2fa_expired', __( 'The two-factor step timed out or had too many wrong codes. Please log in again.', 'nodethemes-security-ai' ) );
		}
		return $errors;
	}

	/* ---------------------------------------------------------------------
	 * Storage
	 * ------------------------------------------------------------------ */

	/**
	 * Is two-factor login on for a user?
	 *
	 * @param int $user_id User ID.
	 * @return bool
	 */
	public static function enabled( $user_id ) {
		return '1' === (string) get_user_meta( (int) $user_id, 'ntsa_2fa_on', true ) && '' !== (string) get_user_meta( (int) $user_id, 'ntsa_2fa_secret', true );
	}

	/**
	 * How many users have it on.
	 *
	 * @return int
	 */
	public static function count_enabled() {
		global $wpdb;
		return (int) $wpdb->get_var( $wpdb->prepare( "SELECT COUNT(*) FROM {$wpdb->usermeta} WHERE meta_key = %s AND meta_value = %s", 'ntsa_2fa_on', '1' ) ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery
	}

	/**
	 * How many users may use it (0 = no limit).
	 *
	 * @return int
	 */
	public static function user_limit() {
		return (int) apply_filters( 'ntsa_2fa_user_limit', ntsa_is_pro() ? 0 : NTSA_FREE_2FA_USERS );
	}

	/**
	 * May this user turn it on now? Users who already have it on always keep it.
	 *
	 * @param int $user_id User.
	 * @return bool
	 */
	public static function can_enable( $user_id ) {
		$limit = self::user_limit();
		return self::enabled( $user_id ) || 0 === $limit || self::count_enabled() < $limit;
	}

	/**
	 * Encrypt / decrypt the secret with the site's own keys (from wp-config.php).
	 *
	 * @param string $v       Value.
	 * @param bool   $decrypt Decrypt.
	 * @return string
	 */
	private static function crypt( $v, $decrypt = false ) {
		if ( ! function_exists( 'openssl_encrypt' ) || '' === (string) $v ) {
			return (string) $v;
		}
		$key = hash( 'sha256', wp_salt( 'auth' ) . 'ntsa-2fa', true );
		if ( $decrypt ) {
			if ( 0 !== strpos( $v, 'e1:' ) ) {
				return (string) $v;
			}
			$raw = base64_decode( substr( $v, 3 ), true ); // phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.obfuscation_base64_decode -- our own stored value.
			if ( false === $raw || strlen( $raw ) < 17 ) {
				return '';
			}
			$out = openssl_decrypt( substr( $raw, 16 ), 'aes-256-ctr', $key, OPENSSL_RAW_DATA, substr( $raw, 0, 16 ) );
			return false === $out ? '' : $out;
		}
		$iv = random_bytes( 16 );
		return 'e1:' . base64_encode( $iv . openssl_encrypt( $v, 'aes-256-ctr', $key, OPENSSL_RAW_DATA, $iv ) ); // phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.obfuscation_base64_encode
	}

	/**
	 * Secret of a user.
	 *
	 * @param int    $user_id User.
	 * @param string $which   ntsa_2fa_secret|ntsa_2fa_pending.
	 * @return string
	 */
	private static function secret( $user_id, $which = 'ntsa_2fa_secret' ) {
		return self::crypt( (string) get_user_meta( (int) $user_id, $which, true ), true );
	}

	/**
	 * Check a code or a backup code for a user.
	 *
	 * @param int    $user_id User.
	 * @param string $code    Code.
	 * @return bool
	 */
	public static function check_code( $user_id, $code ) {
		$code = preg_replace( '/\D/', '', (string) $code );
		$step = NTSA_TOTP::verify( self::secret( $user_id ), $code, (int) get_user_meta( $user_id, 'ntsa_2fa_last', true ) );
		if ( false !== $step ) {
			update_user_meta( $user_id, 'ntsa_2fa_last', $step );
			return true;
		}
		if ( 8 === strlen( $code ) ) {
			$codes = (array) get_user_meta( $user_id, 'ntsa_2fa_backup', true );
			foreach ( $codes as $i => $hash ) {
				if ( is_string( $hash ) && wp_check_password( $code, $hash ) ) {
					unset( $codes[ $i ] );
					update_user_meta( $user_id, 'ntsa_2fa_backup', array_values( $codes ) );
					NTSA_Log::add( '2fa_backup_used', '', array( 'left' => count( $codes ) ), 2, $user_id );
					return true;
				}
			}
		}
		return false;
	}

	/**
	 * New backup codes (shown once, stored hashed).
	 *
	 * @param int $user_id User.
	 * @return array Plain codes.
	 */
	private static function new_backup_codes( $user_id ) {
		$plain = array();
		$hash  = array();
		for ( $i = 0; $i < 10; $i++ ) {
			$c       = str_pad( (string) random_int( 0, 99999999 ), 8, '0', STR_PAD_LEFT );
			$plain[] = $c;
			$hash[]  = wp_hash_password( $c );
		}
		update_user_meta( $user_id, 'ntsa_2fa_backup', $hash );
		return $plain;
	}

	/* ---------------------------------------------------------------------
	 * Login flow
	 * ------------------------------------------------------------------ */

	/**
	 * Keep the session token WordPress just created.
	 *
	 * @param string $cookie     Cookie.
	 * @param int    $expire     Expire.
	 * @param int    $expiration Expiration.
	 * @param int    $user_id    User.
	 * @param string $scheme     Scheme.
	 * @param string $token      Session token.
	 */
	public static function remember_token( $cookie, $expire, $expiration, $user_id, $scheme, $token ) {
		self::$token = (string) $token;
	}

	/**
	 * After the password: pause the login and ask for the code.
	 *
	 * @param string  $login Username.
	 * @param WP_User $user  User.
	 */
	public static function intercept( $login, $user ) {
		if ( self::$passed || ! $user instanceof WP_User || ! self::enabled( $user->ID ) ) {
			return;
		}
		if ( '' !== self::$token ) {
			WP_Session_Tokens::get_instance( $user->ID )->destroy( self::$token );
		}
		wp_clear_auth_cookie();
		wp_set_current_user( 0 );

		// phpcs:disable WordPress.Security.NonceVerification -- the login form was checked by WordPress / WooCommerce.
		$to = '';
		if ( isset( $_REQUEST['redirect_to'] ) ) {
			$to = esc_url_raw( wp_unslash( $_REQUEST['redirect_to'] ) );
		} elseif ( isset( $_POST['woocommerce-login-nonce'] ) ) {
			$to = isset( $_POST['redirect'] ) ? esc_url_raw( wp_unslash( $_POST['redirect'] ) ) : '';
			if ( '' === $to && function_exists( 'wc_get_page_permalink' ) ) {
				$to = wc_get_page_permalink( 'myaccount' );
			}
		}
		$remember = ! empty( $_POST['rememberme'] );
		// phpcs:enable

		$t = wp_generate_password( 40, false );
		set_transient(
			'ntsa_2fa_' . hash( 'sha256', $t ),
			array(
				'u'  => $user->ID,
				'r'  => $remember,
				'to' => $to,
				'n'  => 0,
			),
			10 * MINUTE_IN_SECONDS
		);
		wp_safe_redirect( add_query_arg( array( 'action' => 'ntsa_2fa', 'ntsa_t' => $t ), wp_login_url() ) );
		exit;
	}

	/**
	 * The code screen on wp-login.php.
	 */
	public static function screen() {
		// phpcs:disable WordPress.Security.NonceVerification -- the random login token is the proof here.
		$t     = isset( $_REQUEST['ntsa_t'] ) ? preg_replace( '/[^A-Za-z0-9]/', '', wp_unslash( $_REQUEST['ntsa_t'] ) ) : '';
		$key   = 'ntsa_2fa_' . hash( 'sha256', $t );
		$state = '' !== $t ? get_transient( $key ) : false;
		if ( ! is_array( $state ) || empty( $state['u'] ) ) {
			wp_safe_redirect( add_query_arg( 'ntsa_2fa_expired', '1', wp_login_url() ) );
			exit;
		}
		$user  = get_userdata( (int) $state['u'] );
		$error = '';
		if ( $user && 'POST' === ( isset( $_SERVER['REQUEST_METHOD'] ) ? $_SERVER['REQUEST_METHOD'] : '' ) && isset( $_POST['ntsa_code'] ) ) { // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized
			if ( NTSA_Login::locked_for( NTSA_IP::get() ) > 0 && ! NTSA_IP::allowed() ) {
				delete_transient( $key );
				wp_safe_redirect( wp_login_url() );
				exit;
			}
			if ( self::check_code( $user->ID, sanitize_text_field( wp_unslash( $_POST['ntsa_code'] ) ) ) ) {
				delete_transient( $key );
				self::$passed = true;
				wp_set_auth_cookie( $user->ID, ! empty( $state['r'] ), is_ssl() );
				wp_set_current_user( $user->ID );
				do_action( 'wp_login', $user->user_login, $user );
				$requested = (string) $state['to'];
				$to        = '' !== $requested ? $requested : admin_url();
				$to        = apply_filters( 'login_redirect', $to, $requested, $user );
				if ( ( empty( $to ) || admin_url() === $to ) && ! $user->has_cap( 'edit_posts' ) ) {
					$to = function_exists( 'wc_get_page_permalink' ) ? wc_get_page_permalink( 'myaccount' ) : admin_url( 'profile.php' );
				}
				wp_safe_redirect( wp_validate_redirect( $to, admin_url() ) );
				exit;
			}
			NTSA_Login::failed( $user->user_login );
			$state['n'] = (int) $state['n'] + 1;
			if ( $state['n'] >= 5 ) {
				delete_transient( $key );
				NTSA_Log::add( '2fa_failed', $user->user_login, array( 'attempts' => 5 ), 2, $user->ID );
				wp_safe_redirect( add_query_arg( 'ntsa_2fa_expired', '1', wp_login_url() ) );
				exit;
			}
			set_transient( $key, $state, 10 * MINUTE_IN_SECONDS );
			$error = __( 'That code is not right. Please check the time on your phone and try again.', 'nodethemes-security-ai' );
		}
		// phpcs:enable

		$err = new WP_Error();
		if ( '' !== $error ) {
			$err->add( 'ntsa_code', $error );
		}
		login_header( __( 'Two-factor login', 'nodethemes-security-ai' ), '', $err );
		?>
		<form name="ntsa_2fa" id="loginform" action="<?php echo esc_url( add_query_arg( array( 'action' => 'ntsa_2fa', 'ntsa_t' => $t ), wp_login_url() ) ); ?>" method="post" autocomplete="off">
			<p><?php esc_html_e( 'Enter the 6-digit code from your authenticator app. Lost your phone? Enter one of your 8-digit backup codes instead.', 'nodethemes-security-ai' ); ?></p>
			<p style="margin-top:14px">
				<label for="ntsa_code"><?php esc_html_e( 'Code', 'nodethemes-security-ai' ); ?></label>
				<input type="text" name="ntsa_code" id="ntsa_code" class="input" inputmode="numeric" autocomplete="one-time-code" pattern="[0-9 ]*" maxlength="9" size="20" autofocus required style="letter-spacing:.2em;font-size:22px">
			</p>
			<p class="submit"><input type="submit" class="button button-primary button-large" value="<?php esc_attr_e( 'Log in', 'nodethemes-security-ai' ); ?>"></p>
		</form>
		<?php
		login_footer( 'ntsa_code' );
		exit;
	}

	/**
	 * Password logins over XML-RPC cannot ask for a code, so they are refused for 2FA users.
	 *
	 * @param WP_User|WP_Error|null $user Result.
	 * @return WP_User|WP_Error|null
	 */
	public static function no_xmlrpc_password( $user ) {
		if ( defined( 'XMLRPC_REQUEST' ) && XMLRPC_REQUEST && $user instanceof WP_User && self::enabled( $user->ID ) ) {
			return new WP_Error( 'ntsa_2fa_xmlrpc', __( 'This account uses two-factor login. Please use an application password for apps.', 'nodethemes-security-ai' ) );
		}
		return $user;
	}

	/* ---------------------------------------------------------------------
	 * Profile screen
	 * ------------------------------------------------------------------ */

	/**
	 * Scripts on the profile screens.
	 *
	 * @param string $hook Screen.
	 */
	public static function assets( $hook ) {
		if ( ! in_array( $hook, array( 'profile.php', 'user-edit.php' ), true ) ) {
			return;
		}
		wp_enqueue_script( 'ntsa-qrcode', NTSA_URL . 'assets/qrcode.js', array(), '2.0.4', true );
		wp_enqueue_script( 'ntsa-2fa', NTSA_URL . 'assets/twofa.js', array( 'jquery', 'ntsa-qrcode' ), NTSA_VERSION, true );
		wp_localize_script(
			'ntsa-2fa',
			'NTSA2FA',
			array(
				'ajax' => admin_url( 'admin-ajax.php' ),
				'i18n' => array(
					'scan'    => __( '1. Scan this QR code with your authenticator app (Google Authenticator, Microsoft Authenticator, 1Password, Authy…), or type the key below.', 'nodethemes-security-ai' ),
					'enter'   => __( '2. Enter the 6-digit code the app shows:', 'nodethemes-security-ai' ),
					'confirm' => __( 'Turn on', 'nodethemes-security-ai' ),
					'codes'   => __( 'Two-factor login is on. Save these backup codes somewhere safe (each works once, if you lose your phone). They will not be shown again:', 'nodethemes-security-ai' ),
					'error'   => __( 'Something went wrong. Please reload the page and try again.', 'nodethemes-security-ai' ),
					'sure'    => __( 'Turn off two-factor login for this account?', 'nodethemes-security-ai' ),
				),
			)
		);
	}

	/**
	 * Profile section.
	 *
	 * @param WP_User $user User being edited.
	 */
	public static function profile( $user ) {
		$own     = get_current_user_id() === $user->ID;
		$admin   = current_user_can( 'edit_user', $user->ID ) && current_user_can( 'manage_options' );
		$on      = self::enabled( $user->ID );
		$limit   = self::user_limit();
		$nonce   = wp_create_nonce( 'ntsa_2fa_' . $user->ID );
		$backups = count( (array) get_user_meta( $user->ID, 'ntsa_2fa_backup', true ) );
		?>
		<h2 id="ntsa-2fa"><?php esc_html_e( 'Two-factor login', 'nodethemes-security-ai' ); ?></h2>
		<table class="form-table" role="presentation"><tr><th><?php esc_html_e( 'Status', 'nodethemes-security-ai' ); ?></th><td>
		<div id="ntsa-2fa-box" data-user="<?php echo (int) $user->ID; ?>" data-nonce="<?php echo esc_attr( $nonce ); ?>">
		<?php if ( $on ) : ?>
			<p><span class="dashicons dashicons-yes-alt" style="color:#16a34a"></span> <strong><?php esc_html_e( 'On', 'nodethemes-security-ai' ); ?></strong> &middot;
			<?php
			/* translators: %d: number of backup codes */
			echo esc_html( sprintf( _n( '%d backup code left', '%d backup codes left', $backups, 'nodethemes-security-ai' ), $backups ) );
			?>
			</p>
			<p>
				<?php if ( $own ) : ?>
					<button type="button" class="button" id="ntsa-2fa-backup"><?php esc_html_e( 'Make new backup codes', 'nodethemes-security-ai' ); ?></button>
				<?php endif; ?>
				<?php if ( $own || $admin ) : ?>
					<button type="button" class="button" id="ntsa-2fa-disable"><?php esc_html_e( 'Turn off', 'nodethemes-security-ai' ); ?></button>
				<?php endif; ?>
			</p>
		<?php elseif ( ! $own ) : ?>
			<p><?php esc_html_e( 'Off. Only the user can turn it on, from their own profile.', 'nodethemes-security-ai' ); ?></p>
		<?php elseif ( ! self::can_enable( $user->ID ) ) : ?>
			<p>
				<?php
				/* translators: %d: number of users */
				echo esc_html( sprintf( _n( 'The free version protects %d account with two-factor login, and it is already in use on this site.', 'The free version protects %d accounts with two-factor login, and they are already in use on this site.', $limit, 'nodethemes-security-ai' ), $limit ) );
				?>
			</p>
			<p><?php echo NTSA_Admin::lock( __( 'Two-factor login for every user', 'nodethemes-security-ai' ) ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- escaped in lock(). ?></p>
		<?php else : ?>
			<p><?php esc_html_e( 'Off. Turn it on so a stolen password alone is not enough to log in.', 'nodethemes-security-ai' ); ?></p>
			<p><button type="button" class="button button-primary" id="ntsa-2fa-start"><?php esc_html_e( 'Set up two-factor login', 'nodethemes-security-ai' ); ?></button></p>
			<div id="ntsa-2fa-setup" hidden></div>
		<?php endif; ?>
		<div id="ntsa-2fa-codes" hidden></div>
		</div>
		</td></tr></table>
		<?php
	}

	/**
	 * AJAX guard: returns the target user ID.
	 *
	 * @param bool $own_only Only the user themself.
	 * @return int
	 */
	private static function ajax_user( $own_only ) {
		$uid = isset( $_POST['user'] ) ? absint( $_POST['user'] ) : 0;
		check_ajax_referer( 'ntsa_2fa_' . $uid, 'nonce' );
		$own = get_current_user_id() === $uid;
		if ( ! $uid || ( $own_only && ! $own ) || ( ! $own && ! ( current_user_can( 'edit_user', $uid ) && current_user_can( 'manage_options' ) ) ) ) {
			wp_send_json_error( array( 'message' => __( 'You do not have permission to do this.', 'nodethemes-security-ai' ) ), 403 );
		}
		return $uid;
	}

	/**
	 * Start setup: new pending secret.
	 */
	public static function ajax_start() {
		$uid = self::ajax_user( true );
		if ( ! self::can_enable( $uid ) ) {
			wp_send_json_error( array( 'message' => __( 'The free version allows two-factor login for one account only.', 'nodethemes-security-ai' ) ) );
		}
		$secret = NTSA_TOTP::new_secret();
		update_user_meta( $uid, 'ntsa_2fa_pending', self::crypt( $secret ) );
		$u = get_userdata( $uid );
		wp_send_json_success(
			array(
				'secret' => trim( chunk_split( $secret, 4, ' ' ) ),
				'uri'    => NTSA_TOTP::uri( $secret, $u->user_login, wp_specialchars_decode( get_bloginfo( 'name' ), ENT_QUOTES ) ),
			)
		);
	}

	/**
	 * Confirm setup with a first code.
	 */
	public static function ajax_confirm() {
		$uid    = self::ajax_user( true );
		$secret = self::secret( $uid, 'ntsa_2fa_pending' );
		$code   = isset( $_POST['code'] ) ? sanitize_text_field( wp_unslash( $_POST['code'] ) ) : ''; // phpcs:ignore WordPress.Security.NonceVerification.Missing -- checked in ajax_user().
		$step   = NTSA_TOTP::verify( $secret, $code );
		if ( '' === $secret || false === $step ) {
			wp_send_json_error( array( 'message' => __( 'That code is not right. Check that the time on your phone is set automatically, then try the newest code.', 'nodethemes-security-ai' ) ) );
		}
		if ( ! self::can_enable( $uid ) ) {
			wp_send_json_error( array( 'message' => __( 'The free version allows two-factor login for one account only.', 'nodethemes-security-ai' ) ) );
		}
		update_user_meta( $uid, 'ntsa_2fa_secret', self::crypt( $secret ) );
		update_user_meta( $uid, 'ntsa_2fa_last', $step );
		update_user_meta( $uid, 'ntsa_2fa_on', '1' );
		delete_user_meta( $uid, 'ntsa_2fa_pending' );
		NTSA_Log::add( '2fa_on', '', array(), 1, $uid );
		wp_send_json_success( array( 'codes' => self::new_backup_codes( $uid ) ) );
	}

	/**
	 * Turn off (own account, or an administrator for another user).
	 */
	public static function ajax_disable() {
		$uid = self::ajax_user( false );
		foreach ( array( 'ntsa_2fa_on', 'ntsa_2fa_secret', 'ntsa_2fa_pending', 'ntsa_2fa_backup', 'ntsa_2fa_last' ) as $k ) {
			delete_user_meta( $uid, $k );
		}
		$u = get_userdata( $uid );
		NTSA_Log::add( '2fa_off', $u ? $u->user_login : '', array(), 2 );
		wp_send_json_success();
	}

	/**
	 * New backup codes.
	 */
	public static function ajax_backup() {
		$uid = self::ajax_user( true );
		if ( ! self::enabled( $uid ) ) {
			wp_send_json_error();
		}
		wp_send_json_success( array( 'codes' => self::new_backup_codes( $uid ) ) );
	}
}
