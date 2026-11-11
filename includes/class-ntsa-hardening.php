<?php
/**
 * Hardening: one-click settings that close common doors.
 *
 * Every item is tested right after you turn it on: the plugin loads your home page and login page
 * again, and if either stops working the item is turned off at once. Turning an item off is always
 * possible (also in the free version and after a Pro license ends).
 *
 * @package NodeThemes_Security_AI
 */

defined( 'ABSPATH' ) || exit;

/**
 * Hardening.
 */
class NTSA_Hardening {

	const MARKER = 'NodeThemes Security AI';

	/**
	 * Hooks: run the PHP side of the switched-on items.
	 */
	public static function init() {
		if ( ntsa_safe_mode() ) {
			return;
		}
		$on = (array) NTSA_Settings::get( 'hardening', array() );
		if ( ! empty( $on['file_editor'] ) ) {
			add_filter( 'map_meta_cap', array( __CLASS__, 'no_file_editor' ), 10, 2 );
		}
		if ( ! empty( $on['hide_version'] ) ) {
			remove_action( 'wp_head', 'wp_generator' );
			add_filter( 'the_generator', '__return_empty_string' );
			add_filter( 'script_loader_src', array( __CLASS__, 'mask_version' ), 20 );
			add_filter( 'style_loader_src', array( __CLASS__, 'mask_version' ), 20 );
		}
		if ( ! empty( $on['xmlrpc_off'] ) ) {
			add_filter( 'xmlrpc_enabled', '__return_false' );
			add_filter( 'xmlrpc_methods', '__return_empty_array' );
			add_filter( 'wp_headers', array( __CLASS__, 'no_pingback_header' ) );
			remove_action( 'wp_head', 'rsd_link' );
			if ( defined( 'XMLRPC_REQUEST' ) && XMLRPC_REQUEST ) {
				status_header( 403 );
				exit( 'XML-RPC is turned off on this site.' );
			}
		}
		if ( ! empty( $on['user_enum'] ) ) {
			add_action( 'template_redirect', array( __CLASS__, 'no_author_scan' ), 1 );
			add_filter( 'rest_endpoints', array( __CLASS__, 'no_rest_users' ) );
			add_filter( 'wp_sitemaps_add_provider', array( __CLASS__, 'no_user_sitemap' ), 10, 2 );
		}
		if ( ! empty( $on['login_errors'] ) ) {
			add_filter( 'authenticate', array( __CLASS__, 'generic_login_error' ), 999 );
		}
		do_action( 'ntsa_hardening_init', $on );
	}

	/**
	 * All items (Pro adds its own through the ntsa_hardening_items filter).
	 *
	 * @return array id => array( title, desc, pro, warn ).
	 */
	public static function items() {
		$items = array(
			'file_editor'  => array(
				'title' => __( 'Turn off the file editor in the dashboard', 'nodethemes-security-ai' ),
				'desc'  => __( 'Hides Appearance › Theme File Editor and Plugins › Plugin File Editor, so a stolen admin login cannot be used to add code to your theme or plugins.', 'nodethemes-security-ai' ),
				'pro'   => false,
				'warn'  => '',
			),
			'hide_version' => array(
				'title' => __( 'Hide the WordPress version', 'nodethemes-security-ai' ),
				'desc'  => __( 'Removes the version from the page source and from script and style links, so bots cannot pick your site by its version number.', 'nodethemes-security-ai' ),
				'pro'   => false,
				'warn'  => '',
			),
			'xmlrpc_off'   => array(
				'title' => __( 'Turn off XML-RPC', 'nodethemes-security-ai' ),
				'desc'  => __( 'XML-RPC is an old remote-access door that bots use for password guessing and pingback attacks. Most sites do not need it.', 'nodethemes-security-ai' ),
				'pro'   => false,
				'warn'  => __( 'Leave it on if you use Jetpack, the WordPress mobile app or a desktop blogging app.', 'nodethemes-security-ai' ),
			),
			'user_enum'    => array(
				'title' => __( 'Hide usernames from bots', 'nodethemes-security-ai' ),
				'desc'  => __( 'Stops the "?author=1" trick, hides the user list in the REST API from visitors who are not logged in, and removes users from the sitemap.', 'nodethemes-security-ai' ),
				'pro'   => false,
				'warn'  => '',
			),
			'login_errors' => array(
				'title' => __( 'Do not reveal which part of a login was wrong', 'nodethemes-security-ai' ),
				'desc'  => __( 'Shows "Wrong username or password" instead of telling a bot that the username exists.', 'nodethemes-security-ai' ),
				'pro'   => false,
				'warn'  => '',
			),
		);
		$pro   = array(
			'uploads_php'      => __( 'Block PHP files from running in the uploads folder', 'nodethemes-security-ai' ),
			'protect_files'    => __( 'Block web access to wp-config.php, readme.html, debug.log and other private files', 'nodethemes-security-ai' ),
			'no_indexes'       => __( 'Turn off folder listings', 'nodethemes-security-ai' ),
			'security_headers' => __( 'Add security headers (clickjacking and MIME-sniffing protection)', 'nodethemes-security-ai' ),
			'no_app_passwords' => __( 'Turn off application passwords', 'nodethemes-security-ai' ),
			'table_prefix'     => __( 'Change the database table prefix (old tables kept as a backup)', 'nodethemes-security-ai' ),
		);
		foreach ( $pro as $id => $title ) {
			$items[ $id ] = array(
				'title' => $title,
				'desc'  => '',
				'pro'   => true,
				'warn'  => '',
			);
		}
		return apply_filters( 'ntsa_hardening_items', $items );
	}

	/**
	 * Is an item on?
	 *
	 * @param string $id Item.
	 * @return bool
	 */
	public static function is_on( $id ) {
		$on = (array) NTSA_Settings::get( 'hardening', array() );
		return ! empty( $on[ $id ] );
	}

	/**
	 * Switch an item on or off, then test the site and undo if it broke.
	 *
	 * @param string $id Item.
	 * @param bool   $on On.
	 * @return true|WP_Error
	 */
	public static function set( $id, $on ) {
		$items = self::items();
		if ( ! isset( $items[ $id ] ) ) {
			return new WP_Error( 'ntsa_item', __( 'Unknown item.', 'nodethemes-security-ai' ) );
		}
		if ( $on && $items[ $id ]['pro'] && ! ntsa_is_pro() ) {
			return new WP_Error( 'ntsa_pro', __( 'This item is part of NodeThemes Security AI Pro.', 'nodethemes-security-ai' ) );
		}
		$before = $on ? self::probe() : array();
		$state  = (array) NTSA_Settings::get( 'hardening', array() );
		if ( $on ) {
			$state[ $id ] = 1;
		} else {
			unset( $state[ $id ] );
		}
		// Server-side part (Pro items): apply / remove.
		$r = apply_filters( 'ntsa_hardening_apply', true, $id, $on );
		if ( is_wp_error( $r ) ) {
			return $r;
		}
		NTSA_Settings::update( array( 'hardening' => $state ) );
		if ( ! $on ) {
			return true;
		}
		$after = self::probe();
		$broke = self::broken( $before, $after );
		if ( '' !== $broke ) {
			unset( $state[ $id ] );
			apply_filters( 'ntsa_hardening_apply', true, $id, false );
			NTSA_Settings::update( array( 'hardening' => $state ) );
			/* translators: %s: what stopped working */
			return new WP_Error( 'ntsa_broke', sprintf( __( 'This setting was turned off again because %s stopped working after it was turned on. Your site is back as it was.', 'nodethemes-security-ai' ), $broke ) );
		}
		return true;
	}

	/**
	 * Load the home and login pages (as a visitor) and note the HTTP status.
	 *
	 * @return array url-key => status (0 = could not connect).
	 */
	public static function probe() {
		$out = array();
		foreach ( array( 'home' => home_url( '/' ), 'login' => wp_login_url() ) as $k => $url ) {
			$r         = wp_remote_get(
				add_query_arg( 'ntsa_probe', wp_rand( 1000, 999999 ), $url ),
				array(
					'timeout'     => 15,
					'redirection' => 3,
					'sslverify'   => false,
					'headers'     => array( 'Cache-Control' => 'no-cache' ),
					'user-agent'  => 'Mozilla/5.0 (NodeThemes Security AI site check)',
				)
			);
			$out[ $k ] = is_wp_error( $r ) ? 0 : (int) wp_remote_retrieve_response_code( $r );
		}
		return $out;
	}

	/**
	 * Did a page break between two probes?
	 *
	 * @param array $before Before.
	 * @param array $after  After.
	 * @return string What broke ('' = fine, or the check could not run).
	 */
	public static function broken( $before, $after ) {
		$names = array(
			'home'  => __( 'your home page', 'nodethemes-security-ai' ),
			'login' => __( 'your login page', 'nodethemes-security-ai' ),
		);
		foreach ( $before as $k => $code ) {
			$now = isset( $after[ $k ] ) ? (int) $after[ $k ] : 0;
			if ( $code >= 200 && $code < 400 && ( $now >= 400 || 0 === $now ) ) {
				return $names[ $k ];
			}
		}
		return '';
	}

	/**
	 * Remove every server rule we added (on deactivation, and from the hardening screen).
	 */
	public static function remove_server_rules() {
		require_once ABSPATH . 'wp-admin/includes/misc.php';
		$files = array( ABSPATH . '.htaccess' );
		$up    = wp_get_upload_dir();
		if ( ! empty( $up['basedir'] ) ) {
			$files[] = trailingslashit( $up['basedir'] ) . '.htaccess';
		}
		foreach ( $files as $f ) {
			if ( is_file( $f ) && is_writable( $f ) && false !== strpos( (string) file_get_contents( $f ), '# BEGIN ' . self::MARKER ) ) { // phpcs:ignore WordPress.WP.AlternativeFunctions
				insert_with_markers( $f, self::MARKER, array() );
			}
		}
		NTSA_Data::remove_prepend();
		do_action( 'ntsa_remove_server_rules' );
	}

	/* ---------------------------------------------------------------------
	 * Runtime parts of the free items
	 * ------------------------------------------------------------------ */

	/**
	 * No file editing capabilities.
	 *
	 * @param array  $caps Caps.
	 * @param string $cap  Cap.
	 * @return array
	 */
	public static function no_file_editor( $caps, $cap ) {
		if ( in_array( $cap, array( 'edit_themes', 'edit_plugins', 'edit_files' ), true ) ) {
			return array( 'do_not_allow' );
		}
		return $caps;
	}

	/**
	 * Replace ?ver=<WordPress version> with a hash that still changes after updates.
	 *
	 * @param string $src URL.
	 * @return string
	 */
	public static function mask_version( $src ) {
		global $wp_version;
		if ( is_string( $src ) && false !== strpos( $src, 'ver=' . $wp_version ) ) {
			$src = add_query_arg( 'ver', substr( md5( $wp_version . wp_salt( 'nonce' ) ), 0, 8 ), $src );
		}
		return $src;
	}

	/**
	 * No X-Pingback header.
	 *
	 * @param array $h Headers.
	 * @return array
	 */
	public static function no_pingback_header( $h ) {
		unset( $h['X-Pingback'] );
		return $h;
	}

	/**
	 * Stop ?author=N scans by visitors.
	 */
	public static function no_author_scan() {
		if ( isset( $_GET['author'] ) && ! current_user_can( 'list_users' ) ) { // phpcs:ignore WordPress.Security.NonceVerification.Recommended
			wp_safe_redirect( home_url( '/' ), 301 );
			exit;
		}
	}

	/**
	 * Hide REST user endpoints from visitors who are not logged in.
	 *
	 * @param array $endpoints Endpoints.
	 * @return array
	 */
	public static function no_rest_users( $endpoints ) {
		if ( is_user_logged_in() ) {
			return $endpoints;
		}
		foreach ( array_keys( $endpoints ) as $route ) {
			if ( 0 === strpos( $route, '/wp/v2/users' ) ) {
				unset( $endpoints[ $route ] );
			}
		}
		return $endpoints;
	}

	/**
	 * No users sitemap.
	 *
	 * @param mixed  $provider Provider.
	 * @param string $name     Name.
	 * @return mixed
	 */
	public static function no_user_sitemap( $provider, $name ) {
		return 'users' === $name ? false : $provider;
	}

	/**
	 * One message for wrong username, e-mail or password.
	 *
	 * @param WP_User|WP_Error|null $user Result.
	 * @return WP_User|WP_Error|null
	 */
	public static function generic_login_error( $user ) {
		if ( is_wp_error( $user ) && array_intersect( $user->get_error_codes(), array( 'invalid_username', 'incorrect_password', 'invalid_email' ) ) ) {
			return new WP_Error( 'ntsa_wrong_login', __( '<strong>Error:</strong> Wrong username or password.', 'nodethemes-security-ai' ) );
		}
		return $user;
	}

	/**
	 * Done / total (for the dashboard).
	 *
	 * @return array array( done, total ).
	 */
	public static function progress() {
		$items = self::items();
		$done  = 0;
		foreach ( array_keys( $items ) as $id ) {
			$done += self::is_on( $id ) ? 1 : 0;
		}
		return array( $done, count( $items ) );
	}
}
