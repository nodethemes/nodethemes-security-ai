<?php
/**
 * Admin screens.
 *
 * @package NodeThemes_Security_AI
 */

defined( 'ABSPATH' ) || exit;

/**
 * Admin.
 */
class NTSA_Admin {

	const SLUG = 'ntsa';

	/**
	 * Hooks.
	 */
	public static function init() {
		add_action( 'admin_menu', array( __CLASS__, 'menu' ) );
		add_action( 'admin_enqueue_scripts', array( __CLASS__, 'assets' ) );
		add_filter( 'plugin_action_links_' . NTSA_BASENAME, array( __CLASS__, 'action_links' ) );
		add_action( 'wp_dashboard_setup', array( __CLASS__, 'dashboard_widget' ) );
		add_action( 'admin_notices', array( __CLASS__, 'notices' ) );
		$posts = array( 'save_firewall', 'save_login', 'save_settings', 'unlock_ip', 'fw_exception', 'fw_exception_del', 'harden', 'remove_rules', 'integrity_ok', 'malware_ignore', 'vuln_toggle' );
		foreach ( $posts as $p ) {
			add_action( 'admin_post_ntsa_' . $p, array( __CLASS__, 'post_' . $p ) );
		}
		foreach ( array( 'integrity_core', 'malware_start', 'malware_step', 'vuln_run' ) as $a ) {
			add_action( 'wp_ajax_ntsa_' . $a, array( __CLASS__, 'ajax_' . $a ) );
		}
	}

	/**
	 * Menu.
	 */
	public static function menu() {
		add_menu_page(
			__( 'NodeThemes Security AI', 'nodethemes-security-ai' ),
			__( 'Security AI', 'nodethemes-security-ai' ),
			'manage_options',
			self::SLUG,
			array( __CLASS__, 'page' ),
			'dashicons-shield',
			81
		);
	}

	/**
	 * Plugin row links.
	 *
	 * @param array $links Links.
	 * @return array
	 */
	public static function action_links( $links ) {
		array_unshift( $links, '<a href="' . esc_url( admin_url( 'admin.php?page=' . self::SLUG ) ) . '">' . esc_html__( 'Settings', 'nodethemes-security-ai' ) . '</a>' );
		if ( ! ntsa_pro_installed() ) {
			$links[] = '<a href="' . esc_url( NTSA_PRO_URL ) . '" target="_blank" rel="noopener" style="color:#b45309;font-weight:600">' . esc_html__( 'Get Pro', 'nodethemes-security-ai' ) . '</a>';
		}
		return $links;
	}

	/**
	 * Styles and scripts.
	 *
	 * @param string $hook Screen.
	 */
	public static function assets( $hook ) {
		if ( false === strpos( (string) $hook, self::SLUG ) && 'index.php' !== $hook ) {
			return;
		}
		wp_enqueue_style( 'ntsa-admin', NTSA_URL . 'assets/admin.css', array(), NTSA_VERSION );
		if ( false === strpos( (string) $hook, self::SLUG ) ) {
			return;
		}
		wp_enqueue_script( 'ntsa-admin', NTSA_URL . 'assets/admin.js', array( 'jquery' ), NTSA_VERSION, true );
		wp_localize_script(
			'ntsa-admin',
			'NTSA',
			array(
				'ajax'  => admin_url( 'admin-ajax.php' ),
				'nonce' => wp_create_nonce( 'ntsa_ajax' ),
				'i18n'  => array(
					'working' => __( 'Working…', 'nodethemes-security-ai' ),
					'scanned' => __( 'Scanned %1$d of %2$d files', 'nodethemes-security-ai' ),
					'done'    => __( 'Done. Reloading…', 'nodethemes-security-ai' ),
					'error'   => __( 'Something went wrong. Please reload the page and try again.', 'nodethemes-security-ai' ),
				),
			)
		);
	}

	/* ---------------------------------------------------------------------
	 * Helpers
	 * ------------------------------------------------------------------ */

	/**
	 * Locked PRO button.
	 *
	 * @param string $label Label.
	 * @return string HTML.
	 */
	public static function lock( $label ) {
		return '<a class="button ntsa-lock" href="' . esc_url( ntsa_upgrade_url() ) . '"' . ( ntsa_pro_installed() ? '' : ' target="_blank" rel="noopener"' ) . '><span class="dashicons dashicons-lock"></span> ' . esc_html( $label ) . ' <span class="ntsa-pro">PRO</span></a>';
	}

	/**
	 * URL of a tab.
	 *
	 * @param string $tab  Tab.
	 * @param array  $args Extra args.
	 * @return string
	 */
	public static function url( $tab = 'dashboard', $args = array() ) {
		return add_query_arg( array_merge( array( 'page' => self::SLUG, 'tab' => $tab ), $args ), admin_url( 'admin.php' ) );
	}

	/**
	 * Admin-post form start.
	 *
	 * @param string $action Action.
	 */
	private static function form_open( $action ) {
		echo '<form method="post" action="' . esc_url( admin_url( 'admin-post.php' ) ) . '">';
		echo '<input type="hidden" name="action" value="ntsa_' . esc_attr( $action ) . '">';
		wp_nonce_field( 'ntsa_' . $action );
	}

	/**
	 * Link that runs an admin-post action.
	 *
	 * @param string $action Action.
	 * @param array  $args   Args.
	 * @return string
	 */
	private static function action_url( $action, $args = array() ) {
		return wp_nonce_url( add_query_arg( array_merge( array( 'action' => 'ntsa_' . $action ), $args ), admin_url( 'admin-post.php' ) ), 'ntsa_' . $action );
	}

	/**
	 * Check a handler request.
	 *
	 * @param string $action Action.
	 */
	private static function guard( $action ) {
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( esc_html__( 'You do not have permission to do this.', 'nodethemes-security-ai' ), 403 );
		}
		check_admin_referer( 'ntsa_' . $action );
	}

	/**
	 * Redirect back with a message.
	 *
	 * @param string $tab  Tab.
	 * @param string $type success|error|warning.
	 * @param string $msg  Message.
	 */
	private static function back( $tab, $type, $msg ) {
		set_transient( 'ntsa_msg_' . get_current_user_id(), array( $type, $msg ), 120 );
		wp_safe_redirect( self::url( $tab ) );
		exit;
	}

	/**
	 * AJAX guard.
	 */
	private static function ajax_guard() {
		check_ajax_referer( 'ntsa_ajax', 'nonce' );
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error( array( 'message' => __( 'You do not have permission to do this.', 'nodethemes-security-ai' ) ), 403 );
		}
	}

	/**
	 * Date in the site's format.
	 *
	 * @param int $ts Timestamp.
	 * @return string
	 */
	public static function when( $ts ) {
		if ( ! $ts ) {
			return __( 'never', 'nodethemes-security-ai' );
		}
		return wp_date( get_option( 'date_format' ) . ' ' . get_option( 'time_format' ), (int) $ts );
	}

	/**
	 * Status pill.
	 *
	 * @param string $type ok|bad|warn|off.
	 * @param string $text Text.
	 * @return string
	 */
	public static function pill( $type, $text ) {
		return '<span class="ntsa-pill ntsa-pill-' . esc_attr( $type ) . '">' . esc_html( $text ) . '</span>';
	}

	/* ---------------------------------------------------------------------
	 * Page
	 * ------------------------------------------------------------------ */

	/**
	 * Tabs.
	 *
	 * @return array
	 */
	public static function tabs() {
		$tabs = array(
			'dashboard' => __( 'Overview', 'nodethemes-security-ai' ),
			'firewall'  => __( 'Firewall', 'nodethemes-security-ai' ),
			'login'     => __( 'Login & 2FA', 'nodethemes-security-ai' ),
			'scans'     => __( 'Scans', 'nodethemes-security-ai' ),
			'vulns'     => __( 'Vulnerabilities', 'nodethemes-security-ai' ),
			'log'       => __( 'Activity log', 'nodethemes-security-ai' ),
			'hardening' => __( 'Hardening', 'nodethemes-security-ai' ),
			'settings'  => __( 'Settings', 'nodethemes-security-ai' ),
		);
		$tabs = apply_filters( 'ntsa_admin_tabs', $tabs );
		if ( ! ntsa_is_pro() ) {
			$tabs['pro'] = __( 'Pro', 'nodethemes-security-ai' );
		}
		return $tabs;
	}

	/**
	 * Main page.
	 */
	public static function page() {
		if ( ! current_user_can( 'manage_options' ) ) {
			return;
		}
		$tabs = self::tabs();
		$tab  = isset( $_GET['tab'] ) ? sanitize_key( wp_unslash( $_GET['tab'] ) ) : 'dashboard'; // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- tab switch only.
		$tab  = isset( $tabs[ $tab ] ) ? $tab : 'dashboard';
		?>
		<div class="wrap ntsa-wrap">
			<div class="ntsa-head">
				<div>
					<h1><?php esc_html_e( 'NodeThemes Security AI', 'nodethemes-security-ai' ); ?> <span class="ntsa-ver"><?php echo esc_html( NTSA_VERSION ); ?></span><?php echo ntsa_is_pro() ? ' <span class="ntsa-pro">PRO</span>' : ''; ?></h1>
					<p><?php esc_html_e( 'Firewall, login protection, scans and safe hardening for WordPress and WooCommerce.', 'nodethemes-security-ai' ); ?></p>
				</div>
				<?php if ( ntsa_safe_mode() ) : ?>
					<span class="ntsa-pill ntsa-pill-bad"><?php esc_html_e( 'Safe mode: protection paused (NTSA_SAFE_MODE)', 'nodethemes-security-ai' ); ?></span>
				<?php endif; ?>
			</div>
			<hr class="wp-header-end">
			<?php self::flash(); ?>
			<nav class="nav-tab-wrapper ntsa-tabs">
				<?php foreach ( $tabs as $k => $label ) : ?>
					<a class="nav-tab<?php echo $k === $tab ? ' nav-tab-active' : ''; ?>" href="<?php echo esc_url( self::url( $k ) ); ?>"><?php echo esc_html( $label ); ?><?php echo 'pro' === $k ? ' <span class="ntsa-pro">PRO</span>' : ''; ?></a>
				<?php endforeach; ?>
			</nav>
			<?php
			$method = 'tab_' . $tab;
			if ( method_exists( __CLASS__, $method ) ) {
				self::$method();
			} else {
				do_action( 'ntsa_admin_tab_' . $tab );
			}
			?>
		</div>
		<?php
	}

	/**
	 * Message after a redirect.
	 */
	private static function flash() {
		$k = 'ntsa_msg_' . get_current_user_id();
		$m = get_transient( $k );
		if ( is_array( $m ) ) {
			delete_transient( $k );
			echo '<div class="notice notice-' . esc_attr( $m[0] ) . ' is-dismissible"><p>' . esc_html( $m[1] ) . '</p></div>';
		}
	}

	/**
	 * Things to do (for the overview and the dashboard widget).
	 *
	 * @return array List of array( level bad|warn|ok, text, tab ).
	 */
	public static function checklist() {
		$out  = array();
		$mode = NTSA_Settings::get( 'fw_mode' );
		$out[] = 'block' === $mode
			? array( 'ok', __( 'Firewall is blocking attacks.', 'nodethemes-security-ai' ), 'firewall' )
			: array( 'bad', 'monitor' === $mode ? __( 'Firewall only records attacks (monitor mode). Switch it to Block.', 'nodethemes-security-ai' ) : __( 'Firewall is off.', 'nodethemes-security-ai' ), 'firewall' );
		$out[] = NTSA_Settings::get( 'login_on' )
			? array( 'ok', __( 'Failed-login limits and lockouts are on.', 'nodethemes-security-ai' ), 'login' )
			: array( 'bad', __( 'Failed-login limits are off: bots can guess passwords without limit.', 'nodethemes-security-ai' ), 'login' );
		$out[] = NTSA_TwoFA::enabled( get_current_user_id() )
			? array( 'ok', __( 'Your account uses two-factor login.', 'nodethemes-security-ai' ), 'login' )
			: array( 'warn', __( 'Turn on two-factor login for your administrator account.', 'nodethemes-security-ai' ), 'login' );

		$ir = NTSA_Integrity::result();
		$ip = NTSA_Integrity::problem_count();
		if ( null === $ip ) {
			$out[] = array( 'warn', __( 'Run the WordPress core file check once.', 'nodethemes-security-ai' ), 'scans' );
		} elseif ( $ip > 0 ) {
			/* translators: %d: number of files */
			$out[] = array( 'bad', sprintf( _n( '%d file differs from the original (see Scans).', '%d files differ from the original (see Scans).', $ip, 'nodethemes-security-ai' ), $ip ), 'scans' );
		} else {
			/* translators: %s: date */
			$out[] = array( 'ok', sprintf( __( 'WordPress core files match the originals (checked %s).', 'nodethemes-security-ai' ), self::when( isset( $ir['time'] ) ? $ir['time'] : 0 ) ), 'scans' );
		}

		$mr = NTSA_Malware::result();
		if ( empty( $mr['time'] ) ) {
			$out[] = array( 'warn', __( 'Run a malware scan.', 'nodethemes-security-ai' ), 'scans' );
		} elseif ( ! empty( $mr['findings'] ) ) {
			/* translators: %d: number */
			$out[] = array( 'bad', sprintf( _n( 'The malware scan found %d thing to review.', 'The malware scan found %d things to review.', count( $mr['findings'] ), 'nodethemes-security-ai' ), count( $mr['findings'] ) ), 'scans' );
		} else {
			/* translators: %s: date */
			$out[] = array( 'ok', sprintf( __( 'Malware scan found nothing (%s).', 'nodethemes-security-ai' ), self::when( $mr['time'] ) ), 'scans' );
		}

		if ( ! NTSA_Settings::get( 'vuln_enabled' ) ) {
			$out[] = array( 'warn', __( 'Turn on the known-vulnerability check for your plugins and themes.', 'nodethemes-security-ai' ), 'vulns' );
		} else {
			$vr = NTSA_Vuln::result();
			$n  = isset( $vr['items'] ) ? count( $vr['items'] ) : 0;
			if ( $n ) {
				/* translators: %d: number */
				$out[] = array( 'bad', sprintf( _n( '%d installed item has a known vulnerability.', '%d installed items have known vulnerabilities.', $n, 'nodethemes-security-ai' ), $n ), 'vulns' );
			} elseif ( ! empty( $vr['time'] ) ) {
				$out[] = array( 'ok', __( 'No known vulnerabilities in your plugins, themes or WordPress.', 'nodethemes-security-ai' ), 'vulns' );
			}
		}

		$upd = get_site_transient( 'update_plugins' );
		$n   = ( is_object( $upd ) && ! empty( $upd->response ) ) ? count( (array) $upd->response ) : 0;
		if ( $n ) {
			/* translators: %d: number */
			$out[] = array( 'warn', sprintf( _n( '%d plugin has an update waiting. Updates often fix security problems.', '%d plugins have updates waiting. Updates often fix security problems.', $n, 'nodethemes-security-ai' ), $n ), '' );
		}
		if ( defined( 'WP_DEBUG' ) && WP_DEBUG && ( ! defined( 'WP_DEBUG_DISPLAY' ) || WP_DEBUG_DISPLAY ) ) {
			$out[] = array( 'warn', __( 'WP_DEBUG shows PHP errors to visitors. Turn off WP_DEBUG_DISPLAY on a live site.', 'nodethemes-security-ai' ), '' );
		}
		if ( username_exists( 'admin' ) ) {
			$u = get_user_by( 'login', 'admin' );
			if ( $u && user_can( $u, 'manage_options' ) ) {
				$out[] = array( 'warn', __( 'An administrator is named "admin", the first name bots try. Consider a new administrator with another name.', 'nodethemes-security-ai' ), '' );
			}
		}
		list( $done, $total ) = NTSA_Hardening::progress();
		/* translators: 1: done, 2: total */
		$out[] = array( $done >= 5 ? 'ok' : 'warn', sprintf( __( 'Hardening: %1$d of %2$d settings on.', 'nodethemes-security-ai' ), $done, $total ), 'hardening' );
		return apply_filters( 'ntsa_checklist', $out );
	}

	/**
	 * Overview tab.
	 */
	private static function tab_dashboard() {
		$c      = NTSA_Firewall::counts( 7 );
		$locked = count( NTSA_Login::locked_list() );
		$list   = self::checklist();
		$bad    = count( array_filter( $list, function ( $i ) { return 'bad' === $i[0]; } ) ); // phpcs:ignore Universal.FunctionDeclarations.NoLongClosures
		$warn   = count( array_filter( $list, function ( $i ) { return 'warn' === $i[0]; } ) );
		?>
		<div class="ntsa-grid">
			<div class="ntsa-card">
				<h3><?php esc_html_e( 'Attacks blocked (7 days)', 'nodethemes-security-ai' ); ?></h3>
				<div class="ntsa-big"><?php echo (int) ( isset( $c['block'] ) ? $c['block'] : 0 ); ?></div>
				<p><?php echo isset( $c['monitor'] ) ? esc_html( sprintf( /* translators: %d: number */ __( '%d more recorded in monitor mode', 'nodethemes-security-ai' ), (int) $c['monitor'] ) ) : esc_html__( 'Harmful requests the firewall stopped.', 'nodethemes-security-ai' ); ?></p>
			</div>
			<div class="ntsa-card">
				<h3><?php esc_html_e( 'Login lockouts (7 days)', 'nodethemes-security-ai' ); ?></h3>
				<div class="ntsa-big"><?php echo (int) ( isset( $c['lockout'] ) ? $c['lockout'] : 0 ); ?></div>
				<p>
				<?php
				/* translators: %d: number */
				echo esc_html( sprintf( _n( '%d IP address locked right now', '%d IP addresses locked right now', $locked, 'nodethemes-security-ai' ), $locked ) );
				?>
				</p>
			</div>
			<div class="ntsa-card">
				<h3><?php esc_html_e( 'To review', 'nodethemes-security-ai' ); ?></h3>
				<div class="ntsa-big <?php echo $bad ? 'ntsa-bad' : ( $warn ? 'ntsa-warn' : 'ntsa-ok' ); ?>"><?php echo (int) ( $bad + $warn ); ?></div>
				<p><?php echo $bad ? esc_html__( 'Some items need attention now.', 'nodethemes-security-ai' ) : ( $warn ? esc_html__( 'A few recommended steps are left.', 'nodethemes-security-ai' ) : esc_html__( 'Everything looks good.', 'nodethemes-security-ai' ) ); ?></p>
			</div>
		</div>
		<div class="ntsa-card">
			<h2><?php esc_html_e( 'Security checklist', 'nodethemes-security-ai' ); ?></h2>
			<ul class="ntsa-check">
				<?php
				foreach ( $list as $i ) {
					$icon = 'ok' === $i[0] ? 'yes-alt' : ( 'bad' === $i[0] ? 'warning' : 'info' );
					echo '<li class="is-' . esc_attr( $i[0] ) . '"><span class="dashicons dashicons-' . esc_attr( $icon ) . '"></span> ';
					echo esc_html( $i[1] );
					if ( '' !== $i[2] && 'ok' !== $i[0] ) {
						echo ' <a href="' . esc_url( self::url( $i[2] ) ) . '">' . esc_html__( 'Open', 'nodethemes-security-ai' ) . ' &rarr;</a>';
					}
					echo '</li>';
				}
				?>
			</ul>
			<?php do_action( 'ntsa_overview_after_checklist' ); ?>
		</div>
		<?php
		if ( ! ntsa_is_pro() ) {
			self::pro_box();
		}
	}

	/**
	 * Firewall tab.
	 */
	private static function tab_firewall() {
		global $wpdb;
		$s    = NTSA_Settings::all();
		$rows = $wpdb->get_results( 'SELECT * FROM ' . NTSA_DB::table( 'fw' ) . " WHERE action IN ('block','monitor','ratelimit') ORDER BY id DESC LIMIT 50", ARRAY_A ); // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared,WordPress.DB.DirectDatabaseQuery
		?>
		<div class="ntsa-card">
			<h2><?php esc_html_e( 'Web application firewall', 'nodethemes-security-ai' ); ?></h2>
			<p><?php esc_html_e( 'Checks every request for SQL injection, cross-site scripting, path traversal, PHP code injection, attack tools and requests for private files, and blocks it before other plugins and your theme handle it. Administrators are never blocked; editors may post HTML.', 'nodethemes-security-ai' ); ?></p>
			<?php self::form_open( 'save_firewall' ); ?>
			<table class="form-table" role="presentation">
				<tr><th><?php esc_html_e( 'Mode', 'nodethemes-security-ai' ); ?></th><td>
					<?php
					$modes = array(
						'block'   => __( 'Block – stop attacks (recommended)', 'nodethemes-security-ai' ),
						'monitor' => __( 'Monitor – only record what would be blocked (to test first)', 'nodethemes-security-ai' ),
						'off'     => __( 'Off', 'nodethemes-security-ai' ),
					);
					foreach ( $modes as $k => $l ) {
						echo '<label class="ntsa-switch"><input type="radio" name="fw_mode" value="' . esc_attr( $k ) . '"' . checked( $s['fw_mode'], $k, false ) . '> ' . esc_html( $l ) . '</label>';
					}
					?>
				</td></tr>
				<tr><th><label for="ntsa-allow"><?php esc_html_e( 'Never block these IPs', 'nodethemes-security-ai' ); ?></label></th><td>
					<textarea id="ntsa-allow" name="fw_allow_ips" rows="3" class="large-text code" placeholder="203.0.113.10&#10;198.51.100.0/24"><?php echo esc_textarea( $s['fw_allow_ips'] ); ?></textarea>
					<p class="description">
					<?php
					/* translators: %s: IP */
					echo esc_html( sprintf( __( 'One IP or range per line. They are also never locked out. Your IP right now: %s', 'nodethemes-security-ai' ), NTSA_IP::get() ) );
					?>
					</p>
				</td></tr>
				<tr><th><label for="ntsa-block"><?php esc_html_e( 'Always block these IPs', 'nodethemes-security-ai' ); ?></label></th><td>
					<textarea id="ntsa-block" name="fw_block_ips" rows="3" class="large-text code"><?php echo esc_textarea( $s['fw_block_ips'] ); ?></textarea>
				</td></tr>
			</table>
			<?php submit_button( __( 'Save firewall settings', 'nodethemes-security-ai' ) ); ?>
			</form>
		</div>

		<?php do_action( 'ntsa_firewall_tab' ); ?>
		<?php if ( ! ntsa_is_pro() ) : ?>
			<div class="ntsa-card ntsa-feature">
				<h2><?php esc_html_e( 'More firewall protection', 'nodethemes-security-ai' ); ?> <span class="ntsa-pro">PRO</span></h2>
				<ul class="ntsa-list">
					<li><?php esc_html_e( 'Early firewall: runs before WordPress loads, so attacks use far less of your server.', 'nodethemes-security-ai' ); ?></li>
					<li><?php esc_html_e( 'Rate limiting: slows down bots that send too many requests.', 'nodethemes-security-ai' ); ?></li>
					<li><?php esc_html_e( 'Country blocking (with Cloudflare or your host’s country header).', 'nodethemes-security-ai' ); ?></li>
					<li><?php esc_html_e( 'Your own rules: block by user agent, URL or query text.', 'nodethemes-security-ai' ); ?></li>
				</ul>
				<p>
					<?php echo self::lock( __( 'Early firewall', 'nodethemes-security-ai' ) ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped ?>
					<?php echo self::lock( __( 'Rate limiting', 'nodethemes-security-ai' ) ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped ?>
					<?php echo self::lock( __( 'Country blocking', 'nodethemes-security-ai' ) ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped ?>
					<?php echo self::lock( __( 'Custom rules', 'nodethemes-security-ai' ) ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped ?>
				</p>
			</div>
		<?php endif; ?>

		<div class="ntsa-card">
			<h2><?php esc_html_e( 'Latest blocked requests', 'nodethemes-security-ai' ); ?></h2>
			<?php if ( ! $rows ) : ?>
				<p><?php esc_html_e( 'Nothing blocked yet.', 'nodethemes-security-ai' ); ?></p>
			<?php else : ?>
				<div class="ntsa-table-wrap"><table class="widefat striped ntsa-table">
					<thead><tr><th><?php esc_html_e( 'Time', 'nodethemes-security-ai' ); ?></th><th>IP</th><th><?php esc_html_e( 'Rule', 'nodethemes-security-ai' ); ?></th><th><?php esc_html_e( 'URL', 'nodethemes-security-ai' ); ?></th><th></th></tr></thead>
					<tbody>
					<?php foreach ( $rows as $r ) : ?>
						<?php $path = (string) wp_parse_url( $r['uri'], PHP_URL_PATH ); ?>
						<tr class="ntsa-finding" data-kind="firewall" data-ref="<?php echo (int) $r['id']; ?>">
							<td><?php echo esc_html( self::when( $r['ts'] ) ); ?><?php echo 'monitor' === $r['action'] ? ' ' . self::pill( 'warn', __( 'monitor', 'nodethemes-security-ai' ) ) : ''; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped ?></td>
							<td><code><?php echo esc_html( $r['ip'] ); ?></code></td>
							<td><?php echo esc_html( $r['detail'] ); ?></td>
							<td class="ntsa-break"><?php echo esc_html( $r['uri'] ); ?></td>
							<td>
								<?php if ( 'ip-block' !== $r['rule'] && 'ratelimit' !== $r['action'] ) : ?>
									<a class="button button-small" href="<?php echo esc_url( self::action_url( 'fw_exception', array( 'rule' => $r['rule'], 'path' => $path ) ) ); ?>" title="<?php esc_attr_e( 'This was a false alarm: stop using this rule for this address.', 'nodethemes-security-ai' ); ?>"><?php esc_html_e( 'Allow this', 'nodethemes-security-ai' ); ?></a>
								<?php endif; ?>
							</td>
						</tr>
					<?php endforeach; ?>
					</tbody>
				</table></div>
			<?php endif; ?>
			<?php $ex = (array) $s['fw_exceptions']; ?>
			<?php if ( $ex ) : ?>
				<h3 style="margin-top:18px"><?php esc_html_e( 'Exceptions (rules turned off for an address)', 'nodethemes-security-ai' ); ?></h3>
				<ul>
					<?php foreach ( $ex as $e ) : ?>
						<li><code><?php echo esc_html( $e ); ?></code> <a href="<?php echo esc_url( self::action_url( 'fw_exception_del', array( 'ex' => $e ) ) ); ?>"><?php esc_html_e( 'Remove', 'nodethemes-security-ai' ); ?></a></li>
					<?php endforeach; ?>
				</ul>
			<?php endif; ?>
		</div>
		<?php
	}

	/**
	 * Login tab.
	 */
	private static function tab_login() {
		$s      = NTSA_Settings::all();
		$locked = NTSA_Login::locked_list();
		$limit  = NTSA_TwoFA::user_limit();
		?>
		<div class="ntsa-card">
			<h2><?php esc_html_e( 'Failed-login limits', 'nodethemes-security-ai' ); ?></h2>
			<p><?php esc_html_e( 'Stops password guessing on wp-login.php, the WooCommerce login form and XML-RPC by pausing logins from an IP address after too many wrong passwords.', 'nodethemes-security-ai' ); ?></p>
			<?php self::form_open( 'save_login' ); ?>
			<table class="form-table" role="presentation">
				<tr><th><?php esc_html_e( 'Protection', 'nodethemes-security-ai' ); ?></th><td><label><input type="checkbox" name="login_on" value="1" <?php checked( $s['login_on'] ); ?>> <?php esc_html_e( 'Limit failed logins', 'nodethemes-security-ai' ); ?></label></td></tr>
				<tr><th><?php esc_html_e( 'Rule', 'nodethemes-security-ai' ); ?></th><td class="ntsa-inline">
					<?php
					printf(
						/* translators: 1: attempts field, 2: minutes field, 3: lockout minutes field */
						esc_html__( 'After %1$s failed logins within %2$s minutes, lock the IP for %3$s minutes.', 'nodethemes-security-ai' ),
						'<input type="number" min="2" max="50" name="login_max" value="' . (int) $s['login_max'] . '" class="small-text">',
						'<input type="number" min="1" max="1440" name="login_window" value="' . (int) $s['login_window'] . '" class="small-text">',
						'<input type="number" min="1" max="10080" name="login_lock" value="' . (int) $s['login_lock'] . '" class="small-text">'
					);
					?>
				</td></tr>
				<tr><th><?php esc_html_e( 'Repeat offenders', 'nodethemes-security-ai' ); ?></th><td class="ntsa-inline">
					<?php
					printf(
						/* translators: 1: lockouts field, 2: hours field */
						esc_html__( 'After %1$s lockouts in 24 hours, lock the IP for %2$s hours.', 'nodethemes-security-ai' ),
						'<input type="number" min="2" max="50" name="login_long" value="' . (int) $s['login_long'] . '" class="small-text">',
						'<input type="number" min="1" max="720" name="login_long_hrs" value="' . (int) $s['login_long_hrs'] . '" class="small-text">'
					);
					?>
				</td></tr>
				<tr><th><?php esc_html_e( 'Strong passwords', 'nodethemes-security-ai' ); ?></th><td>
					<label class="ntsa-switch"><input type="radio" name="strong_pw" value="off" <?php checked( $s['strong_pw'], 'off' ); ?>> <?php esc_html_e( 'Off', 'nodethemes-security-ai' ); ?></label>
					<label class="ntsa-switch"><input type="radio" name="strong_pw" value="admins" <?php checked( $s['strong_pw'], 'admins' ); ?>> <?php esc_html_e( 'Administrators, editors and shop managers (recommended)', 'nodethemes-security-ai' ); ?></label>
					<?php if ( ntsa_is_pro() ) : ?>
						<label class="ntsa-switch"><input type="radio" name="strong_pw" value="all" <?php checked( $s['strong_pw'], 'all' ); ?>> <?php esc_html_e( 'Every user, customers included', 'nodethemes-security-ai' ); ?></label>
					<?php else : ?>
						<?php echo self::lock( __( 'Strong passwords for every user', 'nodethemes-security-ai' ) ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped ?>
					<?php endif; ?>
					<p class="description"><?php esc_html_e( 'At least 12 characters, three kinds of characters, no username and no very common words. Checked when a password is set or changed.', 'nodethemes-security-ai' ); ?></p>
				</td></tr>
			</table>
			<?php submit_button( __( 'Save login settings', 'nodethemes-security-ai' ) ); ?>
			</form>
		</div>

		<div class="ntsa-card">
			<h2><?php esc_html_e( 'IP addresses locked right now', 'nodethemes-security-ai' ); ?></h2>
			<?php if ( ! $locked ) : ?>
				<p><?php esc_html_e( 'None.', 'nodethemes-security-ai' ); ?></p>
			<?php else : ?>
				<div class="ntsa-table-wrap"><table class="widefat striped ntsa-table">
					<thead><tr><th>IP</th><th><?php esc_html_e( 'Last username tried', 'nodethemes-security-ai' ); ?></th><th><?php esc_html_e( 'Locked until', 'nodethemes-security-ai' ); ?></th><th></th></tr></thead>
					<tbody>
					<?php foreach ( $locked as $r ) : ?>
						<tr><td><code><?php echo esc_html( $r['ip'] ); ?></code></td><td><?php echo esc_html( $r['last_user'] ); ?></td><td><?php echo esc_html( self::when( $r['locked_until'] ) ); ?></td>
						<td><a class="button button-small" href="<?php echo esc_url( self::action_url( 'unlock_ip', array( 'ip' => $r['ip'] ) ) ); ?>"><?php esc_html_e( 'Unlock', 'nodethemes-security-ai' ); ?></a></td></tr>
					<?php endforeach; ?>
					</tbody>
				</table></div>
			<?php endif; ?>
		</div>

		<div class="ntsa-card">
			<h2><?php esc_html_e( 'Two-factor login (2FA)', 'nodethemes-security-ai' ); ?></h2>
			<p><?php esc_html_e( 'After the password, users enter a 6-digit code from an authenticator app on their phone. A stolen password alone is then not enough to log in. Each user turns it on in Users › Profile, and gets 10 one-time backup codes.', 'nodethemes-security-ai' ); ?></p>
			<p>
				<?php
				$n = NTSA_TwoFA::count_enabled();
				if ( $limit ) {
					/* translators: 1: users with 2FA, 2: limit */
					echo esc_html( sprintf( __( 'Accounts using two-factor login: %1$d of %2$d allowed in the free version.', 'nodethemes-security-ai' ), $n, $limit ) );
				} else {
					/* translators: %d: users */
					echo esc_html( sprintf( __( 'Accounts using two-factor login: %d.', 'nodethemes-security-ai' ), $n ) );
				}
				?>
			</p>
			<p><a class="button button-primary" href="<?php echo esc_url( admin_url( 'profile.php#ntsa-2fa' ) ); ?>"><?php esc_html_e( 'Set up two-factor login for my account', 'nodethemes-security-ai' ); ?></a>
			<?php
			if ( ! ntsa_is_pro() ) {
				echo self::lock( __( 'Two-factor login for every user', 'nodethemes-security-ai' ) ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
				echo self::lock( __( 'Require 2FA for chosen roles', 'nodethemes-security-ai' ) ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
			}
			?>
			</p>
			<p class="description"><?php esc_html_e( 'Locked out? Add define( \'NTSA_DISABLE_2FA\', true ); to wp-config.php, log in, then remove it again.', 'nodethemes-security-ai' ); ?></p>
			<?php do_action( 'ntsa_login_tab_2fa' ); ?>
		</div>
		<?php
	}

	/**
	 * Scans tab.
	 */
	private static function tab_scans() {
		$ir  = NTSA_Integrity::result();
		$mr  = NTSA_Malware::result();
		$job = NTSA_Malware::job();
		?>
		<div class="ntsa-card" id="ntsa-integrity">
			<h2><?php esc_html_e( 'WordPress core file check', 'nodethemes-security-ai' ); ?></h2>
			<p><?php esc_html_e( 'Compares every WordPress file with the official copy from WordPress.org and lists files that were changed, removed or added. Changed core files are a common sign of a hacked site.', 'nodethemes-security-ai' ); ?></p>
			<p>
				<button type="button" class="button button-primary" id="ntsa-run-integrity"><?php esc_html_e( 'Check WordPress files now', 'nodethemes-security-ai' ); ?></button>
				<span class="ntsa-status" id="ntsa-integrity-status">
				<?php
				/* translators: %s: date */
				echo esc_html( sprintf( __( 'Last check: %s', 'nodethemes-security-ai' ), self::when( isset( $ir['core'] ) && isset( $ir['time'] ) ? $ir['time'] : 0 ) ) );
				?>
				</span>
			</p>
			<?php
			if ( ! empty( $ir['core'] ) ) {
				self::integrity_list( $ir['core'], 'core' );
			}
			do_action( 'ntsa_scans_integrity', $ir );
			if ( ! ntsa_is_pro() ) {
				echo '<p>' . self::lock( __( 'Check plugins and themes too', 'nodethemes-security-ai' ) ) . self::lock( __( 'Automatic daily checks', 'nodethemes-security-ai' ) ) . '</p>'; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
			}
			?>
		</div>

		<div class="ntsa-card" id="ntsa-malware">
			<h2><?php esc_html_e( 'Malware scan', 'nodethemes-security-ai' ); ?></h2>
			<p><?php esc_html_e( 'Looks through your themes, plugins, uploads and WordPress folder for backdoors, web shells, hidden code and injected scripts. It only reports: nothing is deleted or changed.', 'nodethemes-security-ai' ); ?></p>
			<p>
				<?php if ( $job || NTSA_Malware::can_start() ) : ?>
					<button type="button" class="button button-primary" id="ntsa-run-malware"><?php echo $job ? esc_html__( 'Continue the scan', 'nodethemes-security-ai' ) : esc_html__( 'Scan for malware now', 'nodethemes-security-ai' ); ?></button>
				<?php else : ?>
					<button type="button" class="button" disabled><?php esc_html_e( 'Scan for malware now', 'nodethemes-security-ai' ); ?></button>
					<span class="ntsa-status">
					<?php
					/* translators: %s: date */
					echo esc_html( sprintf( __( 'The free version runs one scan per week. Next scan: %s', 'nodethemes-security-ai' ), self::when( NTSA_Malware::next_allowed() ) ) );
					?>
					</span>
				<?php endif; ?>
			</p>
			<div class="ntsa-bar" hidden><span id="ntsa-progress"></span></div>
			<p class="ntsa-status" id="ntsa-malware-status">
			<?php
			if ( ! empty( $mr['time'] ) ) {
				/* translators: 1: date, 2: files, 3: seconds */
				echo esc_html( sprintf( _n( 'Last scan: %1$s · %2$d files · %3$d second', 'Last scan: %1$s · %2$d files · %3$d seconds', max( 1, (int) $mr['secs'] ), 'nodethemes-security-ai' ), self::when( $mr['time'] ), (int) $mr['files'], max( 1, (int) $mr['secs'] ) ) );
				if ( ! empty( $mr['skipped'] ) ) {
					/* translators: %d: files */
					echo ' · ' . esc_html( sprintf( __( '%d files over 3 MB skipped', 'nodethemes-security-ai' ), (int) $mr['skipped'] ) );
				}
			}
			?>
			</p>
			<?php self::malware_list( $mr ); ?>
			<?php
			if ( ! ntsa_is_pro() ) {
				echo '<p>' . self::lock( __( 'Unlimited and scheduled scans', 'nodethemes-security-ai' ) ) . self::lock( __( 'Database scan (posts, widgets, settings)', 'nodethemes-security-ai' ) ) . self::lock( __( 'AI explanation of each finding', 'nodethemes-security-ai' ) ) . '</p>'; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
			}
			do_action( 'ntsa_scans_malware', $mr );
			?>
		</div>
		<?php
	}

	/**
	 * Integrity results.
	 *
	 * @param array  $part Part of the result.
	 * @param string $kind core|plugins|themes.
	 */
	public static function integrity_list( $part, $kind ) {
		$groups = array(
			'modified' => __( 'Changed files', 'nodethemes-security-ai' ),
			'missing'  => __( 'Missing files', 'nodethemes-security-ai' ),
			'unknown'  => __( 'Unknown files (not part of the original)', 'nodethemes-security-ai' ),
		);
		$any    = false;
		foreach ( $groups as $k => $label ) {
			$files = isset( $part[ $k ] ) ? (array) $part[ $k ] : array();
			if ( ! $files ) {
				continue;
			}
			$any = true;
			echo '<h3>' . esc_html( $label ) . ' (' . count( $files ) . ')</h3><ul class="ntsa-files">';
			foreach ( array_slice( $files, 0, 200 ) as $f ) {
				echo '<li class="ntsa-finding" data-kind="integrity" data-ref="' . esc_attr( $k . '|' . $f ) . '"><code>' . esc_html( $f ) . '</code> <a href="' . esc_url( self::action_url( 'integrity_ok', array( 'path' => $f ) ) ) . '">' . esc_html__( 'Mark as OK', 'nodethemes-security-ai' ) . '</a></li>';
			}
			echo '</ul>';
		}
		if ( ! $any ) {
			echo '<p class="ntsa-ok"><span class="dashicons dashicons-yes-alt"></span> ';
			if ( 'core' === $kind ) {
				/* translators: 1: number of files, 2: WordPress version */
				echo esc_html( sprintf( __( 'All %1$d WordPress %2$s files match the originals.', 'nodethemes-security-ai' ), (int) $part['checked'], $part['version'] ) );
			} else {
				esc_html_e( 'No changes found.', 'nodethemes-security-ai' );
			}
			echo '</p>';
		} elseif ( 'core' === $kind ) {
			echo '<p class="description">' . esc_html__( 'How to fix changed or missing WordPress files: go to Dashboard › Updates and click "Re-install version …". This replaces only WordPress itself, not your content, themes or plugins. Delete unknown files only after checking they are not yours.', 'nodethemes-security-ai' ) . '</p>';
		}
	}

	/**
	 * Malware findings.
	 *
	 * @param array $mr Result.
	 */
	private static function malware_list( $mr ) {
		if ( empty( $mr['time'] ) ) {
			return;
		}
		$f = isset( $mr['findings'] ) ? (array) $mr['findings'] : array();
		if ( ! $f ) {
			echo '<p class="ntsa-ok"><span class="dashicons dashicons-yes-alt"></span> ' . esc_html__( 'Nothing suspicious found.', 'nodethemes-security-ai' ) . '</p>';
			return;
		}
		$sev = array(
			3 => array( 'bad', __( 'Dangerous', 'nodethemes-security-ai' ) ),
			2 => array( 'warn', __( 'Suspicious', 'nodethemes-security-ai' ) ),
			1 => array( 'off', __( 'Info', 'nodethemes-security-ai' ) ),
		);
		echo '<div class="ntsa-table-wrap"><table class="widefat striped ntsa-table"><thead><tr><th>' . esc_html__( 'Level', 'nodethemes-security-ai' ) . '</th><th>' . esc_html__( 'File', 'nodethemes-security-ai' ) . '</th><th>' . esc_html__( 'What was found', 'nodethemes-security-ai' ) . '</th><th></th></tr></thead><tbody>';
		foreach ( $f as $i ) {
			$s = isset( $sev[ (int) $i['sev'] ] ) ? $sev[ (int) $i['sev'] ] : $sev[1];
			echo '<tr class="ntsa-finding" data-kind="malware" data-ref="' . esc_attr( $i['path'] . '|' . $i['sig'] ) . '"><td>' . self::pill( $s[0], $s[1] ) . '</td>'; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
			echo '<td class="ntsa-break"><code>' . esc_html( $i['path'] ) . '</code>' . ( $i['line'] ? ' <span class="description">' . esc_html( sprintf( /* translators: %d: line */ __( 'line %d', 'nodethemes-security-ai' ), (int) $i['line'] ) ) . '</span>' : '' ) . '</td>';
			echo '<td>' . esc_html( $i['label'] ) . ( '' !== $i['snippet'] ? '<br><code class="ntsa-snippet">' . esc_html( $i['snippet'] ) . '</code>' : '' ) . '</td>';
			echo '<td><a class="button button-small" href="' . esc_url( self::action_url( 'malware_ignore', array( 'path' => $i['path'], 'sig' => $i['sig'] ) ) ) . '">' . esc_html__( 'It’s safe – ignore', 'nodethemes-security-ai' ) . '</a></td></tr>';
		}
		echo '</tbody></table></div>';
		echo '<p class="description">' . esc_html__( 'What to do: if a file belongs to a plugin or theme, reinstall that plugin or theme from its original source. Files you do not recognise in uploads or the WordPress folder should be removed by you or your host after a backup. Change all passwords afterwards.', 'nodethemes-security-ai' ) . '</p>';
	}

	/**
	 * Vulnerabilities tab.
	 */
	private static function tab_vulns() {
		$on = NTSA_Settings::get( 'vuln_enabled' );
		$r  = NTSA_Vuln::result();
		?>
		<div class="ntsa-card">
			<h2><?php esc_html_e( 'Known vulnerabilities', 'nodethemes-security-ai' ); ?></h2>
			<p><?php esc_html_e( 'Checks your WordPress version, plugins and themes against the free WPVulnerability database, which collects reports from CVE, Wordfence, Patchstack, WPScan and others, and tells you what to update.', 'nodethemes-security-ai' ); ?></p>
			<?php if ( ! $on ) : ?>
				<div class="ntsa-pro-box">
					<p><strong><?php esc_html_e( 'This check is off.', 'nodethemes-security-ai' ); ?></strong> <?php esc_html_e( 'When you turn it on, the names and versions of your installed WordPress, plugins and themes are sent to wpvulnerability.net once a week. Nothing else is sent: no content, users or site settings.', 'nodethemes-security-ai' ); ?></p>
					<p><a class="button button-primary" href="<?php echo esc_url( self::action_url( 'vuln_toggle', array( 'on' => 1 ) ) ); ?>"><?php esc_html_e( 'Turn on the vulnerability check', 'nodethemes-security-ai' ); ?></a></p>
				</div>
			<?php else : ?>
				<p>
					<?php if ( NTSA_Vuln::can_run() ) : ?>
						<button type="button" class="button button-primary" id="ntsa-run-vuln"><?php esc_html_e( 'Check now', 'nodethemes-security-ai' ); ?></button>
					<?php else : ?>
						<button type="button" class="button" disabled><?php esc_html_e( 'Check now', 'nodethemes-security-ai' ); ?></button>
					<?php endif; ?>
					<span class="ntsa-status" id="ntsa-vuln-status">
					<?php
					/* translators: %s: date */
					echo esc_html( sprintf( __( 'Last check: %s', 'nodethemes-security-ai' ), self::when( isset( $r['time'] ) ? $r['time'] : 0 ) ) );
					if ( 'weekly' === NTSA_Vuln::frequency() ) {
						echo ' · ' . esc_html__( 'automatic once a week', 'nodethemes-security-ai' );
					} else {
						echo ' · ' . esc_html__( 'automatic every day', 'nodethemes-security-ai' );
					}
					?>
					</span>
					<a class="ntsa-small-link" href="<?php echo esc_url( self::action_url( 'vuln_toggle', array( 'on' => 0 ) ) ); ?>"><?php esc_html_e( 'Turn off', 'nodethemes-security-ai' ); ?></a>
				</p>
				<?php self::vuln_list( $r ); ?>
			<?php endif; ?>
			<?php
			if ( ! ntsa_is_pro() ) {
				echo '<p>' . self::lock( __( 'Daily checks', 'nodethemes-security-ai' ) ) . self::lock( __( 'E-mail and Telegram alerts', 'nodethemes-security-ai' ) ) . '</p>'; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
			}
			?>
			<p class="description"><?php echo wp_kses_post( __( 'Vulnerability data from <a href="https://www.wpvulnerability.com/" target="_blank" rel="noopener">WPVulnerability</a>. Plugins and themes that are not listed on WordPress.org may not be in the database.', 'nodethemes-security-ai' ) ); ?></p>
		</div>
		<?php
	}

	/**
	 * Vulnerability list.
	 *
	 * @param array $r Result.
	 */
	private static function vuln_list( $r ) {
		if ( empty( $r['time'] ) ) {
			return;
		}
		if ( empty( $r['items'] ) ) {
			echo '<p class="ntsa-ok"><span class="dashicons dashicons-yes-alt"></span> ';
			/* translators: %d: number */
			echo esc_html( sprintf( __( 'No known vulnerabilities in the %d items checked.', 'nodethemes-security-ai' ), (int) $r['checked'] ) );
			echo '</p>';
			return;
		}
		foreach ( $r['items'] as $it ) {
			echo '<div class="ntsa-vuln ntsa-finding" data-kind="vuln" data-ref="' . esc_attr( $it['type'] . '|' . $it['slug'] ) . '"><h3>' . esc_html( $it['name'] . ' ' . $it['version'] ) . ' <span class="description">(' . esc_html( $it['type'] ) . ')</span></h3><ul>';
			foreach ( $it['vulns'] as $v ) {
				$cls = in_array( $v['sev'], array( 'c', 'h' ), true ) ? 'bad' : 'warn';
				echo '<li>' . self::pill( $cls, NTSA_Vuln::severity_label( $v['sev'] ) ) . ' ' . esc_html( $v['name'] ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
				if ( '' !== $v['fixed'] ) {
					/* translators: %s: version */
					echo ' — <strong>' . esc_html( sprintf( __( 'Fixed in %s: update now.', 'nodethemes-security-ai' ), $v['fixed'] ) ) . '</strong>';
				} elseif ( $v['unfixed'] ) {
					echo ' — <strong>' . esc_html__( 'No fix yet: consider turning it off or replacing it.', 'nodethemes-security-ai' ) . '</strong>';
				}
				foreach ( $v['links'] as $l ) {
					echo ' <a href="' . esc_url( $l['link'] ) . '" target="_blank" rel="noopener">' . esc_html( '' !== $l['name'] ? $l['name'] : __( 'details', 'nodethemes-security-ai' ) ) . '</a>';
				}
				echo '</li>';
			}
			echo '</ul></div>';
		}
	}

	/**
	 * Activity log tab.
	 */
	private static function tab_log() {
		$labels = NTSA_Log::labels();
		$days   = (int) apply_filters( 'ntsa_log_view_days', NTSA_FREE_LOG_DAYS );
		$page   = isset( $_GET['p'] ) ? max( 1, absint( $_GET['p'] ) ) : 1; // phpcs:ignore WordPress.Security.NonceVerification.Recommended
		$args   = apply_filters(
			'ntsa_log_query_args',
			array(
				'days'   => $days,
				'limit'  => 50,
				'offset' => ( $page - 1 ) * 50,
			)
		);
		$q      = NTSA_Log::query( $args );
		?>
		<div class="ntsa-card">
			<h2><?php esc_html_e( 'Activity log', 'nodethemes-security-ai' ); ?></h2>
			<p>
			<?php
			if ( ntsa_is_pro() ) {
				/* translators: %d: days */
				echo esc_html( sprintf( __( 'Logins, user changes, plugin and theme changes, important settings and security events. Kept for %d days.', 'nodethemes-security-ai' ), NTSA_Log::retention_days() ) );
			} else {
				/* translators: 1: days, 2: events */
				echo esc_html( sprintf( __( 'Logins, user changes, plugin and theme changes, important settings and security events. The free version keeps %1$d days and up to %2$d events.', 'nodethemes-security-ai' ), NTSA_FREE_LOG_DAYS, NTSA_FREE_LOG_ROWS ) );
			}
			?>
			</p>
			<?php do_action( 'ntsa_log_tools' ); ?>
			<?php if ( ! ntsa_is_pro() ) : ?>
				<p><?php echo self::lock( __( '90-day history', 'nodethemes-security-ai' ) ) . self::lock( __( 'Search and filters', 'nodethemes-security-ai' ) ) . self::lock( __( 'CSV export', 'nodethemes-security-ai' ) ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped ?></p>
			<?php endif; ?>
			<?php if ( ! $q['rows'] ) : ?>
				<p><?php esc_html_e( 'No events yet.', 'nodethemes-security-ai' ); ?></p>
			<?php else : ?>
				<div class="ntsa-table-wrap"><table class="widefat striped ntsa-table">
					<thead><tr><th><?php esc_html_e( 'Time', 'nodethemes-security-ai' ); ?></th><th><?php esc_html_e( 'User', 'nodethemes-security-ai' ); ?></th><th><?php esc_html_e( 'Event', 'nodethemes-security-ai' ); ?></th><th><?php esc_html_e( 'Details', 'nodethemes-security-ai' ); ?></th><th>IP</th></tr></thead>
					<tbody>
					<?php foreach ( $q['rows'] as $r ) : ?>
						<?php
						$det = '';
						if ( ! empty( $r['details'] ) ) {
							$d = json_decode( $r['details'], true );
							if ( is_array( $d ) ) {
								$parts = array();
								foreach ( $d as $k => $v ) {
									$parts[] = $k . ': ' . ( is_array( $v ) ? implode( ', ', array_map( 'strval', $v ) ) : (string) $v );
								}
								$det = implode( ' · ', $parts );
							}
						}
						?>
						<tr class="ntsa-sev-<?php echo (int) $r['severity']; ?>">
							<td><?php echo esc_html( self::when( $r['ts'] ) ); ?></td>
							<td><?php echo esc_html( '' !== $r['user_login'] ? $r['user_login'] : '—' ); ?></td>
							<td><?php echo esc_html( isset( $labels[ $r['event'] ] ) ? $labels[ $r['event'] ] : $r['event'] ); ?></td>
							<td class="ntsa-break"><?php echo esc_html( trim( $r['object'] . ( '' !== $det ? ' (' . $det . ')' : '' ) ) ); ?></td>
							<td><code><?php echo esc_html( $r['ip'] ); ?></code></td>
						</tr>
					<?php endforeach; ?>
					</tbody>
				</table></div>
				<?php
				$pages = (int) ceil( $q['total'] / 50 );
				if ( $pages > 1 ) {
					echo '<p class="ntsa-pages">';
					for ( $i = 1; $i <= min( $pages, 40 ); $i++ ) {
						echo $i === $page ? '<strong>' . (int) $i . '</strong> ' : '<a href="' . esc_url( add_query_arg( array_merge( $_GET, array( 'p' => $i ) ), admin_url( 'admin.php' ) ) ) . '">' . (int) $i . '</a> '; // phpcs:ignore WordPress.Security.NonceVerification.Recommended,WordPress.Security.ValidatedSanitizedInput -- add_query_arg + esc_url.
					}
					echo '</p>';
				}
				?>
			<?php endif; ?>
		</div>
		<?php
	}

	/**
	 * Hardening tab.
	 */
	private static function tab_hardening() {
		$items = NTSA_Hardening::items();
		?>
		<div class="ntsa-card">
			<h2><?php esc_html_e( 'Hardening', 'nodethemes-security-ai' ); ?></h2>
			<p><?php esc_html_e( 'Each switch is tested right after you turn it on: your home page and login page are loaded again, and if one of them stops working, the switch is turned off at once.', 'nodethemes-security-ai' ); ?></p>
			<table class="widefat ntsa-harden">
				<tbody>
				<?php foreach ( $items as $id => $it ) : ?>
					<?php $on = NTSA_Hardening::is_on( $id ); ?>
					<tr>
						<td class="ntsa-harden-state"><?php echo $on ? self::pill( 'ok', __( 'On', 'nodethemes-security-ai' ) ) : self::pill( 'off', __( 'Off', 'nodethemes-security-ai' ) ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped ?></td>
						<td>
							<strong><?php echo esc_html( $it['title'] ); ?></strong><?php echo $it['pro'] ? ' <span class="ntsa-pro">PRO</span>' : ''; ?>
							<?php if ( '' !== $it['desc'] ) : ?>
								<br><span class="description"><?php echo esc_html( $it['desc'] ); ?></span>
							<?php endif; ?>
							<?php if ( '' !== $it['warn'] ) : ?>
								<br><span class="ntsa-warn-text"><?php echo esc_html( $it['warn'] ); ?></span>
							<?php endif; ?>
						</td>
						<td class="ntsa-harden-btn">
							<?php if ( $on && ! empty( $it['no_off'] ) ) : ?>
								<span class="description"><?php esc_html_e( 'Done', 'nodethemes-security-ai' ); ?></span>
							<?php elseif ( $on ) : ?>
								<a class="button" href="<?php echo esc_url( self::action_url( 'harden', array( 'item' => $id, 'on' => 0 ) ) ); ?>"><?php esc_html_e( 'Turn off', 'nodethemes-security-ai' ); ?></a>
							<?php elseif ( $it['pro'] && ! ntsa_is_pro() ) : ?>
								<?php echo self::lock( __( 'Turn on', 'nodethemes-security-ai' ) ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped ?>
							<?php elseif ( ! empty( $it['confirm'] ) ) : ?>
								<a class="button button-primary" href="<?php echo esc_url( self::url( 'hardening', array( 'confirm' => $id ) ) ); ?>"><?php esc_html_e( 'Turn on…', 'nodethemes-security-ai' ); ?></a>
							<?php else : ?>
								<a class="button button-primary" href="<?php echo esc_url( self::action_url( 'harden', array( 'item' => $id, 'on' => 1 ) ) ); ?>"><?php esc_html_e( 'Turn on', 'nodethemes-security-ai' ); ?></a>
							<?php endif; ?>
						</td>
					</tr>
				<?php endforeach; ?>
				</tbody>
			</table>
			<?php do_action( 'ntsa_hardening_tab' ); ?>
			<p class="description"><?php esc_html_e( 'Rescue switch: if you ever cannot log in, add define( \'NTSA_SAFE_MODE\', true ); to wp-config.php. It pauses the firewall, lockouts, two-factor login and these settings until you remove it. Deactivating the plugin also removes every rule it added to .htaccess.', 'nodethemes-security-ai' ); ?></p>
		</div>
		<?php
	}

	/**
	 * Settings tab.
	 */
	private static function tab_settings() {
		$s   = NTSA_Settings::all();
		$sug = NTSA_IP::suggestion();
		?>
		<div class="ntsa-card">
			<h2><?php esc_html_e( 'Visitor IP address', 'nodethemes-security-ai' ); ?></h2>
			<p><?php esc_html_e( 'Lockouts and IP rules need the real IP of each visitor. If your site is behind Cloudflare or a proxy, choose the header it sets; otherwise keep the default. A wrong choice could let visitors fake their IP.', 'nodethemes-security-ai' ); ?></p>
			<?php if ( '' !== $sug ) : ?>
				<div class="notice notice-info inline"><p><?php esc_html_e( 'Your site appears to be behind Cloudflare. Choose "Cloudflare (CF-Connecting-IP)" so each visitor gets their own IP instead of a Cloudflare address.', 'nodethemes-security-ai' ); ?></p></div>
			<?php endif; ?>
			<?php self::form_open( 'save_settings' ); ?>
			<table class="form-table" role="presentation">
				<tr><th><?php esc_html_e( 'Read the IP from', 'nodethemes-security-ai' ); ?></th><td>
					<?php
					$prev = NTSA_IP::preview();
					foreach ( NTSA_IP::sources() as $k => $label ) {
						echo '<label class="ntsa-switch"><input type="radio" name="ip_source" value="' . esc_attr( $k ) . '"' . checked( $s['ip_source'], $k, false ) . '> ' . esc_html( $label ) . ' <code>' . esc_html( '' !== $prev[ $k ] ? $prev[ $k ] : '—' ) . '</code></label>';
					}
					?>
				</td></tr>
			</table>
			<?php submit_button( __( 'Save settings', 'nodethemes-security-ai' ) ); ?>
			</form>
		</div>
		<?php do_action( 'ntsa_settings_tab' ); ?>
		<div class="ntsa-card">
			<h2><?php esc_html_e( 'Rescue and data', 'nodethemes-security-ai' ); ?></h2>
			<ul class="ntsa-list">
				<li><?php echo wp_kses_post( __( '<code>define( \'NTSA_SAFE_MODE\', true );</code> in wp-config.php pauses all protection that runs in PHP.', 'nodethemes-security-ai' ) ); ?></li>
				<li><?php echo wp_kses_post( __( '<code>define( \'NTSA_DISABLE_2FA\', true );</code> pauses only two-factor login.', 'nodethemes-security-ai' ) ); ?></li>
				<li><?php esc_html_e( 'Deactivating the plugin removes the .htaccess rules it added. Deleting it also removes its settings, logs and scan results.', 'nodethemes-security-ai' ); ?></li>
			</ul>
			<p><a class="button" href="<?php echo esc_url( self::action_url( 'remove_rules' ) ); ?>"><?php esc_html_e( 'Remove all .htaccess rules added by this plugin', 'nodethemes-security-ai' ); ?></a></p>
		</div>
		<?php
	}

	/**
	 * Pro tab (free version only).
	 */
	private static function tab_pro() {
		self::pro_box( true );
	}

	/**
	 * Pro box.
	 *
	 * @param bool $full Full list.
	 */
	private static function pro_box( $full = false ) {
		$rows = array(
			__( 'Early firewall that runs before WordPress loads, rate limiting, country blocking and your own rules', 'nodethemes-security-ai' ),
			__( 'Two-factor login for every user, and required 2FA for chosen roles', 'nodethemes-security-ai' ),
			__( 'File change check for all plugins and themes, not only WordPress itself', 'nodethemes-security-ai' ),
			__( 'Unlimited and scheduled malware scans, including the database', 'nodethemes-security-ai' ),
			__( 'Daily vulnerability checks with e-mail and Telegram alerts', 'nodethemes-security-ai' ),
			__( '90-day activity log with search and CSV export', 'nodethemes-security-ai' ),
			__( 'All hardening switches: block PHP in uploads, protect private files, security headers, change the table prefix', 'nodethemes-security-ai' ),
			__( 'WooCommerce checkout protection against card-testing bots', 'nodethemes-security-ai' ),
			__( 'AI explanations of findings in plain language, with a daily spending limit', 'nodethemes-security-ai' ),
		);
		?>
		<div class="ntsa-card ntsa-feature">
			<h2><?php esc_html_e( 'NodeThemes Security AI Pro', 'nodethemes-security-ai' ); ?> <span class="ntsa-pro">PRO</span></h2>
			<ul class="ntsa-list">
				<?php foreach ( $full ? $rows : array_slice( $rows, 0, 5 ) as $r ) : ?>
					<li><span class="dashicons dashicons-yes"></span> <?php echo esc_html( $r ); ?></li>
				<?php endforeach; ?>
			</ul>
			<p><?php esc_html_e( 'Pro is installed next to this free plugin. Your settings, logs and scan results stay as they are.', 'nodethemes-security-ai' ); ?></p>
			<p><a class="button button-primary" href="<?php echo esc_url( ntsa_upgrade_url() ); ?>" <?php echo ntsa_pro_installed() ? '' : 'target="_blank" rel="noopener"'; ?>><?php echo ntsa_pro_installed() ? esc_html__( 'Activate your Pro license', 'nodethemes-security-ai' ) : esc_html__( 'Get Security AI Pro', 'nodethemes-security-ai' ); ?></a></p>
		</div>
		<?php
	}

	/* ---------------------------------------------------------------------
	 * Dashboard widget and notices
	 * ------------------------------------------------------------------ */

	/**
	 * Dashboard widget.
	 */
	public static function dashboard_widget() {
		if ( current_user_can( 'manage_options' ) ) {
			wp_add_dashboard_widget( 'ntsa_widget', __( 'Security AI', 'nodethemes-security-ai' ), array( __CLASS__, 'widget' ) );
		}
	}

	/**
	 * Widget body.
	 */
	public static function widget() {
		$list = array_filter(
			self::checklist(),
			function ( $i ) {
				return 'ok' !== $i[0];
			}
		);
		$c    = NTSA_Firewall::counts( 7 );
		echo '<p>';
		/* translators: 1: blocked, 2: lockouts */
		echo esc_html( sprintf( __( 'Last 7 days: %1$d attacks blocked, %2$d login lockouts.', 'nodethemes-security-ai' ), (int) ( isset( $c['block'] ) ? $c['block'] : 0 ), (int) ( isset( $c['lockout'] ) ? $c['lockout'] : 0 ) ) );
		echo '</p>';
		if ( $list ) {
			echo '<ul class="ntsa-check">';
			foreach ( array_slice( $list, 0, 6 ) as $i ) {
				echo '<li class="is-' . esc_attr( $i[0] ) . '"><span class="dashicons dashicons-' . ( 'bad' === $i[0] ? 'warning' : 'info' ) . '"></span> ' . esc_html( $i[1] ) . '</li>';
			}
			echo '</ul>';
		} else {
			echo '<p class="ntsa-ok"><span class="dashicons dashicons-yes-alt"></span> ' . esc_html__( 'Everything looks good.', 'nodethemes-security-ai' ) . '</p>';
		}
		echo '<p><a href="' . esc_url( self::url() ) . '">' . esc_html__( 'Open Security AI', 'nodethemes-security-ai' ) . ' &rarr;</a></p>';
	}

	/**
	 * Important notices (on our page and the Dashboard only, so they are not noisy).
	 */
	public static function notices() {
		if ( ! current_user_can( 'manage_options' ) ) {
			return;
		}
		$screen = function_exists( 'get_current_screen' ) ? get_current_screen() : null;
		if ( ! $screen || ( 'dashboard' !== $screen->id && false === strpos( (string) $screen->id, self::SLUG ) ) ) {
			return;
		}
		$mr = NTSA_Malware::result();
		$n  = isset( $mr['findings'] ) ? count( array_filter( (array) $mr['findings'], function ( $f ) { return 3 === (int) $f['sev']; } ) ) : 0; // phpcs:ignore Universal.FunctionDeclarations.NoLongClosures
		if ( $n ) {
			/* translators: %d: number */
			echo '<div class="notice notice-error"><p><strong>' . esc_html__( 'Security AI:', 'nodethemes-security-ai' ) . '</strong> ' . esc_html( sprintf( _n( 'the malware scan found %d dangerous file.', 'the malware scan found %d dangerous files.', $n, 'nodethemes-security-ai' ), $n ) ) . ' <a href="' . esc_url( self::url( 'scans' ) ) . '">' . esc_html__( 'Review', 'nodethemes-security-ai' ) . '</a></p></div>';
		}
	}

	/* ---------------------------------------------------------------------
	 * Handlers
	 * ------------------------------------------------------------------ */

	/**
	 * Save firewall.
	 */
	public static function post_save_firewall() {
		self::guard( 'save_firewall' );
		// phpcs:disable WordPress.Security.NonceVerification.Missing -- checked in guard().
		$mode  = isset( $_POST['fw_mode'] ) ? sanitize_key( wp_unslash( $_POST['fw_mode'] ) ) : 'block';
		$allow = NTSA_Settings::clean_ip_list( isset( $_POST['fw_allow_ips'] ) ? sanitize_textarea_field( wp_unslash( $_POST['fw_allow_ips'] ) ) : '' );
		$block = NTSA_Settings::clean_ip_list( isset( $_POST['fw_block_ips'] ) ? sanitize_textarea_field( wp_unslash( $_POST['fw_block_ips'] ) ) : '' );
		// phpcs:enable
		$me = NTSA_IP::get();
		if ( ntsa_ip_in_list( $me, explode( "\n", $block ) ) ) {
			self::back( 'firewall', 'error', __( 'Not saved: your own IP is in the block list, which would lock you out.', 'nodethemes-security-ai' ) );
		}
		NTSA_Settings::update(
			array(
				'fw_mode'      => in_array( $mode, array( 'block', 'monitor', 'off' ), true ) ? $mode : 'block',
				'fw_allow_ips' => $allow,
				'fw_block_ips' => $block,
			)
		);
		self::back( 'firewall', 'success', __( 'Firewall settings saved.', 'nodethemes-security-ai' ) );
	}

	/**
	 * Save login.
	 */
	public static function post_save_login() {
		self::guard( 'save_login' );
		// phpcs:disable WordPress.Security.NonceVerification.Missing -- checked in guard().
		$pw = isset( $_POST['strong_pw'] ) ? sanitize_key( wp_unslash( $_POST['strong_pw'] ) ) : 'admins';
		if ( 'all' === $pw && ! ntsa_is_pro() ) {
			$pw = 'admins';
		}
		NTSA_Settings::update(
			array(
				'login_on'       => empty( $_POST['login_on'] ) ? 0 : 1,
				'login_max'      => min( 50, max( 2, isset( $_POST['login_max'] ) ? absint( $_POST['login_max'] ) : 5 ) ),
				'login_window'   => min( 1440, max( 1, isset( $_POST['login_window'] ) ? absint( $_POST['login_window'] ) : 15 ) ),
				'login_lock'     => min( 10080, max( 1, isset( $_POST['login_lock'] ) ? absint( $_POST['login_lock'] ) : 30 ) ),
				'login_long'     => min( 50, max( 2, isset( $_POST['login_long'] ) ? absint( $_POST['login_long'] ) : 3 ) ),
				'login_long_hrs' => min( 720, max( 1, isset( $_POST['login_long_hrs'] ) ? absint( $_POST['login_long_hrs'] ) : 24 ) ),
				'strong_pw'      => in_array( $pw, array( 'off', 'admins', 'all' ), true ) ? $pw : 'admins',
			)
		);
		// phpcs:enable
		self::back( 'login', 'success', __( 'Login settings saved.', 'nodethemes-security-ai' ) );
	}

	/**
	 * Save general settings.
	 */
	public static function post_save_settings() {
		self::guard( 'save_settings' );
		$src = isset( $_POST['ip_source'] ) ? sanitize_text_field( wp_unslash( $_POST['ip_source'] ) ) : 'REMOTE_ADDR'; // phpcs:ignore WordPress.Security.NonceVerification.Missing
		NTSA_Settings::update( array( 'ip_source' => isset( NTSA_IP::sources()[ $src ] ) ? $src : 'REMOTE_ADDR' ) );
		self::back( 'settings', 'success', __( 'Settings saved.', 'nodethemes-security-ai' ) );
	}

	/**
	 * Unlock an IP.
	 */
	public static function post_unlock_ip() {
		self::guard( 'unlock_ip' );
		$ip = isset( $_GET['ip'] ) ? sanitize_text_field( wp_unslash( $_GET['ip'] ) ) : ''; // phpcs:ignore WordPress.Security.NonceVerification.Recommended
		if ( filter_var( $ip, FILTER_VALIDATE_IP ) ) {
			NTSA_Login::unlock( $ip );
		}
		self::back( 'login', 'success', __( 'IP unlocked.', 'nodethemes-security-ai' ) );
	}

	/**
	 * Add a firewall exception.
	 */
	public static function post_fw_exception() {
		self::guard( 'fw_exception' );
		// phpcs:disable WordPress.Security.NonceVerification.Recommended -- checked in guard().
		$rule = isset( $_GET['rule'] ) ? sanitize_key( wp_unslash( $_GET['rule'] ) ) : '';
		$path = isset( $_GET['path'] ) ? sanitize_text_field( wp_unslash( $_GET['path'] ) ) : '';
		// phpcs:enable
		if ( '' !== $rule && isset( ntsa_waf_rules()[ $rule ] ) ) {
			NTSA_Firewall::add_exception( $rule, $path );
		}
		self::back( 'firewall', 'success', __( 'Exception added: this rule no longer runs for that address.', 'nodethemes-security-ai' ) );
	}

	/**
	 * Remove a firewall exception.
	 */
	public static function post_fw_exception_del() {
		self::guard( 'fw_exception_del' );
		$ex  = isset( $_GET['ex'] ) ? sanitize_text_field( wp_unslash( $_GET['ex'] ) ) : ''; // phpcs:ignore WordPress.Security.NonceVerification.Recommended
		$all = array_values( array_diff( (array) NTSA_Settings::get( 'fw_exceptions', array() ), array( $ex ) ) );
		NTSA_Settings::update( array( 'fw_exceptions' => $all ) );
		self::back( 'firewall', 'success', __( 'Exception removed.', 'nodethemes-security-ai' ) );
	}

	/**
	 * Hardening switch.
	 */
	public static function post_harden() {
		self::guard( 'harden' );
		// phpcs:disable WordPress.Security.NonceVerification -- checked in guard().
		$id = isset( $_REQUEST['item'] ) ? sanitize_key( wp_unslash( $_REQUEST['item'] ) ) : '';
		$on = ! empty( $_REQUEST['on'] );
		// phpcs:enable
		$r = NTSA_Hardening::set( $id, $on );
		if ( is_wp_error( $r ) ) {
			self::back( 'hardening', 'error', $r->get_error_message() );
		}
		self::back( 'hardening', 'success', $on ? __( 'Turned on and tested: your home page and login page still work.', 'nodethemes-security-ai' ) : __( 'Turned off.', 'nodethemes-security-ai' ) );
	}

	/**
	 * Remove .htaccess rules.
	 */
	public static function post_remove_rules() {
		self::guard( 'remove_rules' );
		$state = (array) NTSA_Settings::get( 'hardening', array() );
		foreach ( array( 'uploads_php', 'protect_files', 'no_indexes' ) as $k ) {
			unset( $state[ $k ] );
		}
		NTSA_Settings::update( array( 'hardening' => $state ) );
		NTSA_Hardening::remove_server_rules();
		self::back( 'settings', 'success', __( 'All .htaccess rules added by NodeThemes Security AI were removed.', 'nodethemes-security-ai' ) );
	}

	/**
	 * Integrity: mark OK.
	 */
	public static function post_integrity_ok() {
		self::guard( 'integrity_ok' );
		$p = isset( $_GET['path'] ) ? sanitize_text_field( wp_unslash( $_GET['path'] ) ) : ''; // phpcs:ignore WordPress.Security.NonceVerification.Recommended
		if ( '' !== $p ) {
			NTSA_Integrity::mark_ok( $p );
		}
		self::back( 'scans', 'success', __( 'Marked as OK. It will be reported again only if the file changes.', 'nodethemes-security-ai' ) );
	}

	/**
	 * Malware: ignore a finding.
	 */
	public static function post_malware_ignore() {
		self::guard( 'malware_ignore' );
		// phpcs:disable WordPress.Security.NonceVerification.Recommended -- checked in guard().
		$p = isset( $_GET['path'] ) ? sanitize_text_field( wp_unslash( $_GET['path'] ) ) : '';
		$s = isset( $_GET['sig'] ) ? sanitize_key( wp_unslash( $_GET['sig'] ) ) : '';
		// phpcs:enable
		NTSA_Malware::ignore( $p, $s );
		self::back( 'scans', 'success', __( 'Ignored. It will be reported again only if the file changes.', 'nodethemes-security-ai' ) );
	}

	/**
	 * Vulnerability check on / off.
	 */
	public static function post_vuln_toggle() {
		self::guard( 'vuln_toggle' );
		$on = ! empty( $_GET['on'] ); // phpcs:ignore WordPress.Security.NonceVerification.Recommended
		NTSA_Settings::update( array( 'vuln_enabled' => $on ? 1 : 0 ) );
		if ( ! $on ) {
			wp_clear_scheduled_hook( 'ntsa_weekly_vuln' );
		}
		self::back( 'vulns', 'success', $on ? __( 'Vulnerability check turned on. Click "Check now" for the first check.', 'nodethemes-security-ai' ) : __( 'Vulnerability check turned off.', 'nodethemes-security-ai' ) );
	}

	/* ---------------------------------------------------------------------
	 * AJAX
	 * ------------------------------------------------------------------ */

	/**
	 * Core file check.
	 */
	public static function ajax_integrity_core() {
		self::ajax_guard();
		$r = NTSA_Integrity::scan_core();
		if ( is_wp_error( $r ) ) {
			wp_send_json_error( array( 'message' => $r->get_error_message() ) );
		}
		wp_send_json_success();
	}

	/**
	 * Malware: start.
	 */
	public static function ajax_malware_start() {
		self::ajax_guard();
		$j = NTSA_Malware::start( 'manual' );
		if ( is_wp_error( $j ) ) {
			wp_send_json_error( array( 'message' => $j->get_error_message() ) );
		}
		wp_send_json_success( array( 'pos' => $j['pos'], 'total' => $j['total'] ) );
	}

	/**
	 * Malware: next batch.
	 */
	public static function ajax_malware_step() {
		self::ajax_guard();
		$j = NTSA_Malware::step( 8.0 );
		if ( null === $j ) {
			wp_send_json_success( array( 'done' => true ) );
		}
		wp_send_json_success(
			array(
				'done'  => false,
				'pos'   => $j['pos'],
				'total' => $j['total'],
			)
		);
	}

	/**
	 * Vulnerability check.
	 */
	public static function ajax_vuln_run() {
		self::ajax_guard();
		$r = NTSA_Vuln::run( 'manual' );
		if ( is_wp_error( $r ) ) {
			wp_send_json_error( array( 'message' => $r->get_error_message() ) );
		}
		wp_send_json_success();
	}
}
