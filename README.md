# NodeThemes Security AI

**Free WordPress security plugin with a firewall, login limits, two-factor login, malware and file scans, and hardening that is tested before it stays on.**

NodeThemes Security AI protects WordPress and WooCommerce sites without the usual risk of locking you out. Administrators are never blocked by the firewall rules, every hardening switch is tested on your live site right after you turn it on (and undone if your home or login page stops loading), and one line in `wp-config.php` pauses everything if you ever need it.

- Website: [NodeThemes Security AI on nodethemes.com](https://nodethemes.com/product/nodethemes-security-ai-pro/)
- All free plugins: [Free WordPress plugins from NodeThemes](https://nodethemes.com/free-plugins/)

## Features (free version)

The free version never stops protecting partway. Its limits are on counts and schedules:

- Firewall inside WordPress against SQL injection, cross-site scripting, path traversal, PHP code injection, attack tools and requests for private files such as `.env` and wp-config backups; monitor mode and one-click "Allow this"
- Failed-login limits and IP lockouts for `wp-login.php`, the WooCommerce My Account login and XML-RPC
- Two-factor login (TOTP, any authenticator app, 10 backup codes) for **1 account**
- Strong passwords for administrators, editors and shop managers
- WordPress core file check against the official checksums from WordPress.org
- Malware scan for backdoors, web shells, hidden code and PHP files in uploads: **1 manual scan per week**; nothing is deleted without you
- Known-vulnerability check for WordPress, plugins and themes: **weekly** (off until you turn it on), shown on the dashboard
- Activity log of logins, user, plugin and setting changes: **7 days / 500 events**
- **5 of 11** hardening switches, each tested before it stays on
- Rescue lines: `define( 'NTSA_SAFE_MODE', true );` and `define( 'NTSA_DISABLE_2FA', true );`

## NodeThemes Security AI Pro

The Pro add-on, sold at [nodethemes.com](https://nodethemes.com/product/nodethemes-security-ai-pro/) as a yearly license with updates and support, adds:

- Early firewall that runs before WordPress loads, login and site rate limits, country blocking and your own rules
- Two-factor login for every user and required 2FA for chosen roles
- Plugin and theme file checks, unlimited and scheduled malware scans, and a database scan
- Daily vulnerability checks and alerts by e-mail and Telegram
- Activity log up to 365 days with search and CSV export
- All 11 hardening switches, including changing the database table prefix with test and rollback
- WooCommerce protection that pauses card-testing bots at checkout and Add payment method
- "Explain with AI" on every finding, with a daily AI budget

Pro is installed next to the free plugin; your settings and data stay when you upgrade. See the full **Free vs Pro** comparison table on the [product page](https://nodethemes.com/product/nodethemes-security-ai-pro/).

## Installation

1. Download the free plugin from [nodethemes.com/free-plugins](https://nodethemes.com/free-plugins/) (no account needed).
2. In WordPress go to **Plugins → Add New Plugin → Upload Plugin**, choose the zip, click **Install Now**, then **Activate**.
3. The firewall and login limits start right away. Open **Security AI → Overview** and follow the checklist: two-factor login for your account, the first scans and the hardening switches you want.

Requirements: WordPress 6.0+, PHP 7.4+. The free plugin connects to nodethemes.com only to check for its own updates; the optional vulnerability check uses the WPVulnerability API and the file checks use WordPress.org checksums (see `readme.txt`).

## Guides

- [Hardening WordPress (WordPress Advanced Administration Handbook)](https://developer.wordpress.org/advanced-administration/security/hardening/)
- [OWASP Top 10 web application risks](https://owasp.org/www-project-top-ten/)
- [How to speed up WordPress: a safe step-by-step checklist](https://nodethemes.com/how-to-speed-up-wordpress/)

## Support

- E-mail: nodethemes.com@gmail.com
- Telegram: [t.me/nodethemes](https://t.me/nodethemes)
- Contact page: [nodethemes.com/contact](https://nodethemes.com/contact/)

## License

GPL-2.0-or-later. Made by [NodeThemes](https://nodethemes.com/) – WordPress themes and AI plugins.
