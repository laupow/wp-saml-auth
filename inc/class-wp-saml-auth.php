<?php
/**
 * Class WP_SAML_Auth
 *
 * @package WP_SAML_Auth
 */

/**
 * Main controller class for WP SAML Auth
 */
class WP_SAML_Auth {

	/**
	 * Controller instance as a singleton
	 *
	 * @var object
	 */
	private static $instance;

	/**
	 * SAML provider instance
	 *
	 * @var object
	 */
	private $provider = null;

	/**
	 * Class name to instantiate for SimpleSAML Auth.
	 * Replaced with namespaced version if available.
	 *
	 * @var string
	 */
	private $simplesamlphp_class = 'SimpleSAML_Auth_Simple';

	/**
	 * Endpoint when using the internal connection type
	 * To be used to get XML metadata of the SP at /saml/sp/metadata/
	 *
	 * @var string
	 */
	private $internal_connection_endpoint = 'saml';

	/**
	 * Get the controller instance
	 *
	 * @return object
	 */
	public static function get_instance() {
		if ( ! isset( self::$instance ) ) {
			self::$instance = new WP_SAML_Auth;
			add_action( 'init', array( self::$instance, 'action_init' ) );
		}
		return self::$instance;
	}

	/**
	 * Get a configuration option for this implementation.
	 *
	 * @param string $option_name Configuration option to produce.
	 * @return mixed
	 */
	public static function get_option( $option_name ) {
		return apply_filters( 'wp_saml_auth_option', null, $option_name );
	}

	/**
	 * Get the provider instance for WP_SAML_Auth
	 *
	 * @return mixed
	 */
	public function get_provider() {
		return $this->provider;
	}

	/**
	 * Get the endpoint for internal connection type
	 *
	 * @return string 'saml' or empty string if using SimpleSAMLphp instead of the internal lib
	 */
	public function get_internal_endpoint() {
		$connection_type = self::get_option( 'connection_type' );
		if ( 'internal' !== $connection_type ) {
			return '';
		}

		return $this->internal_connection_endpoint;
	}

	/**
	 * Initialize the controller logic on the 'init' hook
	 */
	public function action_init() {

		$connection_type = self::get_option( 'connection_type' );
		if ( 'internal' === $connection_type ) {
			if ( file_exists( WP_SAML_AUTH_AUTOLOADER ) ) {
				require_once WP_SAML_AUTH_AUTOLOADER;
			}
			if ( ! class_exists( 'OneLogin\Saml2\Auth' ) ) {
				add_action(
					'admin_notices',
					function() {
						if ( current_user_can( 'manage_options' ) ) {
							// Translators: Links to the WP SAML Auth plugin.
							echo '<div class="message error"><p>' . wp_kses_post( sprintf( __( "WP SAML Auth wasn't able to find the <code>OneLogin\Saml2\Auth</code> class. Please verify your Composer autoloader, or <a href='%s'>visit the plugin page</a> for more information.", 'wp-saml-auth' ), 'https://wordpress.org/plugins/wp-saml-auth/' ) ) . '</p></div>';
						}
					}
				);
				return;
			}
			$auth_config    = self::get_option( 'internal_config' );
			$this->provider = new OneLogin\Saml2\Auth( $auth_config );

			add_action( 'template_redirect', array( $this, 'action_template_redirect' ) );

			add_rewrite_endpoint( $this->internal_connection_endpoint, EP_ROOT, true );

			// Attempt to flush rewrite rules on plugin activation, not perfect but it should work at least the first time
			if ( ! get_option( 'wp_saml_rr_flushed' ) ) {
				flush_rewrite_rules();
				do_action( 'rri_flush_rules' ); // Proper flushing on VIP environments
				add_option( 'wp_saml_rr_flushed', true );
			}

		} else {
			$simplesamlphp_path = self::get_option( 'simplesamlphp_autoload' );
			if ( file_exists( $simplesamlphp_path ) ) {
				require_once $simplesamlphp_path;
			}
			if ( class_exists( 'SimpleSAML\Auth\Simple' ) ) {
				$this->simplesamlphp_class = 'SimpleSAML\Auth\Simple';
			}
			if ( ! class_exists( $this->simplesamlphp_class ) ) {
				add_action(
					'admin_notices',
					function() {
						if ( ! empty( $_GET['page'] )
							&& 'wp-saml-auth-settings' === $_GET['page'] ) {
							return;
						}
						if ( current_user_can( 'manage_options' ) ) {
							// Translators: Links to the WP SAML Auth plugin.
							echo '<div class="message error"><p>' . wp_kses_post( sprintf( __( "WP SAML Auth wasn't able to find the <code>%1\$s</code> class. Please check the <code>simplesamlphp_autoload</code> configuration option, or <a href='%2\$s'>visit the plugin page</a> for more information.", 'wp-saml-auth' ), $this->simplesamlphp_class, 'https://wordpress.org/plugins/wp-saml-auth/' ) ) . '</p></div>';
						}
					}
				);
				return;
			}
			$this->provider = new $this->simplesamlphp_class( self::get_option( 'auth_source' ) );
		}
		add_action( 'login_head', array( $this, 'action_login_head' ) );
		add_action( 'login_message', array( $this, 'action_login_message' ) );
		add_action( 'wp_logout', array( $this, 'action_wp_logout' ) );
		add_filter( 'login_body_class', array( $this, 'filter_login_body_class' ) );
		add_filter( 'authenticate', array( $this, 'filter_authenticate' ), 21, 3 ); // after wp_authenticate_username_password runs.
	}

	/**
	 * Render CSS on the login screen
	 */
	public function action_login_head() {
		?>
<style>
	#wp-saml-auth-cta {
		background: #fff;
		-webkit-box-shadow: 0 1px 3px rgba(0,0,0,.13);
		box-shadow: 0 1px 3px rgba(0,0,0,.13);
		padding: 26px 24px 26px;
		margin-top: 24px;
		margin-bottom: 24px;
	}
	.wp-saml-auth-deny-wp-login #loginform,
	.wp-saml-auth-deny-wp-login #nav {
		display: none;
	}
</style>
		<?php
	}

	/**
	 * Such a hack — use a filter to add the button to sign in with SAML provider
	 *
	 * @param string $message Existing message string.
	 * @return string
	 */
	public function action_login_message( $message ) {
		if ( ! self::get_option( 'permit_wp_login' ) ) {
			return $message;
		}
		$strings = array(
			'title'     => __( 'Use one-click authentication:', 'wp-saml-auth' ),
			'button'    => __( 'Sign In', 'wp-saml-auth' ),
			'alt_title' => __( 'Or, sign in with WordPress:', 'wp-saml-auth' ),
		);

		$query_args  = array(
			'action' => 'wp-saml-auth',
		);
		$redirect_to = filter_input( INPUT_GET, 'redirect_to', FILTER_SANITIZE_URL );
		if ( $redirect_to ) {
			$query_args['redirect_to'] = rawurlencode( $redirect_to );
		}

		/**
		 * Permit login screen text strings to be easily customized.
		 *
		 * @param array $strings Existing text strings.
		 */
		$strings = apply_filters( 'wp_saml_auth_login_strings', $strings );
		echo '<h3><em>' . esc_html( $strings['title'] ) . '</em></h3>';
		echo '<div id="wp-saml-auth-cta"><p><a class="button" href="' . esc_url( add_query_arg( $query_args, wp_login_url() ) ) . '">' . esc_html( $strings['button'] ) . '</a></p></div>';
		echo '<h3><em>' . esc_html( $strings['alt_title'] ) . '</em></h3>';
		return $message;
	}

	/**
	 * Log the user out of the SAML instance when they log out of WordPress
	 */
	public function action_wp_logout() {
		if ( 'internal' === self::get_option( 'connection_type' ) ) {
			$internal_config = self::get_option( 'internal_config' );
			if ( empty( $internal_config['idp']['singleLogoutService']['url'] ) ) {
				return;
			}
		}
		$this->provider->logout( add_query_arg( 'loggedout', true, wp_login_url() ) );
	}

	/**
	 * Handle the SAML endpoint used with internal connections
	 */
	public function action_template_redirect() {
		global $wp_query;

		// Do not block access to SAML endpoint if blog is not public
		if ( class_exists( 'ds_more_privacy_options' ) ) {
			global $ds_more_privacy_options; // @codingStandardsIgnoreLine
			remove_action( 'template_redirect', [ $ds_more_privacy_options, 'ds_users_authenticator' ] );
		}

		$endpoint = $this->get_internal_endpoint();
		if ( ! isset( $wp_query->query_vars[ $endpoint ] ) ) {
			return;
		}

		if ( self::get_option( 'connection_type' ) !== 'internal' ) {
			wp_die( esc_html__( 'This endpoint is only available with the internal connection type and OneLogin SAML library', 'wp-saml-auth' ) );
		}

		if ( $wp_query->query_vars[ $endpoint ] === 'sp/metadata' ) {
			$this->do_sp_metadata_export( self::get_provider() );
		}

		wp_safe_redirect( home_url(), 404 );
		exit;
	}

	/**
	 * Add body classes for our specific configuration attributes
	 *
	 * @param array $classes Body CSS classes.
	 * @return array
	 */
	public function filter_login_body_class( $classes ) {

		if ( ! self::get_option( 'permit_wp_login' ) ) {
			$classes[] = 'wp-saml-auth-deny-wp-login';
		}

		return $classes;
	}

	/**
	 * Check if the user is authenticated against the SimpleSAMLphp instance
	 *
	 * @param mixed  $user     WordPress user reference.
	 * @param string $username Username.
	 * @param string $password Password supplied by the user.
	 * @return mixed
	 */
	public function filter_authenticate( $user, $username, $password ) {

		$permit_wp_login = self::get_option( 'permit_wp_login' );
		if ( is_a( $user, 'WP_User' ) && $permit_wp_login ) {
			return $user;
		}

		if ( ! empty( $_POST['SAMLResponse'] ) ) {
			$user = $this->do_saml_authentication();
		} elseif ( ( ! $permit_wp_login && empty( $_GET['loggedout'] ) ) || ( ! empty( $_GET['action'] ) && 'wp-saml-auth' === $_GET['action'] ) ) {
			$user = $this->do_saml_authentication();
		}
		return $user;
	}

	/**
	 * Echo an XML representation of the SP Metadata
	 * Only applies when the connection type is internal
	 * @param \OneLogin\Saml2\Auth $auth
	 */
	public function do_sp_metadata_export( \OneLogin\Saml2\Auth $auth ) {
		$settings = $auth->getSettings();

		$metadata = null;
		try {
			$metadata = $settings->getSPMetadata();
			$errors   = $settings->validateMetadata( $metadata );
		} catch ( \Exception $e ) {
			$errors = $e->getMessage();
		}

		if ( $errors ) {
			wp_die( esc_html__( 'Invalid SAML settings. Contact your administrator.', 'wp-saml-auth' ) );
		}

		header( 'Content-Type: text/xml' );
		echo $metadata; // @codingStandardsIgnoreLine
		exit;
	}

	/**
	 * Do the SAML authentication dance
	 */
	public function do_saml_authentication() {

		if ( is_a( $this->provider, 'OneLogin\Saml2\Auth' ) ) {
			if ( ! empty( $_POST['SAMLResponse'] ) ) {
				$this->provider->processResponse();
				if ( ! $this->provider->isAuthenticated() ) {
					// Translators: Includes error reason from OneLogin.
					return new WP_Error( 'wp_saml_auth_unauthenticated', sprintf( __( 'User is not authenticated with SAML IdP. Reason: %s', 'wp-saml-auth' ), $this->provider->getLastErrorReason() ) );
				}
				$attributes  = $this->provider->getAttributes();
				$redirect_to = filter_input( INPUT_POST, 'RelayState', FILTER_SANITIZE_URL );
				if ( $redirect_to && false === stripos( $redirect_to, parse_url( wp_login_url(), PHP_URL_PATH ) ) ) {
					add_filter(
						'login_redirect',
						function() use ( $redirect_to ) {
							return $redirect_to;
						},
						1
					);
				}
			} else {
				$redirect_to = filter_input( INPUT_GET, 'redirect_to', FILTER_SANITIZE_URL );
				$redirect_to = $redirect_to ? : $_SERVER['REQUEST_URI'];
				$this->provider->login( $redirect_to );
			}
		} elseif ( is_a( $this->provider, $this->simplesamlphp_class ) ) {
			$redirect_to = filter_input( INPUT_GET, 'redirect_to', FILTER_SANITIZE_URL );
			if ( $redirect_to ) {
				$redirect_to = add_query_arg(
					array(
						'redirect_to' => rawurlencode( $redirect_to ),
						'action'      => 'wp-saml-auth',
					),
					wp_login_url()
				);
			} else {
				$redirect_to = wp_login_url();
				// Make sure we're only dealing with the URI components and not arguments.
				$request = explode( '?', $_SERVER['REQUEST_URI'] );
				// Only persist redirect_to when it's not wp-login.php.
				if ( false === stripos( $redirect_to, reset( $request ) ) ) {
					$redirect_to = add_query_arg( 'redirect_to', $_SERVER['REQUEST_URI'], $redirect_to );
				} else {
					$redirect_to = add_query_arg( array( 'action' => 'wp-saml-auth' ), $redirect_to );
				}
			}
			$this->provider->requireAuth(
				array(
					'ReturnTo' => $redirect_to,
				)
			);
			$attributes = $this->provider->getAttributes();
		} else {
			return new WP_Error( 'wp_saml_auth_invalid_provider', __( 'Invalid provider specified for SAML authentication', 'wp-saml-auth' ) );
		}

		/**
		 * Allows to modify attributes before the SAML authentication.
		 *
		 * @param array  $attributes All attributes received from the SAML response.
		 * @param object $provider   Provider instance currently in use.
		 */
		$attributes = apply_filters( 'wp_saml_auth_attributes', $attributes, $this->provider );

		/**
		 * Runs before the SAML authentication dance proceeds
		 *
		 * Can be used to short-circuit the authentication process.
		 *
		 * @param false $short_circuit Return some non-false value to bypass authentication.
		 * @param array $attributes All attributes received from the SAML response.
		 */
		$pre_auth = apply_filters( 'wp_saml_auth_pre_authentication', false, $attributes );
		if ( false !== $pre_auth ) {
			return $pre_auth;
		}

		if ( empty( $attributes ) ) {
			return new WP_Error( 'wp_saml_auth_no_attributes', esc_html__( 'No attributes were present in SAML response. Attributes are used to create and fetch users. Please contact your administrator', 'wp-saml-auth' ) );
		}

		$get_user_by = self::get_option( 'get_user_by' );
		$attribute   = self::get_option( "user_{$get_user_by}_attribute" );
		if ( empty( $attributes[ $attribute ][0] ) ) {
			// Translators: Communicates how the user is fetched based on the SAML response.
			return new WP_Error( 'wp_saml_auth_missing_attribute', sprintf( esc_html__( '"%1$s" attribute is expected, but missing, in SAML response. Attribute is used to fetch existing user by "%2$s". Please contact your administrator.', 'wp-saml-auth' ), $attribute, $get_user_by ) );
		}

		$existing_user = get_user_by( $get_user_by, $attributes[ $attribute ][0] );
		if ( $existing_user ) {
			/**
			 * Runs after a existing user has been authenticated in WordPress
			 *
			 * @param WP_User $existing_user  The existing user object.
			 * @param array   $attributes     All attributes received from the SAML Response
			 */
			do_action( 'wp_saml_auth_existing_user_authenticated', $existing_user, $attributes );
			return $existing_user;
		}
		if ( ! self::get_option( 'auto_provision' ) ) {
			return new WP_Error( 'wp_saml_auth_auto_provision_disabled', esc_html__( 'No WordPress user exists for your account. Please contact your administrator.', 'wp-saml-auth' ) );
		}

		$user_args = array();
		foreach ( array( 'display_name', 'user_login', 'user_email', 'first_name', 'last_name' ) as $type ) {
			$attribute          = self::get_option( "{$type}_attribute" );
			$user_args[ $type ] = ! empty( $attributes[ $attribute ][0] ) ? $attributes[ $attribute ][0] : '';
		}
		$user_args['role']      = self::get_option( 'default_role' );
		$user_args['user_pass'] = wp_generate_password();
		/**
		 * Runs before a user is created based off a SAML response.
		 *
		 * @param array $user_args Arguments passed to wp_insert_user().
		 * @param array $attributes Attributes from the SAML response.
		 */
		$user_args = apply_filters( 'wp_saml_auth_insert_user', $user_args, $attributes );
		$user_id   = wp_insert_user( $user_args );
		if ( is_wp_error( $user_id ) ) {
			return $user_id;
		}

		$user = get_user_by( 'id', $user_id );

		/**
		 * Runs after the user has been authenticated in WordPress
		 *
		 * @param WP_User $user       The new user object.
		 * @param array   $attributes All attributes received from the SAML Response
		 */
		do_action( 'wp_saml_auth_new_user_authenticated', $user, $attributes );
		return $user;
	}

}
