<?php
/*
  Plugin Name: Mysql Directory Service
  Description: Provides directory services, such as user authentication, from a mysql backend.
  Version: 1.0.1
  Author: Alexandre Provencher
  Text Domain: mysql-directory-service
	
  This program is free software; you can redistribute it and/or modify
  it  under the terms of the GNU General Public License as published by
  the Free Software Foundation; either version 2 of the License, or
  (at your option) any later version.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

  You should have received a copy of the GNU General Public License
  along with this program; if not, write to the Free Software
  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

require_once(ABSPATH . WPINC . DIRECTORY_SEPARATOR . 'user.php');
require_once(ABSPATH . WPINC . DIRECTORY_SEPARATOR . 'pluggable.php');
require_once(ABSPATH . WPINC . DIRECTORY_SEPARATOR . 'class-phpass.php');

	

/**
 *	Mysql directory service.
 *
 *	Provides directory services (ie: authentiation) from a mysql backend.
 */
class MysqlDirectoryService {
	
	public $errors;
	public $opts;
	
	protected $_loglevel = 6;
	protected $_logfile = 6;
	
	private $_deleted_users;
	private $_user_pass;
	
	
	/**
	 *	Takes care of initialization and setting up most action/filter hooks.
	 */
	public function __construct() {
 
 		global $wpdb;
 		
		//	Inits errors object.
		$this->errors = new WP_Error();
		
		//	Logfile
		if (is_multisite()) {
			$this->_logfile = dirname(__FILE__) . '/mysqlds-blog-'. $wpdb->blogid . '.log';
		} else {
			$this->_logfile = dirname(__FILE__).'/mysqlds.log';
		}
		
		//	Inits deleted users data array.
		$this->_deleted_users = array();
		
		//	Load options from WP database.
		$this->_load_options();
		
		//	Custom filter hook to retreive user data from all directory services.
		//	This class implements the hook for this service and for Wordpress internal db.
		add_filter('read_user_records', array(&$this, 'read_user_records'), 10, 2);
		add_filter('read_user_records', array(&$this, 'read_wp_user_records'), 10, 2);
		
		//	Hooks to trap user deletion.
		if( $this->opts['mysqlds_allow_delete_users'] == true ) {
			add_action('delete_user_form', array(&$this, 'delete_user_form'), 10, 1);
			if( is_multisite() ) {
				add_action('wpmu_delete_user', array(&$this, 'prepare_delete_user'), 10, 1);
			}
			else {
				add_action('delete_user', array(&$this, 'prepare_delete_user'), 10, 1);
			}
			add_action('deleted_user', array(&$this, 'delete_user'), 10, 1);
		}
		
		add_action('upme_login_failed', array(&$this, 'upme_login_failed'), 10, 3);
		
		//	Hook that loads plugin translation.
		add_action('plugins_loaded', array(&$this, 'load_textdomain'));
		
		//	Hook to handles UPME integration.
		add_action('plugins_loaded', array(&$this, 'plugin_integration_upme'));
		
		//	Hook to handles Woocommerce integration.
		add_action('plugins_loaded', array(&$this, 'plugin_integration_woocommerce'));
		
		//	Hook for administration pages.
		add_action('admin_init', array(&$this, 'register_settings'));
		
		//	Hook for admin and network admin panel menus.
		if ( is_multisite() ) add_action( 'network_admin_menu', array(&$this, 'network_admin_menu'));
		add_action('admin_menu', array(&$this, 'admin_menu'));
		
		//	User password generation hook.
		add_filter('random_password', array(&$this, 'create_user_password'), 99999, 1);
		add_filter('check_password', array(&$this, 'override_password_check'), 10, 4);
		add_filter('login_errors', array(&$this, 'login_errors'), 10, 1);
		
		//	Authentication hook.
		add_filter('authenticate', array(&$this, 'authenticate'), 10, 3);
		
		//	Disabled WP functionalities.
		add_action('lost_password', array(&$this, 'disable_functionality'));
		add_action('retrieve_password', array(&$this, 'disable_functionality'));
		add_action('password_reset', array(&$this, 'disable_functionality'));
		
		//add_action('profile_personal_options', 'mysqlds_warning');
		//add_filter('show_password_fields', 'mysqlds_show_password_fields');
		//add_filter('login_message', 'mysqlds_auth_warning', 10, 1);

		//	Error check before creating user upon self-registration (single-site).
		//	Mainly used to validate username/email duplicates.
		//	The priority should now be ok with 10, but test before changing it.
		add_filter('registration_errors', array(&$this, 'registration_errors'), 99999, 3);

		//	Check for errors when admin registers a new user or user self-registers (multi-site only)
		//	Mainly used to validate username/email duplicates.
		add_filter('wpmu_validate_user_signup', array(&$this, 'wpmu_validate_user_signup'), 10, 1);

		//	Check for errors before user profile is updated by admin or by user (single AND multi-site),
		//	or when admin creates a new user (single-site only).
		//	Mainly used to validate username/email duplicates.
		//	The priority should now be ok with 10, but test before changing it.
		add_filter('user_profile_update_errors', array(&$this, 'user_profile_update_errors'), 99999, 3);

		//	Action hooks for when a user or an admin updates a profile.
		add_action('personal_options_update', array(&$this, 'update_user'), 10, 1);
		add_action('edit_user_profile_update', array(&$this, 'update_user'), 10, 1);
		if( is_multisite() ) {

			//	Action hook triggered upon creation of a new user in wordpress database,
			//	either through self-registration or admin signup (multi-site).
			add_action('wpmu_new_user', array(&$this, 'create_user'), 10, 1);
	
		}
		else {
	
			//	Action hook triggered upon creation of a new user in wordpress database,
			//	either through self-registration or admin signup (single site).
			add_action('user_register', array(&$this, 'create_user'), 10, 1);
	
		}
		
		//	Action that allows to add display content at the bottom of the profile edition page
		//	(only when a user is viewing another user's profile, such as when an admin edits another
		//	user's profile).
		add_action('edit_user_profile', array(&$this, 'edit_user_profile'), 10, 3);
		
		//	Hook to display content in the user view of the user administration section.
		add_filter( 'manage_users_columns', array(&$this, 'manage_users_columns'), 1, 1 );
		add_filter( 'manage_users_custom_column', array(&$this, 'manage_users_custom_column'), 1, 3 );
		
		
	}
	
	/**
	 *	Logs string to log file.
	 */
	protected function _log($level = 0, $info = '') {
		//if ($level <= $this->_loglevel) {
		//	echo '[' .$level . '] '.$info."\n\r";
		//}
		//if (WP_DEBUG) {
			if ($fh = fopen($this->_logfile,'a+')) {
				fwrite($fh,'[' .$level . '] '.$info."\n");
				fclose($fh);
			}
		//}		
	}
	
	/**
	 *	Load plugin options from Wordpress database.
	 */
	protected function _load_options() {
		if( is_multisite() ) {
			$this->opts['mysqlds_host'] = get_site_option('mysqlds_host');
			$this->opts['mysqlds_port'] = get_site_option('mysqlds_port');
			$this->opts['mysqlds_db'] = get_site_option('mysqlds_db');
			$this->opts['mysqlds_user'] = get_site_option('mysqlds_user');
			$this->opts['mysqlds_pw'] = get_site_option('mysqlds_pw');
			$this->opts['mysqlds_table'] = get_site_option('mysqlds_table');
			$this->opts['mysqlds_namefield'] = get_site_option('mysqlds_namefield');
			$this->opts['mysqlds_pwfield'] = get_site_option('mysqlds_pwfield');
			$this->opts['mysqlds_first_name'] = get_site_option('mysqlds_first_name');
			$this->opts['mysqlds_last_name'] = get_site_option('mysqlds_last_name');
			$this->opts['mysqlds_user_email'] = get_site_option('mysqlds_user_email');
			$this->opts['mysqlds_allow_login_network'] = (bool)get_site_option('mysqlds_allow_login_network');
			$this->opts['mysqlds_allow_login'] = (bool)get_option('mysqlds_allow_login');
			$this->opts['mysqlds_allow_delete_users'] = (bool)get_site_option('mysqlds_allow_delete_users');
			$this->opts['mysqlds_upme_integration'] = (bool)get_site_option('mysqlds_upme_integration');
			$this->opts['mysqlds_upme_redirect'] = (bool)get_option('mysqlds_upme_redirect');
		}
		else {
			$this->opts['mysqlds_host'] = get_option('mysqlds_host');
			$this->opts['mysqlds_port'] = get_option('mysqlds_port');
			$this->opts['mysqlds_db'] = get_option('mysqlds_db');
			$this->opts['mysqlds_user'] = get_option('mysqlds_user');
			$this->opts['mysqlds_pw'] = get_option('mysqlds_pw');
			$this->opts['mysqlds_table'] = get_option('mysqlds_table');
			$this->opts['mysqlds_namefield'] = get_option('mysqlds_namefield');
			$this->opts['mysqlds_pwfield'] = get_option('mysqlds_pwfield');
			$this->opts['mysqlds_first_name'] = get_option('mysqlds_first_name');
			$this->opts['mysqlds_last_name'] = get_option('mysqlds_last_name');
			$this->opts['mysqlds_user_email'] = get_option('mysqlds_user_email');
			$this->opts['mysqlds_allow_login_network'] = true;
			$this->opts['mysqlds_allow_login'] = (bool)get_option('mysqlds_allow_login');
			$this->opts['mysqlds_allow_delete_users'] = (bool)get_option('mysqlds_allow_delete_users');
			$this->opts['mysqlds_upme_integration'] = (bool)get_option('mysqlds_upme_integration');
			$this->opts['mysqlds_upme_redirect'] = (bool)get_option('mysqlds_upme_redirect');
		}
	}
	
	/**
	 *	Method that hooks into UPME plugin for integration.
	 */
	public function plugin_integration_upme() {
		
		//	Required for the plugins detection functions.
		if ( ! function_exists( 'get_plugins' ) ) {
			require_once ABSPATH . 'wp-admin/includes/plugin.php';
		}
		
		//	UPME handling.
		if( $this->opts['mysqlds_upme_integration'] && is_plugin_active('upme/upme.php') ) {
			
			//	Action to redirect users to their profile page when some UPME required fields are not set.
			if( $this->opts['mysqlds_upme_redirect'] ) {
				add_action( 'wp_loaded', array(&$this, 'redirect_incomplete_upme_profiles'));
			}
			
			add_filter('upme_profile_before_head', array(&$this, 'upme_redirect_show_message'), 10, 2);
			
			//	Triggers standard wordpress action upon user creation when
			//	user self registers through UPME.
			add_action('upme_user_register', array(&$this, 'upme_user_register'), 10, 1);

			//	Filter for validating UPME registration form fields upon submission.
			add_filter( 'upme_registration_custom_field_type_restrictions', array(&$this, 'upme_registration_custom_field_type_restrictions'), 1, 2 );

			//	Filter for validating UPME edit profile form fields upon submission.
			add_filter( 'upme_frontend_custom_field_type_restrictions', array(&$this, 'upme_frontend_custom_field_type_restrictions'), 1, 2 );

			//	Action launched after a user profile is updated through UPME.
			add_action('upme_profile_update', array(&$this, 'update_user'), 10, 1);
			
			//	Actions to trap/disable some UPME Ajax queries that do not handle multiple directory services.
			add_action('wp_ajax_validate_register_email', array($this, 'disable_upme_ajax'), 1);
			add_action('wp_ajax_nopriv_validate_register_email', array($this, 'disable_upme_ajax'), 1);
			add_action('wp_ajax_validate_register_username', array($this, 'disable_upme_ajax'), 1);
			add_action('wp_ajax_nopriv_validate_register_username', array($this, 'disable_upme_ajax'), 1);
			
		}
		
	}
	
	/**
	 *	Method that hooks into Woocommerce plugin for integration.
	 */
	public function plugin_integration_woocommerce() {
		
		//	Required for the plugins detection functions.
		if ( ! function_exists( 'get_plugins' ) ) {
			require_once ABSPATH . 'wp-admin/includes/plugin.php';
		}
		
		//	Retransmits woocommerce hook to standard Wordpress hook.
		if( is_plugin_active('woocommerce/woocommerce.php') ) {
			add_filter('woocommerce_registration_errors', array(&$this, 'registration_errors'), 10, 3);
			add_action('woocommerce_created_customer', array(&$this, 'woocommerce_created_customer'), 10, 3);
		}
		
	}
	
	/**
	 *	Loads the plugin's text domain.
	 */
	public function load_textdomain() {
		load_plugin_textdomain( 'mysql-directory-service', false, basename(dirname(__FILE__)) );
	}
	
	/**
	 *	Check if username exists in external database.
	 *
	 *	@param[in]	username	Username to search for.
	 *	@return	Associative array of rows matching username, or false on error.
	 */
	public function username_exists($username = '') {
	
		if( empty($username) ) return false;
		
		$host = $this->opts['mysqlds_host'];
		$db_user = $this->opts['mysqlds_user'];
		$pass = $this->opts['mysqlds_pw'];
		$db = $this->opts['mysqlds_db'];
		$db_table = $this->opts['mysqlds_table'];
		$uname = $this->opts['mysqlds_namefield'];
	
		$db_link = mysqli_connect($host, $db_user, $pass, $db) or die("Error " . mysqli_error($db_link));
		$res = mysqli_query($db_link, "SELECT * FROM `" . $db_table . "` WHERE $uname = '" . $username . "'");
		if( $res === false ) return false;
		$entries = array();
		while($row = mysqli_fetch_assoc($res)) {
			$entries[] = $row;
		}
		if( count($entries) == 0 ) return 0;
		return $entries;
	
	}

	/**
	 *	Check if email exists in external database.
	 *
	 *	@param[in]	username	Username to search for.
	 *	@return	Associative array of rows matching username, or false on error.
	 */
	public function email_exists($email = '') {
	
		if( empty($email) ) return false;
		
		$host = $this->opts['mysqlds_host'];
		$db_user = $this->opts['mysqlds_user'];
		$pass = $this->opts['mysqlds_pw'];
		$db = $this->opts['mysqlds_db'];
		$db_table = $this->opts['mysqlds_table'];
		$umail = $this->opts['mysqlds_user_email'];
	
		$db_link = mysqli_connect($host, $db_user, $pass, $db) or die("Error " . mysqli_error($db_link));
		$res = mysqli_query($db_link, "SELECT * FROM `" . $db_table . "` WHERE $umail = '" . $email . "'");
		if( $res === false ) return false;
		$entries = array();
		while($row = mysqli_fetch_assoc($res)) {
			$entries[] = $row;
		}
		if( count($entries) == 0 ) return 0;
		return $entries;
	
	}
	
	/**
	 *	Returns a compound of user record data ordered by service and based on filters.
	 */
	public function read_user_records( $result, $filters=array() ) {
		if( count($filters) == 0 ) return $result;
		$host = $this->opts['mysqlds_host'];
		$db_user = $this->opts['mysqlds_user'];
		$pass = $this->opts['mysqlds_pw'];
		$db = $this->opts['mysqlds_db'];
		$db_table = $this->opts['mysqlds_table'];
		
		$concat = false;
		$where = '';
		foreach( $filters as $key => $value ) {
			switch($key) {
				case 'user_login':
					$where .= ($concat) ? ' AND ' : '';
					$where .=  "{$this->opts['mysqlds_namefield']}='{$value}'";
					$concat = true;
					break;
				case 'user_email':
					$where .= ($concat) ? ' AND ' : '';
					$where .=  "{$this->opts['mysqlds_user_email']}='{$value}'";
					$concat = true;
					break;
				default:
					break;
			}
		}
		if( empty($where) ) return $result;
		$fields = "`{$db_table}`.*";
		$fields .= ",`{$this->opts['mysqlds_namefield']}` as 'user_login'";
		$fields .= ",`{$this->opts['mysqlds_user_email']}` as 'user_email'";
		$query = "SELECT $fields FROM `{$db_table}` WHERE $where";
		$db_link = mysqli_connect($host, $db_user, $pass, $db) or die("Error " . mysqli_error($db_link));
		$res = mysqli_query($db_link, $query);
		if( $res === false ) return false;
		while($row = mysqli_fetch_assoc($res)) {
			unset($row['password']);
			if( !isset($result['mysqlds']) ) $result['mysqlds'] = array();
			$result['mysqlds'][] = array('host'=>$host, 'data'=>$row);
		}
		return $result;
	}
	
	/**
	 *	Returns a compound of user record data ordered by service and based on filters.
	 */
	public function read_wp_user_records( $result, $filters=array() ) {
		
		$login_email_processed = false;
		foreach($filters as $key => $value) {
			switch($key) {
				case 'user_login':
					if( $login_email_processed ) {
						break;
					}
					else {
						$login_email_processed = true;
					}
					$user = get_user_by('login', $filters['user_login']);
					if( $user == false ) return $results;
					if( empty($filters['user_email']) || $user->user_email == $filters['user_email'] ) {
						if( !isset($result['wordpress']) ) $result['wordpress'] = array();
						$entry = get_object_vars($user->data);
						unset($entry['user_pass']);
						$result['wordpress'][] = array('host'=>$_SERVER['SERVER_NAME'], 'data'=>$entry);
					}
					break;
				case 'user_login':
					if( $login_email_processed ) {
						break;
					}
					else {
						$login_email_processed = true;
					}
					$user = get_user_by('email', $filters['user_email']);
					if( $user == false ) return $results;
					if( empty($filters['user_login']) || $user->user_login == $filters['user_login'] ) {
						if( !isset($result['wordpress']) ) $result['wordpress'] = array();
						$entry = get_object_vars($user->data);
						unset($entry['user_pass']);
						$result['wordpress'][] = array('host'=>$_SERVER['SERVER_NAME'], 'data'=>$entry);
					}
					break;
			}
			return $result;
		}
		
		if( !empty($filters['user_login']) ) {
			$user = get_user_by('login', $filters['user_login']);
			if( !empty($filters['user_email']) ) {
				
			}
		}
		elseif( !empty($filters['user_email']) ) {
		
		}
		
	}
	
	/**
	 *	Deletes user from external database.
	 */
	public function delete_user( $user_id ) {
		if( array_key_exists('mysqlds_delete_users',$_POST) && $_POST['mysqlds_delete_users'] == "1" && array_key_exists($user_id, $this->_deleted_users) ) {
			$username = $this->_deleted_users[$user_id]->user_login;
			$email = $this->_deleted_users[$user_id]->user_email;
			if( !empty($username) && !empty($email) ) {
				$host = $this->opts['mysqlds_host'];
				$db_user = $this->opts['mysqlds_user'];
				$pass = $this->opts['mysqlds_pw'];
				$db = $this->opts['mysqlds_db'];
				$db_table = $this->opts['mysqlds_table'];
				$field_username = $this->opts['mysqlds_namefield'];
				$field_email = $this->opts['mysqlds_user_email'];
				$db_link = mysqli_connect($host, $db_user, $pass, $db);
				if( $db_link ) {
					$res = mysqli_query($db_link, "DELETE FROM `" . $db_table . "` WHERE `$field_username`='" . $username . "' AND `$field_email`='" . $email . "'");
					return true;
				}
			}
		}
		return false;
	}
	
	/**
	 *	Stores user meta that Wordpress is about to delete.
	 *
	 *	Required so that the "delete_user" method can still fetch user info such as
	 *	username and email once Wordpress deleted the record.
	 */
	public function prepare_delete_user( $user_id ) {
		if( array_key_exists('mysqlds_delete_users',$_POST) && $_POST['mysqlds_delete_users'] == "1" ) {
			$this->_deleted_users[$user_id] = get_user_by('id', $user_id);
		}
	}
	
	/**
	 *	Creates user profile in external database.
	 */
	public function create_user( $user_id ) {
	
		$update = false;
		$user = get_user_by('id', $user_id);
		$filters = array('user_login'=>$user->user_login,'user_email'=>$user->user_email);
		$records = array();
		$records = apply_filters('read_user_records', $records, $filters);
		
		//	Record already exists in mysql, do not set password.
		if( array_key_exists('mysqlds', $records) ) {
			$this->_user_pass = '';
		}
		elseif( !array_key_exists('wordpress', $records) || count($records) > 1 ) {
			//	User account created by an unknown process or created by wordpress but
			//	stored in another directory service.
			return true;
		}
		$errors = new WP_Error();
		$res = $this->sync_back( $errors, $user, $update );
		if( $res == false ) $this->_log(0,"Method sync_back returned false.");
		$err_codes = $errors->get_error_codes();
		if( !empty($err_codes) ) {
			$user_error_occured = true;
			foreach( $err_codes as $code ) {
				$err_messages = $errors->get_error_messages($code);
				foreach($err_messages as $msg) {
					$this->_log(0, "$code: $msg");
				}
			}
		}
		return $res;
	}
	
	/**
	 *	Updates user profile in external database.
	 */
	public function update_user( $user_id ) {
		$update = true;
		$user = get_user_by('id', $user_id);
		$errors = new WP_Error();
		return $this->sync_back( $errors, $user, $update );
	}
	
	/**
	 *	Creates a user profile in external database when Woocommerce creates a customer.
	 */
	public function woocommerce_created_customer( $customer_id, $new_customer_data, $password_generated ) {
		$update = false;
		$user = get_user_by('id', $customer_id);
		$this->_user_pass = $new_customer_data['password'];
		$errors = new WP_Error();
		return $this->sync_back( $errors, $user, $update );
	}
	
	
	/**
	 *	Function that creates/updates a user record in external database.
	 *
	 *	TODO:	Handle validating password before update.
	 *
	 *	@param[in,out]	errors	WP_Error instance containing errors.
	 *	@param[in]		user	WP_User instance of the user to create/update.
	 *	@param[in]		update	Bool, if true, user record will be created in external database instead of just updated.
	 *	@return					True on success, false on error.
	 */
	public function sync_back( &$errors = NULL, $user = NULL, $update = NULL ) {
		
		if( !is_object($user) ) return false;
		if( !is_object($errors) ) $errors = new WP_Error();
		
		//	Do nothing if updating a user that is not stored in this directory service.
		if( $update == true ) {
			if( get_user_meta($user->ID, 'directory_service', true) != $this->opts['mysqlds_host'] ) {
				return true;
			}
		}
	
		//	Retreive old user values.
		//	Should be required only if $update==false,
		//	but I don't feel like checking right now ;)
		if( isset($user->ID) && !empty($user->ID) ) {
			$old_user = get_userdata($user->ID);
		}
	
		//	Set user login if not set.
		if( !isset($user->user_login) || empty($user->user_login) ) {
			if( !is_object($old_user) || empty($old_user->user_login) ) {
				$errors->add('mysqlds_create_user_error', __('Username must be provided.', 'mysql-directory-service'));
				return false;
			}
			$user->user_login = $old_user->user_login;
		}
	
		$host = $this->opts['mysqlds_host'];
		$db_user = $this->opts['mysqlds_user'];
		$pass = $this->opts['mysqlds_pw'];
		$db = $this->opts['mysqlds_db'];
		$db_table = $this->opts['mysqlds_table'];
		$field_username = $this->opts['mysqlds_namefield'];
		$field_password = $this->opts['mysqlds_pwfield'];
		$field_email = $this->opts['mysqlds_user_email'];
		$field_firstname = $this->opts['mysqlds_first_name'];
		$field_lastname = $this->opts['mysqlds_last_name'];
		
		//	Builds fields array key=>values.
		$fields = array();
		if( $update == false ) $fields[$field_username] = $user->user_login;
		if( !empty($this->_user_pass) ) {
			//$this->_log(0, 'User password stored from class member.');
			$fields[$field_password] = md5($this->_user_pass);
		}
		/*
			if( !empty($_POST["user_pass-{$user->ID}"]) ) {	//	UPME post password.
				$this->_log(0, 'User password stored from UPME post.');
				$fields[$field_password] = md5($_POST["user_pass-{$user->ID}"]);
			}
			elseif( !empty($this->_user_pass) ) {
				$this->_log(0, 'User password stored from class member.');
				$fields[$field_password] = md5($this->_user_pass);
			}
			elseif( !empty($user->user_pass) ) {
				$this->_log(0, 'User password stored from user object.');
				$fields[$field_password] = $user->user_pass;
			}
			elseif( !empty($_POST['user_pass']) ) {
				$this->_log(0, 'User password stored from POST data.');
				$fields[$field_password] = md5($_POST['user_pass']);
			}
		*/
		if( !empty($user->user_email) ) {
			$fields[$field_email] = $user->user_email;
		}
		elseif( !empty($_POST['user_email']) ) {
			$fields[$field_email] = $_POST['user_email'];
		}
		if( !empty($user->first_name) ) {
			$fields[$field_firstname] = $user->first_name;
		}
		elseif( !empty($_POST['first_name']) ) {
			$fields[$field_firstname] = $_POST['first_name'];
		}
		if( !empty($user->last_name) ) {
			$fields[$field_lastname] = $user->last_name;
		}
		elseif( !empty($_POST['last_name']) ) {
			$fields[$field_lastname] = $_POST['last_name'];
		}
	
		//	Build sql field set for user creation.
		$sql_set = '';
		foreach( $fields as $key => $value ) {
			if( empty($value) ) {
				unset( $fields[$key] );
			}
			else {
				$sql_set .= ", `$key`='$value'";
			}
		}
	
		//	No values to create/update.
		//	Should never happen but we're being cautious.
		if( empty($sql_set) ) {
			$errors->add('mysqlds_connect_error', __('Error while updating/creating user: no values to store in record.', 'mysql-directory-service'));
			return false;
		}
	
		$sql_set = substr($sql_set, 2);	//Remove heading ', ';
	
		if( $update == true ) {
		
			//	We're actually just updating a record, not creating a new one.
			$sql = "UPDATE `{$db_table}` SET $sql_set WHERE `{$field_username}`='{$user->user_login}'";
		
		}
		else {
		
			//	Create a new user record in external db.
			$sql = "INSERT INTO `{$db_table}` SET $sql_set";
		
		}
	
		$db_link = mysqli_connect($host, $db_user, $pass, $db);
		if( $db_link === false ) {
			$errors->add('mysqlds_connect_error', __('This plugin must be activated on the entire network. Please contact your network administrator.', 'mysql-directory-service').':<br/>'.mysqli_error($db_link));
			return false;
		}
		$res = mysqli_query($db_link, $sql);
		if( $res === false ) {
			$errors->add('mysqlds_query_error', __("Error while executing query on external database:", 'mysql-directory-service') . "<br/>Query: $sql<br/>" . mysqli_error($db_link));
			return false;
		}
		elseif( mysqli_affected_rows($db_link) == 0 && $update == false ) {
			$errors->add('mysqlds_update_error', __("Error while updating external database account:", 'mysql-directory-service') . "<br/>Query: $sql<br/>" . mysqli_error($db_link));
			return false;
		}
	
		//	Sets additionnal meta keys in user profile.
		update_user_meta($user->ID, 'directory_service', $this->opts['mysqlds_host'] );
	
		return true;
	
	}

	/**
	 *	Adds blog options to blog/site, called by WP's plugin activation process via "register_activation_hook".
	 */
	public static function activate() {
		
		global $wpdb;
	
		if( is_multisite() ) {
		
			if( is_network_admin() && is_super_admin() ) {
			
				//	Network options.
				add_site_option('mysqlds_host', "");
				add_site_option('mysqlds_port', "");
				add_site_option('mysqlds_db', "");
				add_site_option('mysqlds_user', "");
				add_site_option('mysqlds_pw', "");
				add_site_option('mysqlds_table', "");
				add_site_option('mysqlds_namefield', "");
				add_site_option('mysqlds_pwfield', "");
				add_site_option('mysqlds_first_name', "");
				add_site_option('mysqlds_last_name', "");
				add_site_option('mysqlds_user_email', "");
				add_site_option('mysqlds_allow_login_network', true);
				add_site_option('mysqlds_allow_delete_users', false);
				add_site_option('mysqlds_upme_integration', true);
				
				//	Blog options.
				$old_blog = $wpdb->blogid;
				$blogids = $wpdb->get_col("SELECT blog_id FROM {$wpdb->blogs}");
				foreach ($blogids as $blog_id) {
					switch_to_blog($blog_id);
					add_option('mysqlds_allow_login', true);
					add_option('mysqlds_upme_redirect', true);
				}
				switch_to_blog($old_blog);
			
			}
			else {
			
				//	Someone is trying to activate the plugin on a single blog instance from a network enabled Wordpress instane.
				//	This should not be allowed, deactivate immediately (standard procedure).
				deactivate_plugins( plugin_basename( __FILE__ ), false, false );
				wp_die( __('This plugin must be activated on the entire network. Please contact your network administrator.', 'mysql-directory-service') );
			
			}
		
		}
		else {
			if( current_user_can('manage_options') ) {
				add_option('mysqlds_host', "");
				add_option('mysqlds_port', "");
				add_option('mysqlds_db', "");
				add_option('mysqlds_user', "");
				add_option('mysqlds_pw', "");
				add_option('mysqlds_table', "");
				add_option('mysqlds_namefield', "");
				add_option('mysqlds_pwfield', "");
				add_option('mysqlds_first_name', "");
				add_option('mysqlds_last_name', "");
				add_option('mysqlds_user_email', "");
				add_option('mysqlds_allow_login', true);
				add_option('mysqlds_allow_delete_users', false);
				add_option('mysqlds_upme_integration', true);
				add_option('mysqlds_upme_redirect', true);
			}
		}
		
	}

	///	Registers plugin settings with Wordpress.
	public function register_settings() {
		register_setting('MysqlDirectoryService', 'mysqlds_host');
		register_setting('MysqlDirectoryService', 'mysqlds_port');
		register_setting('MysqlDirectoryService', 'mysqlds_db');
		register_setting('MysqlDirectoryService', 'mysqlds_user');
		register_setting('MysqlDirectoryService', 'mysqlds_pw');
		register_setting('MysqlDirectoryService', 'mysqlds_table');
		register_setting('MysqlDirectoryService', 'mysqlds_namefield');
		register_setting('MysqlDirectoryService', 'mysqlds_pwfield');
		register_setting('MysqlDirectoryService', 'mysqlds_first_name');
		register_setting('MysqlDirectoryService', 'mysqlds_last_name');
		register_setting('MysqlDirectoryService', 'mysqlds_user_email');
		register_setting('MysqlDirectoryService', 'mysqlds_allow_login');
		register_setting('MysqlDirectoryService', 'mysqlds_allow_login_network');
		register_setting('MysqlDirectoryService', 'mysqlds_allow_delete_users');
		register_setting('MysqlDirectoryService', 'mysqlds_upme_integration');
		register_setting('MysqlDirectoryService', 'mysqlds_upme_redirect');
	}

	///	Settings menu for network admin pages.
	public function network_admin_menu() {
		add_submenu_page('settings.php', __("Mysql Settings", 'mysql-directory-service'), __("Mysql Settings", 'mysql-directory-service'), 'manage_options', 'MysqlDirectoryService', array(&$this, 'display_options'));
	}

	///	Settings menu for admin pages.
	public function admin_menu() {
		add_submenu_page('options-general.php', __("Mysql Settings", 'mysql-directory-service'), __("Mysql Settings", 'mysql-directory-service'), 'manage_options', 'MysqlDirectoryService', array(&$this, 'display_options'));
	}

	/**
	 *	Outputs "delete users from external database" option in the "delete profile" form.
	 */
	public function delete_user_form( $current_user ) {
		?>
		<table class="form-table">
			<tr valign="top">
				<th scope="row"><label><?php _e('Delete Selected Users From Mysql Authentication Service Database', 'mysql-directory-service'); ?></label></th>
				<td><input type="checkbox" name="mysqlds_delete_users" id="mysqlds_delete_users" value="1" /></td>
				<td><span class="description"><strong><?php _e('Checking this options will delete selected users from the Mysql Authentication Service database where applicable.', 'mysql-directory-service'); ?></strong></span></td>
			</tr>
		</table>
		<?php
	}
	
	
	///	Administration options display output.
	public function display_options() {
		
		?>
		<div class="wrap">
		
			<?php
			
			//	Check if form was posted
			//	Save configs.
			if ( isset($_POST['action']) && $_POST['action'] == 'update') {
				?>
				<div id="message" class="updated notice is-dismissible"><p><?php _e('Settings saved', 'mysql-directory-service'); ?></p><button type="button" class="notice-dismiss" /></div>
				<?php
				$this->_save_multisite_options($_POST);
			}
			?>
			<h2><?php _e('Mysql Authentication Service Settings', 'mysql-directory-service'); ?></h2>
			<?php
			//	Check permissions before printing out form.
			if( (is_network_admin() && !is_super_admin()) || !current_user_can('manage_options') ) {
				?>
				<td colspan="2"><span class="description"><strong style="color:red;"><?php _e('You do not have permission to edit settings here.', 'mysql-directory-service'); ?></strong><span></td>
				</div>
				<?php
				return;
			}
			?>
			<form method="post" action="<?php if ( !is_multisite() ) echo 'options.php#server'; ?>">
				<?php settings_fields('MysqlDirectoryService'); ?>
				<h3><?php _e('General Settings', 'mysql-directory-service'); ?></h3>
				<table class="form-table">	
					<?php
					if( is_network_admin() ) {
						?>
						<tr valign="top">
							<th scope="row"><label><?php _e('Allow Network Login', 'mysql-directory-service'); ?></label></th>
							<td><input type="checkbox" name="mysqlds_allow_login_network" id="mysqlds_allow_login_network"<?php if ( $this->opts['mysqlds_allow_login_network'] ) echo ' checked="checked"' ?> value="1" /></td>
							<td><span class="description"><?php _e('When checked, enables users to authenticate using this service. This can be turned-off individually on each blog. If unchecked, authentication is disabled on the entire network reguardless of blog settings.', 'mysql-directory-service'); ?></span></td>
						</tr>
						<tr valign="top">
							<th scope="row"><label><?php _e('Allow Delete Users', 'mysql-directory-service'); ?></label></th>
							<td><input type="checkbox" name="mysqlds_allow_delete_users" id="mysqlds_allow_delete_users"<?php if ( $this->opts['mysqlds_allow_delete_users'] ) echo ' checked="checked"' ?> value="1" /></td>
							<td><span class="description"><?php _e('When checked, enables administrators to optionnally delete users from the Mysql Authentication Service database along with the Wordpress internal database (when on the "delete profile" form).', 'mysql-directory-service'); ?></span></td>
						</tr>
						<tr valign="top">
							<th scope="row"><label><?php _e('UPME Integration', 'mysql-directory-service'); ?></label></th>
							<td><input type="checkbox" name="mysqlds_upme_integration" id="mysqlds_upme_integration"<?php if ( $this->opts['mysqlds_upme_integration'] ) echo ' checked="checked"' ?> value="1" /></td>
							<td><span class="description"><?php _e('When checked, activates UPME handling by this plugin (including blog-specific settings). This SHOULD be left checked if you are using UPME.', 'mysql-directory-service'); ?></span></td>
						</tr>
						<?php
					}
					elseif( is_admin() && is_multisite() ) {
						if( $this->opts['mysqlds_allow_login_network'] == false ) {
							?>
							<tr valign="top">
								<th scope="row"><label><?php _e('Allow Network Login', 'mysql-directory-service'); ?></label></th>
								<td colspan="2"><span class="description"><strong style="color:red;"><?php _e('Mysql authentication is currently turned-off for the entire network. Contact your administrator for more details.', 'mysql-directory-service'); ?></strong><span></td>
							</tr>
							<?php
						}
						?>
						<tr valign="top">
							<th scope="row"><label><?php _e('Allow Login', 'mysql-directory-service'); ?></label></th>
							<td><input type="checkbox" name="mysqlds_allow_login" id="mysqlds_allow_login"<?php if ( $this->opts['mysqlds_allow_login'] ) echo ' checked="checked"' ?> value="1" /></td>
							<td><span class="description"><?php _e('When checked, activates Mysql database authentication for this site.', 'mysql-directory-service'); ?></span></td>
						</tr>
						<?php
						if( $this->opts['mysqlds_upme_integration'] == false ) {
							?>
							<tr valign="top">
								<th scope="row"><label><?php _e('UPME Integration', 'mysql-directory-service'); ?></label></th>
								<td colspan="2"><span class="description"><strong style="color:red;"><?php _e('UPME integration is currently deactivated on entire network. Contact administrator for details.', 'mysql-directory-service'); ?></strong><span></td>
							</tr>
							<?php
						}
						else {
							?>
							<tr valign="top">
								<th scope="row"><label><?php _e('UPME Redirect', 'mysql-directory-service'); ?></label></th>
								<td><input type="checkbox" name="mysqlds_upme_redirect" id="mysqlds_upme_redirect"<?php if ( $this->opts['mysqlds_upme_redirect'] ) echo ' checked="checked"' ?> value="1" /></td>
								<td><span class="description"><?php _e('When checked, users will be redirected to their profile page after login if some of their required UPME profile fields are not set.', 'mysql-directory-service'); ?></span></td>
							</tr>
							<?php
						}
					}
					elseif( is_admin() && !is_multisite() ) {
						?>
						<tr valign="top">
							<th scope="row"><label><?php _e('Allow Login', 'mysql-directory-service'); ?></label></th>
							<td><input type="checkbox" name="mysqlds_allow_login" id="mysqlds_allow_login"<?php if ( $this->opts['mysqlds_allow_login'] ) echo ' checked="checked"' ?> value="1" /></td>
							<td><span class="description"><?php _e('When checked, activates Mysql database authentication for this site.', 'mysql-directory-service'); ?></span></td>
						</tr>
						<tr valign="top">
							<th scope="row"><label><?php _e('Allow Delete Users', 'mysql-directory-service'); ?></label></th>
							<td><input type="checkbox" name="mysqlds_allow_delete_users" id="mysqlds_allow_delete_users"<?php if ( $this->opts['mysqlds_allow_delete_users'] ) echo ' checked="checked"' ?> value="1" /></td>
							<td><span class="description"><?php _e('When checked, enables administrators to optionnally delete users from the Mysql Authentication Service database along with the Wordpress internal database (when on the "delete profile" form).', 'mysql-directory-service'); ?></span></td>
						</tr>
						<tr valign="top">
							<th scope="row"><label><?php _e('UPME Integration', 'mysql-directory-service'); ?></label></th>
							<td><input type="checkbox" name="mysqlds_upme_integration" id="mysqlds_upme_integration"<?php if ( $this->opts['mysqlds_upme_integration'] ) echo ' checked="checked"' ?> value="1" /></td>
							<td><span class="description"><?php _e('When checked, activates UPME handling by this plugin (including blog-specific settings). This SHOULD be left checked if you are using UPME.', 'mysql-directory-service'); ?></span></td>
						</tr>
						<tr valign="top">
							<th scope="row"><label><?php _e('UPME Redirect', 'mysql-directory-service'); ?></label></th>
							<td><input type="checkbox" name="mysqlds_upme_redirect" id="mysqlds_upme_redirect"<?php if ( $this->opts['mysqlds_upme_redirect'] ) echo ' checked="checked"' ?> value="1" /></td>
							<td><span class="description"><?php _e('When checked, users will be redirected to their profile page after login if some of their required UPME profile fields are not set.', 'mysql-directory-service'); ?></span></td>
						</tr>
					<?php
					}
					?>
				</table>
				
				<?php
				if( is_network_admin() || (is_admin() && !is_multisite()) ) {
					?>
				
					<h3><?php _e('Mysql Database Connection', 'mysql-directory-service'); ?></h3>
					<table class="form-table">
						<tr valign="top">
							<th scope="row"><label><?php _e('Host', 'mysql-directory-service'); ?></label></th>
							<td><input type="text" name="mysqlds_host" value="<?php echo $this->opts['mysqlds_host']; ?>" /> </td>
							<td><span class="description"><?php _e('Server hostname or IP address.', 'mysql-directory-service'); ?></span> </td>
						</tr>
						<tr valign="top">
							<th scope="row"><label><?php _e('Port', 'mysql-directory-service'); ?></label></th>
							<td><input type="text" name="mysqlds_port" value="<?php echo $this->opts['mysqlds_port']; ?>" /> </td>
							<td><span class="description"><?php _e('Leave empty to use the default port.', 'mysql-directory-service'); ?></span></td>
						</tr>        
						<tr valign="top">
							<th scope="row"><label><?php _e('Database', 'mysql-directory-service'); ?></label></th>
							<td><input type="text" name="mysqlds_db" value="<?php echo $this->opts['mysqlds_db']; ?>" /></td>
							<td><span class="description"><?php _e('Database name.', 'mysql-directory-service'); ?></span></td>
						</tr>
						<tr valign="top">
							<th scope="row"><label><?php _e('Username', 'mysql-directory-service'); ?></label></th>
							<td><input type="text" name="mysqlds_user" value="<?php echo $this->opts['mysqlds_user']; ?>" /></td>
							<td><span class="description"><?php _e('Account used for Mysql connections.', 'mysql-directory-service'); ?></span></td>
						</tr>
						<tr valign="top">
							<th scope="row"><label><?php _e('Password', 'mysql-directory-service'); ?></label></th>
							<td><input type="password" name="mysqlds_pw" value="<?php echo $this->opts['mysqlds_pw']; ?>" /></td>
							<td><span class="description"><?php _e('Account password.', 'mysql-directory-service'); ?></span></td>
						</tr>
						<tr valign="top">
							<th scope="row"><label><?php _e('User table', 'mysql-directory-service'); ?></label></th>
							<td><input type="text" name="mysqlds_table" value="<?php echo $this->opts['mysqlds_table']; ?>" /></td>
							<td><span class="description"><?php _e('Name of the table containing Wordpress user data.', 'mysql-directory-service'); ?></span></td>
						</tr>
					</table>

					<h3><?php _e('Field Mappings', 'mysql-directory-service'); ?></h3>
					<table class="form-table">
						<tr valign="top">
							<th scope="row"><label><?php _e('Username', 'mysql-directory-service'); ?></label></th>
							<td><input type="text" name="mysqlds_namefield" value="<?php echo $this->opts['mysqlds_namefield']; ?>" /></td>
							<td><span class="description"><?php echo 'user_login'; ?></span></td>
						</tr>
						<tr valign="top">
							<th scope="row"><label><?php _e('Password', 'mysql-directory-service'); ?></label></th>
							<td><input type="text" name="mysqlds_pwfield" value="<?php echo $this->opts['mysqlds_pwfield']; ?>" /></td>
							<td><span class="description"><?php echo 'user_pass'; ?></span><td>
						</tr>
						<tr valign="top">
							<th scope="row"><label><?php _e('First name', 'mysql-directory-service'); ?></label></th>
							<td><input type="text" name="mysqlds_first_name" value="<?php echo $this->opts['mysqlds_first_name']; ?>" /></td>
							<td><span class="description"><?php echo 'first_name'; ?></span><td>
						</tr>
						<tr valign="top">
							<th scope="row"><label><?php _e('Last name', 'mysql-directory-service'); ?></label></th>
							<td><input type="text" name="mysqlds_last_name" value="<?php echo $this->opts['mysqlds_last_name']; ?>" /></td>
							<td><span class="description"><?php echo 'last_name'; ?></span><td>
						</tr>
						<tr valign="top">
							<th scope="row"><label><?php _e('Email', 'mysql-directory-service'); ?></label></th>
							<td><input type="text" name="mysqlds_user_email" value="<?php echo $this->opts['mysqlds_user_email']; ?>" /></td>
							<td><span class="description"><?php echo 'user_email'; ?></span><td>
						</tr>
					</table>
					<?php
				}
				?>
				<p class="submit">
					<input type="submit" name="Submit" value="Save changes" />
				</p>
			</form>
		</div>
		<?php
	}
	 
	/**
	 *	Saves multisite options (since it is not yet handled automatically by the Wordpress Settings API).
	 */
	private function _save_multisite_options( $data ) {
	
		if (!isset($data['mysqlds_allow_login_network'])) {
			$data['mysqlds_allow_login_network'] = 0;
		}
		if (!isset($data['mysqlds_allow_login'])) {
			$data['mysqlds_allow_login'] = 0;
		}
		if (!isset($data['mysqlds_allow_delete_users'])) {
			$data['mysqlds_allow_delete_users'] = 0;
		}
		if (!isset($data['mysqlds_upme_integration'])) {
			$data['mysqlds_upme_integration'] = 0;
		}
		if (!isset($data['mysqlds_upme_redirect'])) {
			$data['mysqlds_upme_redirect'] = 0;
		}
		
		if( is_network_admin() ) {
			update_site_option('mysqlds_host', $data['mysqlds_host']);
			update_site_option('mysqlds_port', $data['mysqlds_port']);
			update_site_option('mysqlds_db', $data['mysqlds_db']);
			update_site_option('mysqlds_user', $data['mysqlds_user']);
			update_site_option('mysqlds_pw', $data['mysqlds_pw']);
			update_site_option('mysqlds_table', $data['mysqlds_table']);
			update_site_option('mysqlds_namefield', $data['mysqlds_namefield']);
			update_site_option('mysqlds_pwfield', $data['mysqlds_pwfield']);
			update_site_option('mysqlds_first_name', $data['mysqlds_first_name']);
			update_site_option('mysqlds_last_name', $data['mysqlds_last_name']);
			update_site_option('mysqlds_user_email', $data['mysqlds_user_email']);
			update_site_option('mysqlds_allow_login_network', $data['mysqlds_allow_login_network']);
			update_site_option('mysqlds_allow_delete_users', $data['mysqlds_allow_delete_users']);
			update_site_option('mysqlds_upme_integration', $data['mysqlds_upme_integration']);
		}
		elseif( is_admin() ) {
			if( is_multisite() ) {
				update_option('mysqlds_allow_login', $data['mysqlds_allow_login']);
				update_option('mysqlds_upme_redirect', $data['mysqlds_upme_redirect']);
			}
			else {
				update_option('mysqlds_host', $data['mysqlds_host']);
				update_option('mysqlds_port', $data['mysqlds_port']);
				update_option('mysqlds_db', $data['mysqlds_db']);
				update_option('mysqlds_user', $data['mysqlds_user']);
				update_option('mysqlds_pw', $data['mysqlds_pw']);
				update_option('mysqlds_table', $data['mysqlds_table']);
				update_option('mysqlds_namefield', $data['mysqlds_namefield']);
				update_option('mysqlds_pwfield', $data['mysqlds_pwfield']);
				update_option('mysqlds_first_name', $data['mysqlds_first_name']);
				update_option('mysqlds_last_name', $data['mysqlds_last_name']);
				update_option('mysqlds_user_email', $data['mysqlds_user_email']);
				update_option('mysqlds_allow_login', $data['mysqlds_allow_login']);
				update_option('mysqlds_allow_delete_users', $data['mysqlds_allow_delete_users']);
				update_option('mysqlds_upme_integration', $data['mysqlds_upme_integration']);
				update_option('mysqlds_upme_redirect', $data['mysqlds_upme_redirect']);
			}
		}
		
		//	Reload options.
		$this->_load_options();
		
	}

	/**
	 *	Authenticates users if their credentials are found in configured database.
	 *
	 *	Also creates the user in Wordpress database at the end of the authentication process.
	 */
	public function authenticate($user = NULL, $username = '', $password = '') {
		
		$this->errors = new WP_Error();
	
		if( is_multisite() ) $cb = 'get_site_option';
		else $cb = 'get_option';
	
		$db_host = $this->opts['mysqlds_host'];
		$db_user = $this->opts['mysqlds_user'];
		$db_pass = $this->opts['mysqlds_pw'];
		$db = $this->opts['mysqlds_db'];
		$db_user_table = $this->opts['mysqlds_table'];
		
		$db_field_username = $this->opts['mysqlds_namefield'];
		$db_field_password = $this->opts['mysqlds_pwfield'];

		$db_link = mysqli_connect($db_host, $db_user, $db_pass, $db) or die("Error " . mysqli_error($db_link));
		
		$result = mysqli_query($db_link, "SET NAMES 'utf8'");
		$result = mysqli_query($db_link, "SELECT * FROM `" . $db_user_table . "` WHERE `$db_field_username`='" . $username . "'");
		if( $result === false ) {
			//die("Error " . mysqli_error($db_link));
		}
		$data = mysqli_fetch_assoc($result);

		if( $data != NULL ) {
			if( $data[$db_field_password] == md5($password) ) {
				
				//	Exit if network-wide or site authentication has been deactivated for this plugin.
				if( !is_multisite() && get_option('mysqlds_allow_login') == '0' ) {
					$this->errors->add('mysqlds_site_deactivated', __("The authentication service where your account is hosted is currently deactivated for this site.", 'mysql-directory-service'));
					$user = $this->errors;
					return $this->errors;
				}
				if( is_multisite() && get_option('mysqlds_allow_login') == '0' ) {
					$this->errors->add('mysqlds_site_deactivated', __("The authentication service where your account is hosted is currently deactivated for this site.", 'mysql-directory-service'));
					$user = $this->errors;
					return $this->errors;
				}
				elseif( is_multisite() && get_site_option('mysqlds_allow_login_network') == '0' ) {
					$this->errors->add('mysqlds_network_deactivated', __("The authentication service where your account is hosted is currently deactivated for this network.", 'mysql-directory-service'));
					$user = $this->errors;
					return $this->errors;
				}
			
				$userdata = array();
				$userdata['user_login'] = $username;
				$userdata['user_pass'] = $password;
				//$userdata['directory_service'] = $this->opts['mysqlds_host'];
				if( !empty($data[$this->opts['mysqlds_first_name']]) ) $userdata['first_name'] = $data[$this->opts['mysqlds_first_name']];
				if( !empty($data[$this->opts['mysqlds_last_name']]) ) $userdata['last_name'] = $data[$this->opts['mysqlds_last_name']];
				if( !empty($data[$this->opts['mysqlds_user_email']]) ) $userdata['user_email'] = $data[$this->opts['mysqlds_user_email']];
				
				if( $id = username_exists($username) ) {
					$userdata['ID'] = $id;
					wp_update_user($userdata);
				}
				else {
					wp_insert_user($userdata);
				}
				
				if ($id = username_exists($username)) {
					$user = new WP_User($id);
					update_user_meta($user->ID, 'directory_service', $this->opts['mysqlds_host'] );
					return $user;
				}
			
			}
			else {	//	Username found but wrong password.
				$this->errors->add('mysqlds_wrongpw', __("Invalid password.", 'mysql-directory-service'));
				$user = $this->errors;
				return $this->errors;
			}
		}
		else {  //	User not found in external database. Let authentication continue with other plugins or internal.	
		
		}
	
	}
	
	/**
	 *	Generates a password.
	 */	
	public function generate_password( $length = 12, $special_chars = true, $extra_special_chars = false ) {
		$chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
		if ( $special_chars ) $chars .= '!@#$%^&*()';
		if ( $extra_special_chars ) $chars .= '-_ []{}<>~`+=,.;:/?|';
		$password = '';
		for ( $i = 0; $i < $length; $i++ ) {
			$password .= substr($chars, wp_rand(0, strlen($chars) - 1), 1);
		}
		return $password;
	}

	/**
	 *	Generates a password for user currently being created.
	 */	
	public function create_user_password( $password ) {
		$password = $this->generate_password();
		if( empty($this->_user_pass) ) $this->_user_pass = $password;
		return $password;
	}

	/**
	 *	Overrides Wordpress password check with internal database for external users.
	 */
	public function override_password_check($check, $password, $hash, $user_id) {
		$err = $this->errors->get_error_code();
		if( empty($err) ) {
			$check = true;
			return $check;	//	Should never happen since user already authenticated through this class.
		}
		else {
			$check = false;
			return $check;
		}
	}
	
	/**
	 *	Displays an error message for disabled Wordpress functionalities.
	 *
	 *	This method should be called through various WP hooks, such as "lost_password".
	 *
	 *	TODO: Recode the method to reflect the fact that it's not only called by one WP action.
	 */
	public function disable_functionality() {
		$errors = new WP_Error();
		$errors->add('registerdisabled', __('User registration is not available from this site, so you can\'t create an account or retrieve your password from here. See the message above.', 'mysql-directory-service'));
		login_header(__('Log In', 'mysql-directory-service'), '', $errors);

		?>
		<p id="backtoblog"><a href="<?php bloginfo('url'); ?>/" title="<?php _e('Are you lost?', 'mysql-directory-service') ?>"><?php printf(__('&larr; Back to %s', 'mysql-directory-service'), get_bloginfo('title', 'display')); ?></a></p>
		<?php
		exit();
	}

	/**
	 *	Login errors display output.
	 *
	 *	TODO: Recode method to use member variable instead of global.
	 *
	 */
	public function login_errors( $msg = '' ) {
		
		$err_codes = array('mysqlds_site_deactivated', 'mysqlds_network_deactivated', 'mysqlds_wrongpw', 'mysqlds_wrongrole');
	
		foreach( $err_codes as $code ) {
			$err = $this->errors->get_error_message($code);
			if( !empty($err) ) {
				$msg = $err;
				break;
			}
		}
	
		return $msg;
	
	}

	/**
	 *	Validation before a user self-registers in single-site environment.
	 *
	 *	Mostly used to check if username/email are already used in other authentication services.
	 */
	public function registration_errors( $errors = NULL, $username = '', $email = '' ) {
	
		if( !is_object($errors) ) $errors = new WP_Error();
		if( empty($username) ) $errors->add('mysqlds_empty_username', __('Username must be provided.', 'mysql-directory-service'));
		if( empty($email) ) $errors->add('mysqlds_empty_email', __('Email address must be provided.', 'mysql-directory-service'));
	
		$user_exists = false;
		$email_exists = false;
		
		//	Checks if username exists.
		$user_entry = $this->username_exists($username);
		if( $user_entry === false ) {
			$errors->add('user_name', __('Error while accessing database.', 'mysql-directory-service'));
		}
		elseif( is_array($user_entry) && count($user_entry) > 0 ) {
			$user_exists = true;
		}
		
		//	Checks if email exists.
		$email_entry = $this->email_exists($email);
		if( $email_entry === false ) {
			$errors->add('user_email', __('Error while accessing database.', 'mysql-directory-service'));
		}
		elseif( is_array($email_entry) && count($email_entry) > 0 ) {
			$email_exists = true;
		}
		
		if( $user_exists && $email_exists ) {
		
			//	Only admins can insert user accounts in WP that already exists in external DB.
			//	Normal users should simply authenticate.
			if( !is_admin() || !current_user_can('create_users') || $user_entry[0][$this->opts['mysqlds_user_email']] != $email ) {
				$errors->add('user_name', __('This username is already in use.', 'mysql-directory-service'));
				$errors->add('user_email', __('This email address is already in use.', 'mysql-directory-service'));
			}
			
		}
		elseif( $user_exists ) {
			$errors->add('user_name', __('This username is already in use.', 'mysql-directory-service'));
		}
		elseif( $email_exists ) {
			$errors->add('user_email', __('This email address is already in use.', 'mysql-directory-service'));
		}
		else {
			//	OK!
		}
	
		//	Stores password in class member since at the time of call to this function,
		//	the password is not yet encrypted.
		if( !empty($_POST['user_pass']) ) {
			$this->_user_pass = $_POST['user_pass'];
		}
	
		return $errors;
	
	}

	/**
	 *	Validation before a user self-registers or admin creates a user in multi-site environment.
	 *
	 *	Mostly used to check if username/email are already used in other authentication services.
	 */
	public function wpmu_validate_user_signup( $result ) {
	
		$username = $result['user_name'];
		$email = $result['user_email'];
		$errors = &$result['errors'];
	
		if( !($errors instanceof WP_Error) ) die("mysqlds_db-plugin:mysqlds_wpmu_validate_user_signup: exception triggered");
		if( empty($username) ) $errors->add('mysqlds_empty_username', __('Username must be provided.', 'mysql-directory-service'));
		if( empty($email) ) $errors->add('mysqlds_empty_email', __('Email address must be provided.', 'mysql-directory-service'));
		
		$user_exists = false;
		$email_exists = false;
		
		//	Checks if username exists.
		$user_entry = $this->username_exists($username);
		if( $user_entry === false ) {
			$errors->add('user_name', __('Error while accessing database.', 'mysql-directory-service'));
		}
		elseif( is_array($user_entry) && count($user_entry) > 0 ) {
			$user_exists = true;
		}
		
		//	Checks if email exists.
		$email_entry = $this->email_exists($email);
		if( $email_entry === false ) {
			$errors->add('user_email', __('Error while accessing database.', 'mysql-directory-service'));
		}
		elseif( is_array($email_entry) && count($email_entry) > 0 ) {
			$email_exists = true;
		}
		
		if( $user_exists && $email_exists ) {
		
			//	Only admins can insert user accounts in WP that already exists in external DB.
			//	Normal users should simply authenticate.
			if( !is_admin() || !current_user_can('create_users') || $user_entry[0][$this->opts['mysqlds_user_email']] != $email ) {
				$errors->add('user_name', __('This username is already in use.', 'mysql-directory-service'));
				$errors->add('user_email', __('This email address is already in use.', 'mysql-directory-service'));
			}
			
		}
		elseif( $user_exists ) {
			$errors->add('user_name', __('This username is already in use.', 'mysql-directory-service'));
		}
		elseif( $email_exists ) {
			$errors->add('user_email', __('This email address is already in use.', 'mysql-directory-service'));
		}
		else {
			//	OK!
		}
		
		return $result;
	}
	
	/**
	 *	Validation before a profile is updated by the user or an amdin (single/multi-site), or an admin creates a user (single-site).
	 *
	 *	Mostly used to check if username/email are already used in other authentication services.
	 */
	public function user_profile_update_errors( $errors, $update, $user ) {
		
		if( is_multisite() ) $cb = 'get_site_option';
		else $cb = 'get_option';
	
		$field_username = call_user_func($cb, 'mysqlds_namefield');
		$field_email = call_user_func($cb, 'mysqlds_user_email');
		
		if( $update ) {
			$old_user = get_userdata($user->ID);
			if( $old_user === false ) {
				$errors->add('user_name', __('Could not find user in Wordpress database.', 'mysql-directory-service'));
				return $errors; 
			}
			if( !isset($user->user_login) || empty($user->user_login) ) {
				$user->user_login = $old_user->user_login;
			}
			if( !isset($user->user_email) || empty($user->user_email) ) {
				$user->user_email = $old_user->user_email;
			}
		}
		
		$username = $user->user_login;
		$email = $user->user_email;
		$user_exists = false;
		$email_exists = false;
		
		//	Checks if username exists.
		$user_entry = $this->username_exists($username);
		if( $user_entry === false ) {
			$errors->add('user_name', __('Error while accessing database.', 'mysql-directory-service'));
		}
		elseif( is_array($user_entry) && count($user_entry) > 0 ) {
			$user_exists = true;
		}
		
		//	Checks if email exists.
		$email_entry = $this->email_exists($email);
		if( $email_entry === false ) {
			$errors->add('user_email', __('Error while accessing database.', 'mysql-directory-service'));
		}
		elseif( is_array($email_entry) && count($email_entry) > 0 ) {
			$email_exists = true;
		}
		
		if( $user_exists && $email_exists ) {
		
			//	Only admins can insert user accounts in WP that already exists in external DB.
			//	Normal users should simply authenticate.
			if( $user_entry[0][$this->opts['mysqlds_user_email']] != $email ) {
				$errors->add('user_name', __('This username is already in use.', 'mysql-directory-service'));
				$errors->add('user_email', __('This email address is already in use.', 'mysql-directory-service'));
			}
			else {
				if( !$update && !is_admin() && !current_user_can('create_users') ) {
					$errors->add('user_name', __('This username is already in use.', 'mysql-directory-service'));
					$errors->add('user_email', __('This email address is already in use.', 'mysql-directory-service'));
				}
			}
			
		}
		elseif( $user_exists ) {	//	Attempt to update email, address does not already exists.
			if( !$update ) {
				$errors->add('user_name', __('This username is already in use.', 'mysql-directory-service'));
			}
		}
		elseif( $email_exists ) {	//	Attempt to create user but email address already exists.
			$errors->add('user_email', __('This email address is already in use.', 'mysql-directory-service'));
		}
		else {	//	Attempt to create user, both username and email are not in use.
			//	OK
		}
		
		//	Stores password in class member since at the time of call to this function,
		//	the password is not yet encrypted.
		$err_code = $errors->get_error_code();
		if( empty($err_code) ) {
			if( !empty($_POST['user_pass']) ) {
				$this->_user_pass = $_POST['user_pass'];
			}
		}
	
		return $errors;
	
	}

	/**
	 *	Displays additionnal fields in WP's view user profile form.
	 */
	public function edit_user_profile( $user ) {
		?>
			<table class="form-table">
				<tr>
					<th><label><?php _e('Authentication service', 'mysql-directory-service');?></label></th>
					<td>
						<?php
							echo '<input type="text" name="directory_service" id="directory_service" value="'.esc_html(get_user_meta($user->ID,'directory_service',true)).'" class="regular-text code" disabled/>';
						?>
						<p class="description">
							<?php _e('Authentication service for this account.', 'mysql-directory-service'); ?>
						</p>
					</td>
				</tr>
			</table>
		<?php 
	}

	/**
	 *	Adds column headers in WP's user list view.
	 */
	public function manage_users_columns($columns) {
		$columns['directory_service'] = __('Authentication', 'mysql-directory-service');
		return $columns;
	}

	/**
	 *	Adds column content in WP's user list view.
	 */
	public function manage_users_custom_column( $value, $column_name, $user_id ) {

		// Column "directory_service"
		if ( $column_name == 'directory_service' ) {
			$value = get_user_meta($user_id, 'directory_service', true);
			if (empty($value)) {
				$value = 'internal';
			}
		}
	
		return $value;
	}

	/**
	 *	Triggers standard wordpress actions upon user login failure through UPME.
	 */
	public function upme_login_failed($usermeta, $errors, $params) {
		$err_codes = array('mysqlds_site_deactivated', 'mysqlds_network_deactivated', 'mysqlds_wrongpw', 'mysqlds_wrongrole');
		global $upme_login;
		$msg = '';
		$msg .= apply_filters('login_errors', $msg);
		if( $msg != '' ) {
			if( $this->errors->get_error_code() == 'mysqlds_site_deactivated' || $this->errors->get_error_code() == 'mysqlds_network_deactivated' || $this->errors->get_error_code() == 'mysqlds_wrongpw' ) {
				$upme_login->errors = array();
			}
			$upme_login->errors[] = $msg;
		}
	}
	
	/**
	 *	Triggers standard wordpress actions upon user creation when user self registers through UPME.
	 */
	public function upme_user_register( $user_id ) {
		
		/*
		if (isset($_POST['upme-register-form'])) {
			global $upme_register;
			$upme_register->errors[] = "upme_user_register";
		}*/
		
		if( is_multisite() ) {

			//	Creates user in external database when user self registers or
			//	admin creates a new user (multi-site).
			do_action('wpmu_new_user', $user_id);
	
		}
		else {
	
			//	Creates user in external database when user self registers (single-site) or
			//	admin creates a new user (single site).
			do_action('user_register', $user_id);
	
		}
	}

	/**
	 *	UPME filter to preprocess profile fields upon registration.
	 */
	public function upme_registration_custom_field_type_restrictions( $errors, $field ) {
	
		global $mysqlds_upme;
	
		//	Patch for calling the standard "registration_errors" filter when registration
		//	is handled by upme.
		if( $field['meta'] == 'user_login' || $field['meta'] == 'user_email' ) {
			if( !is_array($mysqlds_upme) ) $mysqlds_upme = array('validated'=>false);
			if( $field['meta'] == 'user_login' ) {
				$mysqlds_upme['user_login'] = $field['value'];
			}
			elseif( $field['meta'] == 'user_email' ) {
				$mysqlds_upme['user_email'] = $field['value'];
			}
			if( isset($mysqlds_upme['user_login']) && isset($mysqlds_upme['user_email']) && $mysqlds_upme['validated'] == false ) {
				$err = new WP_Error();
				$err = apply_filters('registration_errors', $err, $mysqlds_upme['user_login'], $mysqlds_upme['user_email']);
				$mysqlds_upme['validated'] = true;
				foreach( $err->errors as $e ) {
					if( is_array($e) ) {
						$errors[] = $e[0];
					}
					else {
						$errors[] = $e;
					}
				}
			}
		}
		elseif( $field['meta'] == 'user_pass' && !empty($field['value']) ) {
			
			//	Trap unencrypted password here before Wordpress jumbles it so we can store it
			//	with our own encryption scheme.
			$this->_user_pass = $field['value'];
			
		}
	
		return $errors;
	
	}


	/**
	 *	UPME filter to preprocess profile fields upon profile update.
	 */
	public function upme_frontend_custom_field_type_restrictions( $errors, $field ) {
	
		global $mysqlds_upme;
	
		//	Check that profile is hosted on this service.
		//	This assumes that only this directory service is writeable (could be addressed
		//	by modifying all other authentication plugins such as ADI, but not necessary at
		//	the moment).
		$restricted_fields = array('first_name', 'last_name', 'user_email');
		if( in_array($field['meta'], $restricted_fields) ) {
			$current_user = wp_get_current_user();
			if( !($current_user instanceof WP_User) || !isset($current_user->user_login) ) {
				$errors[] = "Aucun utilisateur connecté.";
				return $errors;
			}
			if( $field['value'] != $current_user->get($field['meta']) ) {
				$directory_service = get_user_meta($current_user->ID, 'directory_service', true);
				if( is_multisite() ) $cb = 'get_site_option';
				else $cb = 'get_option';
				$host = call_user_func($cb, 'mysqlds_host');
				if( $directory_service != $host ) {
					$errors[] = __('The "lastname", "firstname" et "email" values come from a read-only source and cannot be edited from this form.', 'mysql-directory-service');
				}
			}
		}
		elseif( $field['meta'] == 'user_pass' && !empty($field['value']) ) {
			
			//	Trap unencrypted password here before Wordpress jumbles it so we can store it
			//	with our own encryption scheme.
			$this->_user_pass = $field['value'];
			
		}
	
		return $errors;
	
	}
	
	
	public function upme_redirect_show_message($html, $id) {
		if( isset($_SESSION) && array_key_exists('mysqlds_upme_redirect_show_message', $_SESSION) && $_SESSION['mysqlds_upme_redirect_show_message'] == true ) {
			$_SESSION['mysqlds_upme_redirect_show_message'] = false;
			$html .= '<div id="mysqlds-edit-form-err-holder" style="display: block;" class="upme-errors">';
			$html .= '<span class="upme-error upme-error-block" upme-data-name="mysqlds_redirect">';
			$html .= '<i class="upme-icon upme-icon-remove"></i>' . __("Please complete your profile before proceeding.", 'mysql-directory-service') . '</span></div>';
		}
		return $html;
	}

	/**
	 *	Redirects logged-in users to their profile page if some UPME required fields are not set.
	 */
	public function redirect_incomplete_upme_profiles() {
	
		//	Get user info.
		if( !is_user_logged_in() ) return;
		$user = wp_get_current_user();
		if( $user->ID != 0 && !is_admin() && !is_network_admin() ) {
			
			//	User was already redirected.
			if( isset($_SESSION) && array_key_exists('mysqlds_upme_redirect_show_message', $_SESSION) && $_SESSION['mysqlds_upme_redirect_show_message'] == true ) {
				wp_register_script('mysqlds-upme-redirect', plugin_dir_url(__FILE__) . 'js/mysqlds-upme-redirect.js', array('jquery'));
	            wp_enqueue_script('mysqlds-upme-redirect'); 
				return;
			}
			
			//	Check for empty required fields.
			$do_redirect = false;
			$upme_options = get_option('upme_options');
			$fields = get_option('upme_profile_fields');
			foreach( $fields as $pos => $f ) {
				if( array_key_exists('required', $f) && $f['required'] == '1' ) {
					$value = get_the_author_meta($f['meta'],$user->ID);
					if( empty($value) ) {
						$do_redirect = true;
					}
				}
			}
			if( !$do_redirect ) {
				return;
			}
			
			//	Request url and current blog url.
			( is_ssl() == true ) ? $request_url = 'https://' : $request_url = 'http://';
			$request_url .= $_SERVER['HTTP_HOST'] . $_SERVER['REQUEST_URI'];
			$blog_url = get_bloginfo('url');
		
			//	Don't redirect if request is external url or outside blog scope.
			if( strlen($request_url) < strlen($blog_url) || substr($request_url, 0, strlen($blog_url)) != $blog_url ) {
				return;
			}
		
			//	List of allowed url in the blog domain where no redirect is performed.
			$allowed_urls = array(
					$blog_url . '/wp-login.php?action=logout',			//	Logout
					get_permalink($upme_options['profile_page_id']),	//	UPME profile page
					WC()->cart->get_checkout_url()						//	Woocommerce checkout
			);
			
			//	Match request url against allowed urls.
			$do_redirect = false;
			foreach( $allowed_urls as $url ) {
				if( strlen($request_url) >= strlen($url) && substr($request_url, 0, strlen($url)) == $url ) {
					$do_redirect = true;
					break;
				}
			}
			if( !$do_redirect ) {
				return;
			}
			
			//	Actual redirect.
			$profile_url = get_permalink($upme_options['profile_page_id']) . '#open';
			$_SESSION['mysqlds_upme_redirect_show_message'] = true;
			wp_redirect($profile_url);
			die();
			
		}
	
	}

	/**
	 *	Traps JQuery Ajax calls launched by UPME
	 *
	 *	Traps JQuery Ajax calls launched by UPME to validate username/email dynamically on
	 *	registration and profile update forms. Username/email values are only matched against
	 *	WP's internal database, thus sometimes resulting in a "email adress available" message
	 *	when it is actually in use in the Mysql database.
	 */
	public function disable_upme_ajax() {
		die();
	}

};	//	END CLASS






//**************************************************************************************************************
//**************************************************************************************************************
//**************************************************************************************************************



/*
//gives warning for login - where to get "source" login
function mysqlds_auth_warning($message = '')
{
	
	if( is_multisite() ) $cb = 'get_site_option';
	else $cb = 'get_option';
	
    $message .= "<p class=\"message\">" . call_user_func($cb, 'mysqlds_error_msg') . "</p>";
    return $message;
}
*/


/*
//hopefully grays stuff out.
function mysqlds_warning()
{
	if( is_multisite() ) $cb = 'get_site_option';
	else $cb = 'get_option';
	
    echo '<strong style="color:red;">Any changes made below WILL NOT be preserved when you login again. You have to change your personal information per instructions found @ <a href="' . call_user_func($cb, 'mysqlds_site_url') . '">login box</a>.</strong>';
}
*/



register_activation_hook(__FILE__, 'MysqlDirectoryService::activate');
$MysqlDirectoryService = new MysqlDirectoryService();

?>
