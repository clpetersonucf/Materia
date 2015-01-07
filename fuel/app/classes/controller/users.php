<?php
/**
 * Materia
 * License outlined in licenses folder
 */

class Controller_Users extends Controller
{
	public function before()
	{
		$this->theme = Theme::instance();
		$this->theme->set_template('layouts/main');
	}

	public function after($response)
	{
		// If no response object was returned by the action,
		if (empty($response) or ! $response instanceof Response)
		{
			// render the defined template
			$me = Model_User::find_current();
			if ($me)
			{
				// add beardmode
				if ( ! empty($me->profile_fields['beardMode']))
				{
					// TODO: use angular userServ
					Js::push_inline('var BEARD_MODE = true;');
				}
			}
			$this->theme->set_partial('header', 'partials/header')->set('me', $me);

			// add google analytics
			if ($gid = Config::get('materia.google_tracking_id', false))
			{
				Js::push_inline($this->theme->view('partials/google_analytics', array('id' => $gid)));
			}

			Js::push_inline('var BASE_URL = "'.Uri::base().'";');
			Js::push_inline('var WIDGET_URL = "'.Config::get('materia.urls.engines').'";');
			Js::push_inline('var STATIC_CROSSDOMAIN = "'.Config::get('materia.urls.static_crossdomain').'";');
			$response = Response::forge(Theme::instance()->render());
		}

		return parent::after($response);
	}

	/**
	 * Uses Materia API's remote_login function to log the user in.
	 *
	 */
	public function get_login()
	{
		// figure out where to send if logged in
		$redirect = Input::get('redirect') ?: Router::get('profile');

		if (Model_User::find_current())
		{
			// already logged in
			Response::redirect($redirect);
		}

		Css::push_group(['core', 'login']);

		// TODO: remove ngmodal, jquery, convert author to something else, materia is a mess
		Js::push_group(['angular', 'ng_modal', 'jquery', 'materia', 'author', 'student']);

		$this->theme->get_template()
			->set('title', 'Login')
			->set('page_type', 'login');

		$this->theme->set_partial('content', 'partials/login')
			->set('redirect', urlencode($redirect));

	}

	public function post_login()
	{
		// figure out where to send if logged in
		$redirect = Input::get('redirect') ?: Router::get('profile');
		$login = Materia\Api::session_login(Input::post('username'), Input::post('password'));
		if ($login === true)
		{
			// if the location is the profile and they are an author, send them to my-widgets instead
			if (Materia\Api::session_valid('basic_author') == true && $redirect == Router::get('profile'))
			{
				$redirect = 'my-widgets';
			}
			Response::redirect($redirect);
		}
		else
		{
			$msg = \Model_User::check_rate_limiter() ? 'ERROR: Username and/or password incorrect.' : 'Login locked due to too many attempts.';
			Session::set_flash('login_error', $msg);
			$this->get_login();
		}
	}

	/**
	 * Uses Materia API's remote_logout function to log the user in.
	 *
	 */
	public function action_logout()
	{
		Materia\Api::session_logout();
		Response::redirect(Router::get('login'));
	}

	/**
	 * Displays information about the currently logged-in user
	 *
	 */
	public function get_profile()
	{
		if (Materia\Api::session_valid() !== true)
		{
			Session::set_flash('notice', 'Please log in to view this page.');
			Response::redirect(Router::get('login').'?redirect='.URI::current());
		}

		Css::push_group(['core', 'profile']);

		// TODO: remove ngmodal, jquery, convert author to something else, materia is a mess
		Js::push_group(['angular', 'ng_modal', 'jquery', 'materia', 'author', 'student']);

		// to properly fix the date display, we need to provide the raw server date for JS to access
		$server_date  = date_create('now', timezone_open('UTC'))->format('D, d M Y H:i:s');
		Js::push_inline("var DATE = '$server_date'");

		$this->theme->get_template()
			->set('title', 'Profile')
			->set('page_type', 'user profile');

		$this->theme->set_partial('content', 'partials/user/profile')
			->set('me', \Model_User::find_current());
	}

	/**
	 * Displays information about the currently logged-in user
	 *
	 */
	public function get_settings()
	{
		if (Materia\Api::session_valid() !== true)
		{
			Session::set_flash('notice', 'Please log in to view this page.');
			Response::redirect(Router::get('login').'?redirect='.URI::current());
		}

		Css::push_group(['core', 'profile']);

		// TODO: remove ngmodal, jquery, convert author to something else, materia is a mess
		Js::push_group(['angular', 'ng_modal', 'jquery', 'materia', 'author', 'student']);

		$this->theme->get_template()
			->set('title', 'Settings')
			->set('page_type', 'user profile settings');

		$this->theme->set_partial('content', 'partials/user/settings')
			->set('me', \Model_User::find_current());
	}

}