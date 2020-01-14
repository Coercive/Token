<?php
namespace Coercive\Security\Token;

use DateTime;
use Exception;

/**
 * CSRF Token
 *
 * @package 	Coercive\Security\Token
 * @link		https://github.com/Coercive/Token
 *
 * @author  	Anthony Moral <contact@coercive.fr>
 * @copyright   2020 Anthony Moral
 * @license 	MIT
 */
class Token
{
	const DEFAULT_SALT = __CLASS__;
	const DEFAULT_NAMESPACE = 'token';
	const DEFAULT_NAME = 'global';
	const DEFAULT_LENGTH = 128;

	/** @var int */
	private $max = 0;

	/** @var int */
	private $length;

	/** @var string */
	private $salt;

	/** @var string */
	private $namespace;

	/** @var string */
	private $default;

	/**
	 * CUT index.php
	 *
	 * @param string $request
	 * @return string
	 */
	static private function cutIndexFile(string $request): string
	{
		$index = strpos($request, 'index.php');
		if($index !== false) {
			$request = substr($request, 0, $index);
		}
		return $request;
	}

	/**
	 * CUT query part
	 *
	 * @param string $request
	 * @return string
	 */
	static private function cutGetParam(string $request): string
	{
		$get = strpos($request, '?');
		if($get !== false) {
			$request = substr($request, 0, $get);
		}
		return $request;
	}

	/**
	 * HTTP Referer server data
	 *
	 * @return string
	 */
	static private function getHttpReferer(): string
	{
		$referer = (string) filter_input(INPUT_SERVER, 'HTTP_REFERER', FILTER_VALIDATE_URL);
		return self::cutIndexFile(self::cutGetParam($referer));
	}

	/**
	 * HTTP Server current page
	 *
	 * @return string
	 */
	static private function getCurrentPage(): string
	{
		$port = (int) filter_input(INPUT_SERVER, 'SERVER_PORT', FILTER_VALIDATE_INT);
		$protocol = !empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off' || $port === 443 ? 'https' : 'http';
		$host = (string) filter_input(INPUT_SERVER, 'HTTP_HOST', FILTER_SANITIZE_FULL_SPECIAL_CHARS);
		$request = (string) filter_input(INPUT_SERVER, 'SCRIPT_NAME', FILTER_SANITIZE_FULL_SPECIAL_CHARS);
		$request = self::cutIndexFile($request);
		return "$protocol://$host$request";
	}

	/**
	 * OpenSSL random pseudo bytes
	 *
	 * @param int $length [optional]
	 * @return string
	 */
	static public function rand(int $length = self::DEFAULT_LENGTH): string
	{
		return bin2hex(openssl_random_pseudo_bytes($length));
	}

	/**
	 * Token constructor.
	 *
	 * @param int $length [optional]
	 * @param string $salt [optional]
	 * @param string $namespace [optional]
	 * @param string $default [optional]
	 * @throws Exception
	 */
	public function __construct(int $length = 0, string $salt = '', string $namespace = '', string $default = '')
	{
		# Start
		if(session_status() !== PHP_SESSION_ACTIVE || !session_id()) {
			throw new Exception('Coercive Token needs a session is started before being launched.');
		}

		# SET Code
		$this->length = $length ?: self::DEFAULT_LENGTH;
		$this->salt = $salt ?: self::DEFAULT_SALT;
		$this->namespace = $namespace ?: self::DEFAULT_NAMESPACE;
		$this->default = $default ?: self::DEFAULT_NAME;
	}

	/**
	 * Set the salt for hash token
	 *
	 * @param string $salt [optional]
	 * @return Token
	 */
	public function setSalt(string $salt = ''): Token
	{
		$this->salt = $salt ?: self::DEFAULT_SALT;
		return $this;
	}

	/**
	 * Set the session namespace
	 *
	 * @param string $namespace [optional]
	 * @return Token
	 */
	public function setNamespace(string $namespace = ''): Token
	{
		$this->namespace = $namespace ?: self::DEFAULT_NAMESPACE;
		return $this;
	}

	/**
	 * Set the default name for noname token
	 *
	 * @param string $default [optional]
	 * @return Token
	 */
	public function setDefaultName(string $default = ''): Token
	{
		$this->default = $default ?: self::DEFAULT_NAME;
		return $this;
	}

	/**
	 * Set the openssl_random_pseudo_bytes length for the random method
	 *
	 * @param int $length [optional]
	 * @return Token
	 */
	public function setRandLength(int $length = 0): Token
	{
		$this->length = $length ?: self::DEFAULT_LENGTH;
		return $this;
	}

	/**
	 * Set maximum limit for opened token for a single id
	 *
	 * @param int $limit [optional] 0 === unlimited
	 * @return Token
	 */
	public function setMaxOpened(int $limit = 0): Token
	{
		$this->max = $limit;
		return $this;
	}

	/**
	 * Create token
	 *
	 * @param string $name [optional]
	 * @param string $page [optional]
	 * @param int $max [optional] 0 === unlimited
	 * @return string CSRF Token
	 */
	public function create(string $name = '', string $page = '', int $max = null): string
	{
		# Auto set referer
		if(!$page) {
			$page = self::getCurrentPage();
		}

		# Auto set name
		if(!$name) {
			$name = $this->default;
		}

		# Generate token
		$token = $this->uniqId();

		# Set in session
		$_SESSION[$this->namespace][$name][] = [
			'page' => $page,
			'token' => $token,
			'time' => time()
		];

		# Handle limit
		$limit = $this->max;
		if($max !== null) {
			$limit = $max;
		}
		if($limit) {
			while(count($_SESSION[$this->namespace][$name]) > $this->max) {
				array_shift($_SESSION[$this->namespace][$name]);
			}
		}

		# Maintain chainability
		return $token;
	}

	/**
	 * Check token
	 *
	 * @param string $token
	 * @param string $name [optional]
	 * @param array $referers [optional]
	 * @param int $length [optional] in seconds / default : 10 min
	 * @return bool
	 */
	public function check(string $token, string $name = '', array $referers = [], int $length = 600)
	{
		# Auto set referer
		if(!$referers) {
			$referers = [self::getHttpReferer()];
		}

		# Auto set name
		if(!$name) {
			$name = $this->default;
		}

		# Retreive targeted token
		$session = [];
		foreach ($_SESSION[$this->namespace][$name] ?? [] as $item) {
			if(!empty($item['token']) && $token === $item['token']) {
				$session = $item;
				break;
			}
		}
		if(!isset($session['page'])
			|| empty($session['token'])
			|| empty($session['time'])) {
			return false;
		}

		# Checks
		if($token !== $session['token']) {
			return false;
		}
		if(!in_array($session['page'], $referers, true)) {
			return false;
		}
		if(time() >= $session['time'] + $length) {
			return false;
		}
		return true;
	}

	/**
	 * Delete token
	 *
	 * @param string $name [optional]
	 * @param string $token [optional]
	 * @return bool
	 */
	public function delete(string $name = '', string $token = ''): bool
	{
		# Auto set name
		if(!$name) {
			$name = $this->default;
		}

		# Delete
		if(isset($_SESSION[$this->namespace][$name])) {

			# Targeted
			if($token) {
				$nb = 0;
				foreach ($_SESSION[$this->namespace][$name] ?? [] as $k => $item) {
					if(!empty($item['token']) && $token === $item['token']) {
						unset($_SESSION[$this->namespace][$name][$k]);
						$nb++;
					}
				}
				return $nb > 0;
			}

			# All
			else {
				unset($_SESSION[$this->namespace][$name]);
				return true;
			}
		}
		return false;
	}

	/**
	 * Timer Token
	 *
	 * @param string $crypt [optional]
	 * @param string $format [optional]
	 * @param DateTime $date [optional]
	 * @return string
	 */
	public function timer(string $crypt = '', string $format = 'Ymd', DateTime $date = null): string
	{
		# Auto Current DateTime
		if(!$date) { $date = new DateTime; }

		# Create uniq token
		return hash('sha512', $this->salt . $date->format($format) . $crypt);
	}

	/**
	 * Uniq ID with openssl_random_pseudo_bytes
	 *
	 * @return string
	 */
	public function uniqId(): string
	{
		return hash('sha512', session_id() . $this->salt . self::rand($this->length), false);
	}
}
