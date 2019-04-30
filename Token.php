<?php
namespace Coercive\Security\Token;

use DateTime;
use Exception;

/**
 * Token
 *
 * @package 	Coercive\Security\Token
 * @link		https://github.com/Coercive/Token
 *
 * @author  	Anthony Moral <contact@coercive.fr>
 * @copyright   2019 Anthony Moral
 * @license 	MIT
 */
class Token
{
	const DEFAULT_SALT = __CLASS__;
	const DEFAULT_NAMESPACE = 'token';
	const DEFAULT_NAME = 'global';
	const DEFAULT_LENGTH = 128;

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
	 * CUT index.php
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
	 * HTTP REFERER SERVER VAR
	 *
	 * @return string
	 */
	static private function getHttpReferer(): string
	{
		$referer = (string) filter_input(INPUT_SERVER, 'HTTP_REFERER', FILTER_VALIDATE_URL);
		return self::cutIndexFile(self::cutGetParam($referer));
	}

	/**
	 * HTTP REFERER SERVER VAR
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
	 * OPENSSL_RANDOM_PSEUDO_BYTES
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
	 * CREATE TOKEN
	 *
	 * @param string $name [optional]
	 * @param string $page [optional]
	 * @return string CSRF Token
	 */
	public function create(string $name = '', $page = ''): string
	{
		# Auto set referer
		if(!$page) { $page = self::getCurrentPage(); }

		# Auto set name
		if(!$name) { $name = $this->default; }

		# Generate token
		$token = $this->uniqId();

		# Set in session
		$_SESSION[$this->namespace][$name] = [
			'page' => $page,
			'token' => $token,
			'time' => time()
		];

		# Maintain chainability
		return $token;
	}

	/**
	 * CREATE TOKEN
	 *
	 * @param string $token
	 * @param string $name [optional]
	 * @param array $referers [optional]
	 * @param int $length [optional] in seconds / default : 10 min
	 * @return bool
	 */
	public function verify(string $token, $name = '', $referers = [], $length = 600)
	{
		# AUTO SET REFERER
		if(!$referers) { $referers = [self::getHttpReferer()]; }

		# AUTO SET NAME
		if(!$name) { $name = $this->default; }

		# ERROR
		if(!isset($_SESSION[$this->namespace][$name]['page'])
			|| empty($_SESSION[$this->namespace][$name]['token'])
			|| empty($_SESSION[$this->namespace][$name]['time'])) {
			return false;
		}

		# VERIFY
		if($token !== $_SESSION[$this->namespace][$name]['token']) { return false; }
		if(!in_array($_SESSION[$this->namespace][$name]['page'], $referers, true)) { return false; }
		if(time() >= $_SESSION[$this->namespace][$name]['time'] + $length) { return false; }
		return true;
	}

	/**
	 * DELETE TOKEN
	 *
	 * @param string $name [optional]
	 * @return bool
	 */
	public function delete(string $name = ''): bool
	{
		# AUTO SET NAME
		if(!$name) { $name = $this->default; }

		# DELETE
		if(isset($_SESSION[$this->namespace][$name])) {
			unset($_SESSION[$this->namespace][$name]);
			return true;
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
