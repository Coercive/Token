<?php
namespace Coercive\Security\Token;

use Exception;

/**
 * Token
 *
 * @package 	Coercive\Security\Token
 * @link		https://github.com/Coercive/Token
 *
 * @author  	Anthony Moral <contact@coercive.fr>
 * @copyright   2016 - 2018 Anthony Moral
 * @license 	http://www.gnu.org/copyleft/lesser.html GNU Lesser General Public License
 */
class Token {

	const DEFAULT_SALT = __CLASS__;
	const DEFAULT_NAMESPACE = 'token';
	const DEFAULT_NAME = 'global';

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
	 * Token constructor.
	 *
	 * @param string $salt [optional]
	 * @param string $namespace [optional]
	 * @param string $default [optional]
	 * @throws Exception
	 */
	public function __construct(string $salt = '', string $namespace = '', $default = '')
	{
		# Start
		if(session_status() !== PHP_SESSION_ACTIVE || !session_id()) {
			throw new Exception('Coercive Token needs a session is started before being launched.');
		}

		# SET Code
		$this->salt = $salt ?: self::DEFAULT_SALT;
		$this->namespace = $namespace ?: self::DEFAULT_NAMESPACE;
		$this->default = $default ?: self::DEFAULT_NAME;
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
		# AUTO SET REFERER
		if(!$page) { $page = self::getCurrentPage(); }

		# AUTO SET NAME
		if(!$name) { $name = $this->default; }

		# TOKEN
		$token = hash('sha512', session_id() . $this->salt . uniqid(rand(), true), false);

		# SET
		$_SESSION[$this->namespace][$name] = [
			'page' => $page,
			'token' => $token,
			'time' => time()
		];

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
}
