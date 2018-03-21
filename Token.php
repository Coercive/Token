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
 * @copyright   2016 - 2018 Anthony Moral
 * @license 	http://www.gnu.org/copyleft/lesser.html GNU Lesser General Public License
 */
class Token {

	const DEFAULT_SALT = 'Coercive\Security\Token';
	const DEFAULT_SESSION = 'csrf_token';
	const DEFAULT_NAME = 'global';

	/** @var DateTime */
	private $_oDate;

	/** @var string */
	private $_sUniqSalt;

	/** @var string */
	private $_sSessionName;

	/** @var string */
	private $_sDefaultGlobalName;

	/**
	 * EXCEPTION
	 *
	 * @param string $sMessage
	 * @param int $sLine
	 * @param string $sMethod
	 * @throws Exception
	 */
	static protected function _exception($sMessage, $sLine = __LINE__, $sMethod = __METHOD__) {
		throw new Exception("$sMessage \nMethod :  $sMethod \nLine : $sLine");
	}

	/**
	 * CUT index.php
	 *
	 * @param string $sRequest
	 * @return string
	 */
	static private function _cutIndexFile($sRequest) {
		$iIndexPos = strpos($sRequest, 'index.php');
		if($iIndexPos !== false) {
			$sRequest = substr($sRequest, 0, $iIndexPos);
		}
		return $sRequest;
	}

	/**
	 * CUT index.php
	 *
	 * @param string $sRequest
	 * @return string
	 */
	static private function _cutGetParam($sRequest) {
		$iGetPos = strpos($sRequest, '?');
		if($iGetPos !== false) {
			$sRequest = substr($sRequest, 0, $iGetPos);
		}
		return $sRequest;
	}

	/**
	 * HTTP REFERER SERVER VAR
	 *
	 * @return string
	 */
	static private function _getHttpReferer() {
		$sReferer = (string) filter_input(INPUT_SERVER, 'HTTP_REFERER', FILTER_VALIDATE_URL);
		return self::_cutIndexFile(self::_cutGetParam($sReferer));
	}

	/**
	 * HTTP REFERER SERVER VAR
	 *
	 * @return string
	 */
	static private function _getCurrentPage() {
		$iPort = (int) filter_input(INPUT_SERVER, 'SERVER_PORT', FILTER_VALIDATE_INT);
		$sProtocol = !empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off' || $iPort === 443 ? 'https' : 'http';
		$sHost = (string) filter_input(INPUT_SERVER, 'HTTP_HOST', FILTER_SANITIZE_FULL_SPECIAL_CHARS);
		$sRequest = (string) filter_input(INPUT_SERVER, 'SCRIPT_NAME', FILTER_SANITIZE_FULL_SPECIAL_CHARS);
		$sRequest = self::_cutIndexFile($sRequest);
		return "$sProtocol://$sHost$sRequest";
	}

	/**
	 * Token constructor.
	 *
	 * @param string $sUniqSalt [optional]
	 * @param string $sSessionName [optional]
	 * @param string $sDefaultGlobalName [optional]
	 * @throws Exception
	 */
	public function __construct($sUniqSalt = '', $sSessionName = '', $sDefaultGlobalName = '') {

		# Start
		if(session_id() === '') { self::_exception('Coercive Token needs a session is started before being launched.', __LINE__, __METHOD__); }

		# SET Code
		$this->_sUniqSalt = $sUniqSalt ? (string)$sUniqSalt : self::DEFAULT_SALT;
		$this->_sSessionName = $sSessionName ? (string)$sDefaultGlobalName : self::DEFAULT_SESSION;
		$this->_sDefaultGlobalName = $sDefaultGlobalName ? (string)$sSessionName : self::DEFAULT_NAME;

		# Actual DateTime
		$this->_oDate = new DateTime;
	}

	/**
	 * CREATE TOKEN
	 *
	 * @param string $sName [optional]
	 * @param string $sCurrentPage [optional]
	 * @return string CSRF Token
	 */
	public function create($sName = '', $sCurrentPage = '') {

		# AUTO SET REFERER
		if(!$sCurrentPage) { $sCurrentPage = self::_getCurrentPage(); }

		# AUTO SET NAME
		if(!$sName) { $sName = $this->_sDefaultGlobalName; }

		# TOKEN
		$sToken = hash('sha512', session_id() . $this->_sUniqSalt . uniqid(time(), true), false);

		# SET
		$_SESSION[$this->_sSessionName][$sName] = [
			'page' => $sCurrentPage,
			'token' => $sToken,
			'time' => $this->_oDate->getTimestamp()
		];

		return $sToken;
	}

	/**
	 * CREATE TOKEN
	 *
	 * @param string $sToken
	 * @param string $sName [optional]
	 * @param mixed $mReferer [optional]
	 * @param int $iValidityTime [optional] in seconds / default : 10 min
	 * @return bool
	 */
	public function verify($sToken, $sName = '', $mReferer = [], $iValidityTime = 600) {

		# AUTO SET REFERER
		if(!$mReferer) { $mReferer = self::_getHttpReferer(); }
		if(is_string($mReferer)) { $mReferer = (array) $mReferer; }

		# AUTO SET NAME
		if(!$sName) { $sName = $this->_sDefaultGlobalName; }

		# ERROR
		if(    empty($_SESSION[$this->_sSessionName])
			|| empty($_SESSION[$this->_sSessionName][$sName])
			|| !isset($_SESSION[$this->_sSessionName][$sName]['page'])
			|| empty($_SESSION[$this->_sSessionName][$sName]['token'])
			|| empty($_SESSION[$this->_sSessionName][$sName]['time'])) {
			return false;
		}

		# VERIFY
		if($sToken !== $_SESSION[$this->_sSessionName][$sName]['token']) { return false; }
		if(!in_array($_SESSION[$this->_sSessionName][$sName]['page'], $mReferer, true)) { return false; }
		if($this->_oDate->getTimestamp() >= $_SESSION[$this->_sSessionName][$sName]['time'] + $iValidityTime) { return false; }
		return true;
	}

	/**
	 * DELETE TOKEN
	 *
	 * @param string $sName [optional]
	 * @return bool
	 */
	public function delete($sName = '') {

		# AUTO SET NAME
		if(!$sName) { $sName = $this->_sDefaultGlobalName; }

		# DELETE
		if(isset($_SESSION[$this->_sSessionName][$sName])) {
			unset($_SESSION[$this->_sSessionName][$sName]);
			return true;
		}

		return false;
	}

}
