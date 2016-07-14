<?php
namespace Coercive\Security\Token;

use \DateTime;
use \DateInterval;
use \Exception;

/**
 * Token
 * PHP Version 	5
 *
 * @version		1
 * @package 	Coercive\Security\Token
 * @link		@link https://github.com/Coercive/Token
 *
 * @author  	Anthony Moral <contact@coercive.fr>
 * @copyright   2016 - 2017 Anthony Moral
 * @license 	http://www.gnu.org/copyleft/lesser.html GNU Lesser General Public License
 */
class Token {

	/** @var string (128) */
	private $sToken;

	/** @var string (128) */
	private $sPreviousToken;

	/** @var DateTime */
	private $oDate;

	/** @var string */
	private $sUniqSalt;

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
	 * Token constructor.
	 *
	 * @param string $sUniqSalt
	 * @throws Exception
	 */
	public function __construct($sUniqSalt = __NAMESPACE__) {

		# Start
		if(session_id() === '') { self::_exception('Coercive Token needs a session is started before being launched.', __LINE__, __METHOD__); }

		# SET Code
		$this->sUniqSalt = (string) $sUniqSalt;

		# First Init
		$this->init();
	}

	/**
	 * Process Token
	 *
	 * @return Token
	 */
	public function init() {

		# Actual DateTime
		$this->oDate = new DateTime;

		# REAL Token
		$this->sToken = hash('sha512', session_id() . $this->sUniqSalt . $this->oDate->format('Y-m-d H\h'), false);

		# AS Valid (1H d'interval)
		$this->oDate->sub(new DateInterval('PT1H'));
		$this->sPreviousToken = hash('sha512', session_id() . $this->sUniqSalt . $this->oDate->format('Y-m-d H\h'), false);

		return $this;
	}

	/**
	 * GETTER Token
	 *
	 * @return string
	 */
	public function get() {
		return $this->sToken;
	}

	/**
	 * MATCH : Token validity test
	 *
	 * Correspondence between the token present or the previous hour
	 *
	 * @param string $sInputToken
	 * @return bool
	 */
	public function match($sInputToken) {
		return $sInputToken === $this->sToken || $sInputToken === $this->sPreviousToken;
	}

}