<?php
namespace Flowpack\OAuth2\Client\Eel;

use Neos\Eel\ProtectedContextAwareInterface;
use Neos\ContentRepository\Domain\Model\NodeInterface;
use Neos\Flow\Annotations as Flow;
use Flowpack\OAuth2\Client\UriBuilder;

class AuthorizationHelper implements ProtectedContextAwareInterface {
    /**
     * @Flow\Inject
     * @var UriBuilder
     */
    protected $oauthUriBuilder;

	/**
	 * @param string $providerName
	 * @return string
	 */
	public function getAuthorizationUri(string $providerName) {
		return $this->oauthUriBuilder->getAuthorizationUri($providerName);
	}

	/**
	 * All methods are considered safe
	 *
	 * @param string $methodName
	 * @return boolean
	 */
	public function allowsCallOfMethod($methodName) {
		return true;
	}
}