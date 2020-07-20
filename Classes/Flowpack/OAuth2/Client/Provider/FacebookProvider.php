<?php
namespace Flowpack\OAuth2\Client\Provider;

/*                                                                        *
 * This script belongs to the TYPO3 Flow package "Flowpack.OAuth2.Client".*
 *                                                                        *
 * It is free software; you can redistribute it and/or modify it under    *
 * the terms of the GNU General Public License, either version 3 of the   *
 * License, or (at your option) any later version.                        *
 *                                                                        *
 * The TYPO3 project - inspiring people to share!                         *
 *                                                                        */

use Flowpack\OAuth2\Client\Token\AbstractClientToken;
use Neos\Flow\Annotations as Flow;
use Neos\Flow\Security\Account;
use Neos\Flow\Security\Authentication\TokenInterface;
use Neos\Flow\Security\Exception\UnsupportedAuthenticationTokenException;
use Neos\Flow\Security\Policy\PolicyService;
use Psr\Log\LoggerInterface;

/**
 */
class FacebookProvider extends AbstractClientProvider
{

    /**
     * @Flow\Inject
     * @var LoggerInterface
     */
    protected $systemLogger;

    /**
     * @Flow\Inject
     * @var PolicyService
     */
    protected $policyService;

    /**
     * @Flow\Inject
     * @var \Neos\Flow\Security\Context
     */
    protected $securityContext;

    /**
     * @Flow\Inject
     * @var \Flowpack\OAuth2\Client\Endpoint\FacebookTokenEndpoint
     */
    protected $facebookTokenEndpoint;

    /**
     * @Flow\Inject
     * @var \Flowpack\OAuth2\Client\Flow\FacebookFlow
     */
    protected $facebookFlow;

    /**
     * @Flow\Inject
     * @var \Neos\Flow\Persistence\PersistenceManagerInterface
     */
    protected $persistenceManager;

    /**
     * Tries to authenticate the given token. Sets isAuthenticated to TRUE if authentication succeeded.
     *
     * @param TokenInterface $authenticationToken The token to be authenticated
     * @throws \Neos\Flow\Security\Exception\UnsupportedAuthenticationTokenException
     * @return void
     */
    public function authenticate(TokenInterface $authenticationToken)
    {
        if (!($authenticationToken instanceof AbstractClientToken)) {
            throw new UnsupportedAuthenticationTokenException('This provider cannot authenticate the given token.', 1383754993);
        }

        $credentials = $authenticationToken->getCredentials();

        // Inspect the received access token as documented in https://developers.facebook.com/docs/facebook-login/login-flow-for-web-no-jssdk/
        $tokenInformation = $this->facebookTokenEndpoint->requestValidatedTokenInformation($credentials);

        if ($tokenInformation === false) {
            $authenticationToken->setAuthenticationStatus(TokenInterface::WRONG_CREDENTIALS);
            return;
        }

        // Check if the permitted scopes suffice:
        $necessaryScopes = $this->options['scopes'];
        $scopesHavingPermissionFor = $tokenInformation['scopes'];
        $requiredButNotPermittedScopes = array_diff($necessaryScopes, $scopesHavingPermissionFor);
        if (count($requiredButNotPermittedScopes) > 0) {
            $authenticationToken->setAuthenticationStatus(TokenInterface::WRONG_CREDENTIALS);
            $this->systemLogger->notice('The permitted scopes do not satisfy the required once.', array('necessaryScopes' => $necessaryScopes, 'allowedScopes' => $scopesHavingPermissionFor));
            return;
        }

        // From here, we surely know the user is considered authenticated against the remote service,
        // yet to check if there is an immanent account present.
        $authenticationToken->setAuthenticationStatus(TokenInterface::AUTHENTICATION_SUCCESSFUL);
        /** @var $account \Neos\Flow\Security\Account */
        $account = null;
        $isNewCreatedAccount = false;
        $providerName = $this->name;

        if ($account === null) {
            $account = new Account();
            $isNewCreatedAccount = true;
            $account->setAccountIdentifier($tokenInformation['user_id']);
            $account->setAuthenticationProviderName($providerName);

            // adding in Settings.yaml specified roles to the account
            // so the account can be authenticate against a role in the frontend for example
            $roles = array();
            foreach ($this->options['authenticateRoles'] as $roleIdentifier) {
                $roles[] = $this->policyService->getRole($roleIdentifier);
            }
            $account->setRoles($roles);
        }
        $authenticationToken->setAccount($account);

        // request long-live token and attach that to the account
        $longLivedToken = $this->facebookTokenEndpoint->requestLongLivedToken($credentials['access_token']);
        $account->setCredentialsSource($longLivedToken['access_token']);
        $account->authenticationAttempted(TokenInterface::AUTHENTICATION_SUCCESSFUL);

        // Only if defined a Party for the account is created
        if ($this->options['partyCreation'] && $isNewCreatedAccount) {
            $this->facebookFlow->createPartyAndAttachToAccountFor($authenticationToken);
        }
    }

    /**
     * Returns the class names of the tokens this provider is responsible for.
     *
     * @return array The class name of the token this provider is responsible for
     */
    public function getTokenClassNames()
    {
        return array('Flowpack\OAuth2\Client\Token\FacebookToken');
    }
}
