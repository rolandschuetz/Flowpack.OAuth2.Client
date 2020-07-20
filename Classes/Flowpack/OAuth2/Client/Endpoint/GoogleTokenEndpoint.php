<?php
namespace Flowpack\OAuth2\Client\Endpoint;

/*                                                                        *
 * This script belongs to the TYPO3 Flow package "Flowpack.OAuth2.Client".*
 *                                                                        *
 * It is free software; you can redistribute it and/or modify it under    *
 * the terms of the GNU General Public License, either version 3 of the   *
 * License, or (at your option) any later version.                        *
 *                                                                        *
 * The TYPO3 project - inspiring people to share!                         *
 *                                                                        */

use Flowpack\OAuth2\Client\Exception as OAuth2Exception;
use Neos\Flow\Annotations as Flow;
use Neos\Flow\Http\Request;
use Neos\Flow\Http\Uri;
use Psr\Log\LoggerInterface;

/**
 * @Flow\Scope("singleton")
 */
class GoogleTokenEndpoint extends AbstractHttpTokenEndpoint implements TokenEndpointInterface
{

    /**
     * @Flow\Inject
     * @var LoggerInterface
     */
    protected $systemLogger;

    /**
     *
     * @param string $tokenToInspect
     * @return array
     * @throws OAuth2Exception
     */
    public function requestValidatedTokenInformation($tokenToInspect)
    {
        $requestArguments = array(
            'input_token' => $tokenToInspect['access_token'],
            'id_token' => $tokenToInspect['id_token']
        );

        $request = Request::create(new Uri('https://www.googleapis.com/oauth2/v3/tokeninfo?' . http_build_query($requestArguments)));
        $response = $this->requestEngine->sendRequest($request);
        $responseContent = $response->getContent();
        if ($response->getStatusCode() !== 200) {
            throw new OAuth2Exception(sprintf('The response was not of type 200 but gave code and error %d "%s"', $response->getStatusCode(), $responseContent), 1383758360);
        }

        $responseArray = json_decode($responseContent, true, 16, JSON_BIGINT_AS_STRING);
        $responseArray['aud'] = (string)$responseArray['aud'];
        $responseArray['sub'] = (string)$responseArray['sub'];
        $clientIdentifier = (string)$this->clientIdentifier;

        if ($responseArray['aud'] !== $clientIdentifier) {
            $this->systemLogger->notice('Requesting validated token information from the Google endpoint did not succeed.', array('response' => var_export($responseArray, true), 'clientIdentifier' => $clientIdentifier));
            return false;
        }

        return $responseArray;
    }

    /**
     * @param $shortLivedToken
     * @return string
     */
    public function requestLongLivedToken($shortLivedToken)
    {
        return $this->requestAccessToken('refresh_token', array('refresh_token' => $shortLivedToken));
    }
}
