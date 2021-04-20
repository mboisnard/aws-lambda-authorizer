import jwt from 'jsonwebtoken';

import { authPolicyFromEvent, Payload } from './authPolicy';
import get  from './httpRequest';

exports.handler = async event => {

    try {
        const jwtToken = await getRawTokenFrom(event);
        const decodedJwtToken = await decodeToken(jwtToken);
        const discoveryUrls = await getOpenIdConnectDiscoveryUrlsFrom(decodedJwtToken.payload.iss);
        const availablePublicKeys = await getAvailablePublicKeysFrom(discoveryUrls.jwks_uri);
        const publicKeyForToken = await findPublicKeyForCurrentToken(availablePublicKeys, decodedJwtToken.header.kid);
        const verifiedToken = await verifyToken(jwtToken, publicKeyForToken);

        const principalId = verifiedToken.sub;

        return authPolicyFromEvent(event, principalId)
            .allowAllMethods()
            .build();
    } catch (error) {
        console.error(error.name, ' : ', error.message);
        throw new Error('Unauthorized');
    }
};

async function getRawTokenFrom(event) {

    const token = event.version === Payload.VERSION_1
        ? event.authorizationToken
        : event.authorization;

    if (!token)
        return Promise.reject({ name: 'Get Token Error', message: `Unable to get authorization token from event payload. Event : ${event}` });

    return token.replace('Bearer ', '');
}

async function decodeToken(jwtToken) {

    const decodedJwtToken = jwt.decode(jwtToken, { complete: true });

    if (!decodedJwtToken || !decodedJwtToken.payload)
        return Promise.reject({ name: 'JWT Decode Error', message: `JWT decode failed, invalid token : ${jwtToken}` });

    return decodedJwtToken;
}

async function getOpenIdConnectDiscoveryUrlsFrom(issuer) {

    const wellKnownOpenIdUrl = `${issuer}/.well-known/openid-configuration`;

    const discoveryUrls = await get(wellKnownOpenIdUrl, { json: true }).body;

    if (!discoveryUrls || !discoveryUrls.jwks_uri)
        return Promise.reject({ name: 'Discovery Urls Error', message: `Invalid OpenId Connect Urls. DiscoveryUrls : ${discoveryUrls}` });

    return discoveryUrls;
}

async function getAvailablePublicKeysFrom(keyStoreUrl) {

    const res = await get(keyStoreUrl, { json: true });
    const { keys } = res.body;

    if (!keys || keys.length === 0)
        return Promise.reject({ name: 'Public Keys Error', message: `No available public keys from keystore : ${keyStoreUrl}` });

    return keys;
}

async function findPublicKeyForCurrentToken(publicKeys, tokenKid) {

    const toPemFormat = certificate => `-----BEGIN CERTIFICATE-----\n${certificate}'\n-----END CERTIFICATE-----`;

    // Build object with kid as property name
    const foundKey = keys.reduce((acc, key) => (
        {
            ...acc,
            [key.x5t]: toPemFormat(key.x5c)
        }
    ), {})[tokenKid];

    if (!foundKey)
        return Promise.reject({ name: 'Public Key Error', message: `Token Kid (${tokenKid}) not found in public keys list` });

    return foundKey;
}

async function verifyToken(token, publicKey) {
    return jwt.verify(token, publicKey);
}
