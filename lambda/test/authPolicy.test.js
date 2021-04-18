const assert = require('assert');
const authPolicyBuilder = require('../src/authPolicy');

const payloadV1 = require('./payloadV1.json');
const payloadV2 = require('./payloadV2.json');

const principalId = '12345';

describe('authPolicy', () => {

    describe('authPolicyFromEvent', () => {
        it('should throw error when event payload has wrong format', () => {
            const event = {};
            assert.throws(() => authPolicyBuilder.authPolicyFromEvent(event, principalId), Error);
        });

        it('should throw error when arn has wrong format inside event payload', () => {
            const event = {
                version: '1.0',
                methodArn: 'arn:aws:execute-api:us-east-1:abcdef123/test/GET/request'
            };

            assert.throws(() => authPolicyBuilder.authPolicyFromEvent(event, principalId), Error);
        });

        it('should create policy with event methodArn infos from V1 payload', () => {
            const expectedAuthPolicy = {
                principalId: "12345",
                context: {},
                policyDocument: {
                    Statement: [
                        {
                            Action: "execute-api:Invoke",
                            Effect: "Allow",
                            Resource: [
                                "arn:aws:execute-api:us-east-1:123456789012:abcdef123/test/*/*"
                            ]
                        }
                    ],
                    Version: "2012-10-17"
                }
            };
            const authPolicy = authPolicyBuilder.authPolicyFromEvent(payloadV1, principalId)
                .allowAllMethods()
                .build();

            assert.deepStrictEqual(authPolicy, expectedAuthPolicy);
        });
    });
});
