const assert = require('assert');
const authPolicyBuilder = require('../src/authPolicy');

describe('authPolicy', () => {

    describe('authPolicyFromEvent', () => {
        it('should throw error when event has wrong format', () => {
            assert.throws(() => authPolicyBuilder.authPolicyFromEvent({}, '1234'), Error);
        });
    });
});
