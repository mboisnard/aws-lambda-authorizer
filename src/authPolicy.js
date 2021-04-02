const Payload = {
    VERSION_1: '1.0',
    VERSION_2: '2.0'
};

const ALL_RESOURCES = '*';

const HttpVerb = {
    GET: 'GET',
    POST: 'POST',
    PUT: 'PUT',
    PATCH: 'PATCH',
    HEAD: 'HEAD',
    DELETE: 'DELETE',
    OPTIONS: 'OPTIONS',
    ALL: ALL_RESOURCES
};

const Effect = {
    ALLOW: 'Allow',
    DENY: 'Deny'
};

const Action = {
    EXECUTE_API: 'execute-api:Invoke'
};

// Arn format: 'arn:aws:execute-api:eu-west-1:123456789102:vjpmhhtdi6/dev/GET/test'
const authPolicyFromEvent = function(event, principalId) {

    const arn = event.version === Payload.VERSION_1
        ? event.methodArn
        : event.routeArn;

    if (!arn) {
        throw new Error('Invalid arn. Check your event format.');
    }

    const parts = arn.split(':');

    const regionPart = parts[3];
    const awsAccountIdPart = parts[4];
    const apiGatewayArnParts = parts[5].split('/');
    const apiGatewayRestApiIdPart = apiGatewayArnParts[0];
    const apiGatewayStagePart = apiGatewayArnParts[1];

    return authPolicy(principalId, awsAccountIdPart, {
        region: regionPart,
        restApiId: apiGatewayRestApiIdPart,
        stage: apiGatewayStagePart
    });
};

const authPolicy = function(_principalId, _awsAccountId, apiOptions) {

    const policyVersion = '2012-10-17';
    const pathRegex = /^[/.a-zA-Z0-9-*]+$/;

    const principalId = _principalId;
    const awsAccountId = _awsAccountId;
    const restApiId = apiOptions.restApiId || ALL_RESOURCES;
    const region = apiOptions.region || ALL_RESOURCES;
    const stage = apiOptions.stage || ALL_RESOURCES;

    const allowedMethods = [];
    const deniedMethods = [];

    const customStatements = [];

    let context = {};

    const formatResource = resource => {

        if (resource.startsWith('/')) {
            return resource.substring(1, resource.length);
        }

        return resource;
    };

    const addMethod = (effect, verb, resource, conditions) => {

        if (!HttpVerb[verb]) {
            throw new Error(`Invalid HTTP verb ${verb}. Allowed verbs in HttpVerb enum.`);
        }

        const decodedResource = decodeURI(resource);
        if (!pathRegex.test(decodedResource)) {
            throw new Error(`Invalid resource path: ${decodedResource}. Path should match ${pathRegex}.`);
        }

        const resourceArn = `arn:aws:execute-api:${region}:${awsAccountId}:${restApiId}/${stage}/${verb}/${formatResource(resource)}`;

        const method = {
            resourceArn,
            conditions,

            hasConditions: () => conditions && conditions.length !== 0
        };

        if (effect === Effect.ALLOW) {
            allowedMethods.push(method);
        } else if (effect === Effect.DENY) {
            deniedMethods.push(method);
        }
    };

    const createEmptyStatement = effect => {
        return {
            Action: Action.EXECUTE_API,
            Effect: effect,
            Resource: []
        };
    };

    const createConditionalStatement = (effect, method) => {
        return {
            Action: Action.EXECUTE_API,
            Effect: effect,
            Resource: [
                method.resourceArn
            ],
            Condition: method.conditions
        };
    };

    const createStatementsForEffect = (effect, methods) => {
        const statements = [];

        if (methods.length === 0) {
            return statements;
        }

        const statement = createEmptyStatement(effect);

        methods.forEach(method => {
            if (method.hasConditions()) {
                statements.push(createConditionalStatement(effect, method));
            } else {
                statement.Resource.push(method.resourceArn);
            }
        });

        if (statement.Resource.length !== 0) {
            statements.push(statement);
        }

        return statements;
    };

    return {

        allowMethod: function(verb, resource) {
            addMethod(Effect.ALLOW, verb, resource, null);
            return this;
        },

        allowMethodWithConditions: function(verb, resource, conditions) {
            addMethod(Effect.ALLOW, verb, resource, conditions);
            return this;
        },

        allowAllMethods: function() {
            addMethod(Effect.ALLOW, HttpVerb.ALL, ALL_RESOURCES, null);
            return this;
        },

        denyMethod: function(verb, resource) {
            addMethod(Effect.DENY, verb, resource, null);
            return this;
        },

        denyMethodWithConditions: function(verb, resource, conditions) {
            addMethod(Effect.DENY, verb, resource, conditions);
            return this;
        },

        denyAllMethods: function() {
            addMethod(Effect.DENY, HttpVerb.ALL, ALL_RESOURCES, null);
            return this;
        },

        addStatement: function(statement) {
            customStatements.push(statement);
            return this;
        },

        withContext: function(ctx) {
            context = ctx;
            return this;
        },

        build: function() {
            if (allowedMethods.length === 0 && deniedMethods.length === 0 && customStatements.length === 0) {
                throw new Error('No statement defined for the policy');
            }

            return {
                principalId: principalId,
                context: context,
                policyDocument: {
                    Version: policyVersion,
                    Statement: [
                        ...createStatementsForEffect(Effect.ALLOW, allowedMethods),
                        ...createStatementsForEffect(Effect.DENY, deniedMethods),
                        ...customStatements
                    ]
                }
            };
        }
    };
}

module.exports = {
    authPolicyFromEvent,
    authPolicy,
    HttpVerb,
    Effect
}
