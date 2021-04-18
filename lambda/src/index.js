import { authPolicyFromEvent, HttpVerb } from './authPolicy';

exports.handler = async function(event) {
    console.log(HttpVerb.GET);
}
