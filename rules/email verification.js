/**
 * @title Force Email Verification
 * @overview Forces Email Verification and Sends Verification Email To Unverified User Upon Login
 * @gallery true
 * @category force email verification
 *
 * This rule will send a verification email to a user upon login if they are unverified
 *
 */
async function forceEmailVerification(user, context, callback) {
    const forcedEmailTokenValid = global.M2MForceEmailTokenKey;
    const forcedEmailRuleClientId = configuration.send_verification_email_rule_client_id;
    const forcedEmailRuleClientSecret = configuration.send_verification_email_rule_client_secret;
    const auth0MgmtClientAudience = 'https://week-3.auth0.com/api/v2/';
    const auth0Tenant = 'https://' + context.tenant + '.auth0.com/';
    const axios = require('axios');
    const request = require("request");

    const getM2MAuth0Token  = async (clientId, clientSecret, clientAudience) => {
        let postBody = {
            client_id: clientId,
            client_secret: clientSecret,
            audience: clientAudience,
            grant_type: 'client_credentials'
        };
    
        let options = {
            method: 'POST',
            url: 'https://week-3.auth0.com/oauth/token',
            headers: {'content-type': 'application/json'},
            data: postBody
        };
        let token;
        await axios(options)
            .then(function (response){
                token = {
                    accessToken: response.data.access_token,
                    // Forces reissue token 60 seconds before the token actually expires
                    expirationDate: Date.now() + (response.data.expires_in - 60) * 1000
                };
            });
        return token;
    };


    let emailLastSentLimitMet = (userToCheck => {
        //limit is considered met if these checks fail
        console.log("user to check ", userToCheck);
        if (!userToCheck || !userToCheck.user_metadata || !userToCheck.user_metadata.last_sent_verification_email_date) {
            return true;
        }

        // 5 minutes
        let timeLimitMs = 5 * 60 * 1000;
        let last_sent_verification_email_date = new Date(userToCheck.user_metadata.last_sent_verification_email_date);
        let lastSentTimeMs = last_sent_verification_email_date.getTime();
        let currentDate = new Date();
        let currentTimeMs = currentDate.getTime();

        return currentTimeMs - lastSentTimeMs > timeLimitMs;
    });

    // CHANGING THIS TEXT WILL BREAK LOGIN VERIFY EMAIL COMPONENT IN CUSTOMER-UI
    let mustVerifyEmailError = new UnauthorizedError('Please verify your email before logging in.');
    //enforce this only for a clientID
   //let sendVerificationEmailRuleClientId = configuration.send_verification_email_rule_client_id;

    //if (context.clientID === sendVerificationEmailRuleClientId) {
        //only run this rule for an auth0 user that is unverified
    if (user.email_verified ) {
        return callback(null, user, context);
    } else if (!emailLastSentLimitMet(user)) {
      console.log("not time to send a new one yet");
        return callback(mustVerifyEmailError);
    } else {
        
        if(!forcedEmailTokenValid) {
            try{
                global.M2MForceEmailTokenKey = await getM2MAuth0Token(forcedEmailRuleClientId, forcedEmailRuleClientSecret, auth0MgmtClientAudience);
            }
            catch(error) {
                return callback(error);
            }
        }
        let emailVerificationPath = auth0Tenant + 'api/v2/jobs/verification-email';
        let emailVerificationBody = {
            user_id: user.user_id,
        };
        let emailVerificationRequest = {
            method: 'POST',
            url: emailVerificationPath,
            headers: { 'content-type': 'application/json', authorization: 'Bearer ' + global.M2MForceEmailTokenKey.accessToken },
            body: emailVerificationBody,
            json: true
        };

        request(emailVerificationRequest, async (error, response, job) => {
            try {
                user.user_metadata = user.user_metadata || {};
                user.user_metadata.last_sent_verification_email_date = new Date();
                // persist last_sent_verification_email_date
                await auth0.users.updateUserMetadata(user.user_id, user.user_metadata);
                callback(mustVerifyEmailError);
            } catch (err) {
                callback(err);
            }
        });
    }
    //} else {
    // callback(null, user, context);
    // }
}