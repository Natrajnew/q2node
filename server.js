const express = require('express');
const axios = require('axios');

// Only used if you ever use a local .env; on Render, env vars come from platform
require('dotenv').config();

const app = express();

const PORT = process.env.PORT || 3000;

// Parse JSON body; if malformed, Express may return 400 before hitting the route
app.use(express.json({ type: ['application/json', 'text/plain'] }));

// --- Q2 Configuration ---
const Q2Config = {
  Q2ClientId: process.env.Q2_CLIENT_ID || '',
  Q2ClientSecret: process.env.Q2_CLIENT_SECRET || '',
  Q2GrantType: process.env.Q2_GRANT_TYPE || 'client_credentials',
  Q2Scope: process.env.Q2_SCOPE || 'CaliperAPI:UsageToken:bankofhope CaliperAPI:Enrollment CaliperAPI:Authenticate CaliperAPI:GetGroups Environment:Staging:NonProd_3424_01_Test_01__',
  Q2TokenURL: process.env.Q2_TOKEN_URL || 'https://q2developer.com/oauth2/token',
  Q2URL: process.env.Q2_URL || 'https://stage.q2api.com/v2/Authenticate'
};

// --- Helpers ---

// Get Q2 access token using client_credentials
async function getQ2AccessToken() {
  try {
    const resp = await axios.post(
      Q2Config.Q2TokenURL,
      new URLSearchParams({
        grant_type: Q2Config.Q2GrantType,
        scope: Q2Config.Q2Scope
      }),
      {
        auth: {
          username: Q2Config.Q2ClientId,
          password: Q2Config.Q2ClientSecret
        },
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded'
        }
      }
    );

    return resp.data.access_token;
  } catch (error) {
    console.error('Error getting Q2 access token:', error.response?.data || error.message);
    throw new Error('Failed to obtain Q2 access token');
  }
}

// Call Q2 Authenticate API
async function authenticateQ2(loginName, password, accessToken) {
  try {
    const resp = await axios.post(
      Q2Config.Q2URL,
      null,
      {
        headers: {
          Authorization: `Bearer ${accessToken}`,
          'Content-Type': 'application/json',
          LoginName: loginName,
          Password: password
        }
      }
    );

    return resp.data;
  } catch (error) {
    const status = error.response?.status;
    const data = error.response?.data;

    if (status === 401 || status === 403) {
      return {
        success: false,
        errors: data && Array.isArray(data.errors) ? data.errors : []
      };
    }
    throw new Error(`Q2 Authenticate failed with status ${status}`);
  }
}

// --- Controllers ---

// Okta → Node → Q2 round‑trip endpoint (matches your Okta body: data.context.credential)
app.post('/okta-login', async (req, res) => {
  const payload = req.body;

  console.log('Received Okta hook payload:', payload);

  // Default: treat as UNVERIFIED, then try to validate
  let result = {
    commands: [
      {
        type: 'com.okta.action.update',
        value: {
          credential: 'UNVERIFIED'
        }
      }
    ],
    error: {
      errorSummary: 'Invalid username or password.',
      errorCauses: [
        {
          errorSummary: 'Unable to extract valid credentials from the request.',
          reason: 'MISSING_CREDENTIAL',
          locationType: 'body',
          location: 'data.context.credential'
        }
      ]
    }
  };

  // Parse user + password from the payload
  const username = payload?.data?.context?.credential?.username;
  const password = payload?.data?.context?.credential?.password;

  if (!username || !password) {
    return res.json(result);
  }

  console.log(`Validating user: ${username}`);

  let accessToken;
  try {
    accessToken = await getQ2AccessToken();
  } catch (err) {
    result.commands[0].value.credential = 'UNVERIFIED';
    result.error.errorSummary = 'Authentication service unavailable.';
    result.error.errorCauses[0].errorSummary = err.message;
    result.error.errorCauses[0].reason = 'INTERNAL_ERROR';
    return res.json(result);
  }

  try {
    const q2Result = await authenticateQ2(username, password, accessToken);

    // Q2 success response:
    //   success: true
    //   status: 200
    //   errors: []
    //   data: { ... }
    const isQ2Success =
      q2Result &&
      q2Result.success === true &&
      q2Result.status === 200 &&
      Array.isArray(q2Result.errors) &&
      q2Result.errors.length === 0 &&
      q2Result.data &&
      q2Result.data.UserLogonID;

    if (isQ2Success) {
      // Success: tell Okta credentials are VERIFIED
      return res.json({
        commands: [
          {
            type: 'com.okta.action.update',
            value: {
              credential: 'VERIFIED'
            }
          }
        ]
      });
    } else {
      const isPasswordError =
        q2Result &&
        q2Result.success === false &&
        Array.isArray(q2Result.errors) &&
        q2Result.errors.some(err => err.code === 50002);

      if (isPasswordError) {
        // User exists, password wrong
        result.commands[0].value.credential = 'UNVERIFIED';
        result.error.errorSummary = 'Invalid username or password.';
        result.error.errorCauses[0].errorSummary = 'Password is not valid for the given user.';
        result.error.errorCauses[0].reason = 'INVALID_PASSWORD';
      } else {
        // Generic login failure (user not found, etc.)
        result.commands[0].value.credential = 'UNVERIFIED';
        result.error.errorSummary = 'Invalid username or password.';
        result.error.errorCauses[0].errorSummary =
          'Either the username does not exist or the credentials are invalid.';
        result.error.errorCauses[0].reason = 'INVALID_USERNAME';
      }

      return res.json(result);
    }
  } catch (err) {
    console.error('Q2 authentication error:', err.message);
    result.commands[0].value.credential = 'UNVERIFIED';
    result.error.errorSummary = 'Authentication failed.';
    result.error.errorCauses[0].errorSummary = err.message;
    result.error.errorCauses[0].reason = 'Q2_AUTH_FAILED';
    return res.json(result);
  }
});

// Health check
app.get('/health', (req, res) => {
  res.json({ status: 'ok', service: 'Q2 ↔ Okta round‑trip' });
});

app.listen(PORT, () => {
  console.log(`Q2 ↔ Okta round‑trip service running on port ${PORT}`);
  console.log('Endpoint: POST /okta-login (expects Okta body with data.context.credential)');
});
