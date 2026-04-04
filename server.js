const express = require('express');
const axios = require('axios');

const app = express();

const PORT = process.env.PORT || 3000;

app.use(express.json());

// --- Config from Q2 (use environment or hard‑code) ---

const Q2Config = {
  Q2ClientId: process.env.Q2_CLIENT_ID || 'eaf9d7bc-2fc4-4585-9bea-4780233aa1a5',
  Q2ClientSecret: process.env.Q2_CLIENT_SECRET || 'de6b0ee80ca29062ec89d843f6308c97',
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
      null, // body is empty as per Q2 docs; auth in headers
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

    // You may need to adjust this based on Q2’s actual error shape
    if (status === 401 || status === 403) {
      return { success: false, error: data };
    }
    throw new Error(`Q2 Authenticate failed with status ${status}`);
  }
}

// --- Controllers ---

// Okta → Node → Q2 round‑trip endpoint
app.post('/okta-login', async (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.status(400).json({
      error: 'Missing username or password'
    });
  }

  console.log(`Validating user: ${username}`);

  let accessToken;
  try {
    accessToken = await getQ2AccessToken();
  } catch (err) {
    return res.status(500).json({
      commands: [
        {
          type: 'com.okta.action.update',
          value: {
            credential: 'UNVERIFIED'
          }
        }
      ],
      error: {
        errorSummary: 'Authentication service unavailable.',
        errorCauses: [
          {
            errorSummary: err.message,
            reason: 'INTERNAL_ERROR',
            locationType: 'body',
            location: 'data.credential'
          }
        ]
      }
    });
  }

  try {
    const q2Result = await authenticateQ2(username, password, accessToken);

    // Assume Q2 returns something like { success: true } on success
    // Adjust this condition based on Q2’s actual response
    if (q2Result && q2Result.success !== false) {
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
      // Fail: UNVERIFIED + error
      return res.json({
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
              errorSummary: 'Only specific usernames are allowed to log in, or the password is incorrect.',
              reason: 'INVALID_USERNAME',
              locationType: 'body',
              location: 'data.credential'
            }
          ]
        }
      });
    }
  } catch (err) {
    console.error('Q2 authentication error:', err.message);
    return res.json({
      commands: [
        {
          type: 'com.okta.action.update',
          value: {
            credential: 'UNVERIFIED'
          }
        }
      ],
      error: {
        errorSummary: 'Authentication failed.',
        errorCauses: [
          {
            errorSummary: err.message,
            reason: 'Q2_AUTH_FAILED',
            locationType: 'body',
            location: 'data.credential'
          }
        ]
      }
    });
  }
});

// Simple health check
app.get('/health', (req, res) => {
  res.json({ status: 'ok', service: 'Q2 ↔ Okta round‑trip' });
});

app.listen(PORT, () => {
  console.log(`Q2 ↔ Okta round‑trip service running on port ${PORT}`);
  console.log('Endpoint: POST /okta-login (expects {"username":"...","password":"..."})');
});
