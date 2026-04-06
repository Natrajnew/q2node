const express = require('express');
const axios = require('axios');
// require('dotenv').config();
const app = express();

const PORT = process.env.PORT || 3000;

app.use(express.json());

const Q2Config = {
  Q2ClientId: process.env.Q2_CLIENT_ID || '',
  Q2ClientSecret: process.env.Q2_CLIENT_SECRET || '',
  Q2GrantType: process.env.Q2_GRANT_TYPE || '',
  Q2Scope: process.env.Q2_SCOPE || '',
  Q2TokenURL: process.env.Q2_TOKEN_URL || '',
  Q2URL: process.env.Q2_URL || ''
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
      return { success: false, errors: data ? (Array.isArray(data.errors) ? data.errors : []) : [] };
    }
    throw new Error(`Q2 Authenticate failed with status ${status}`);
  }
}

// --- Controllers ---

// Okta → Node → Q2 round‑trip endpoint (matches your Okta body: data.context.credential)
app.post('/okta-login', async (req, res) => {
  const payload = req.body;

  console.log('Received Okta hook payload:', payload);

  // Expect: { data: { context: { credential: { username, password } } } }
  if (!payload || !payload.data || !payload.data.context || !payload.data.context.credential) {
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
        errorSummary: 'Inline hook payload missing data.context.credential.',
        errorCauses: [
          {
            errorSummary: 'Expected Okta inline-hook JSON with data.context.credential.',
            reason: 'MISSING_CREDENTIAL',
            locationType: 'body',
            location: 'data.context.credential'
          }
        ]
      }
    });
  }

  const username = payload.data.context.credential.username;
  const password = payload.data.context.credential.password;

  if (!username || !password) {
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
        errorSummary: 'Missing username or password.',
        errorCauses: [
          {
            errorSummary: 'Inline hook payload did not contain valid credential.username or credential.password.',
            reason: 'MISSING_CREDENTIAL',
            locationType: 'body',
            location: 'data.context.credential'
          }
        ]
      }
    });
  }

  console.log(`Validating user: ${username}`);

  let accessToken;
  try {
    accessToken = await getQ2AccessToken();
  } catch (err) {
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
        errorSummary: 'Authentication service unavailable.',
        errorCauses: [
          {
            errorSummary: err.message,
            reason: 'INTERNAL_ERROR',
            locationType: 'body',
            location: 'data.context.credential'
          }
        ]
      }
    });
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
              errorSummary: 'Login credentials were rejected by Q2 or an error occurred.',
              reason: 'INVALID_PASSWORD',
              locationType: 'body',
              location: 'data.context.credential'
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
            location: 'data.context.credential'
          }
        ]
      }
    });
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
