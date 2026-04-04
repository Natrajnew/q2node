const express = require('express');
const app = express();

const PORT = process.env.PORT || 3000;

// Middleware to parse JSON bodies
app.use(express.json());

// Dummy “Q2 validation” logic
function validateCredential(username, password) {
  // In real case, call Q2 API here
  // For now: accept only one test user
  return username === 'testuser' && password === 'testpass';
}

// Okta password import inline hook endpoint
app.post('/okta-password-hook', (req, res) => {
  console.log('Received Okta hook payload:', req.body);

  const data = req.body.data;

  if (!data || !data.credential) {
    console.warn('Invalid hook payload format');
    return res.status(400).json({ error: 'Invalid payload' });
  }

  const username = data.credential.username;
  const password = data.credential.password;

  console.log(`Validating user: ${username}`);

  // Call our dummy validation (replace with real Q2 API call)
  const isValid = validateCredential(username, password);

  if (isValid) {
    // Tell Okta: credential is VERIFIED
    res.json({
      commands: [
        {
          type: 'com.okta.action.update',
          value: {
            source: 'data.context.credential',
            attribute: 'credential',
            value: 'VERIFIED'
          }
        }
      ]
    });
  } else {
    // Reject credentials (empty body or empty commands)
    res.json({ commands: [] });
  }
});

// Health check
app.get('/health', (req, res) => {
  res.json({ status: 'ok' });
});

app.listen(PORT, () => {
  console.log(`Node.js password hook server running on port ${PORT}`);
  console.log('Hook endpoint: POST /okta-password-hook');
});
