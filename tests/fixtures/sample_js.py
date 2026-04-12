"""Sample JS code for testing.

All secret-looking literals in this file are intentionally fake sample values
used for detector and fixture coverage. They are not production credentials.
"""

from .fake_secrets import (
    FAKE_AWS_ACCESS_KEY,
    FAKE_STRIPE_LIVE_ALT,
    FAKE_STRIPE_LIVE_SHORT,
)

# Simple endpoint examples
SIMPLE_FETCH = '''
fetch("/api/users")
    .then(response => response.json())
    .then(data => console.log(data));
'''

AXIOS_EXAMPLE = '''
import axios from 'axios';

const api = axios.create({
    baseURL: 'https://api.example.com',
    headers: {
        'Authorization': `Bearer ${token}`
    }
});

api.get('/users');
api.post('/orders', { product: 1, quantity: 2 });
'''

# Secret examples
AWS_SECRETS = '''
const AWS = require('aws-sdk');

AWS.config.update({
    accessKeyId: '__AWS_ACCESS_KEY__',
    secretAccessKey: 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY'
});
'''.replace('__AWS_ACCESS_KEY__', FAKE_AWS_ACCESS_KEY)

STRIPE_INTEGRATION = '''
const stripe = require('stripe')('__STRIPE_LIVE_SHORT__');

app.post('/charge', async (req, res) => {
    const charge = await stripe.charges.create({
        amount: 2000,
        currency: 'usd',
        source: req.body.token
    });
});
'''.replace('__STRIPE_LIVE_SHORT__', FAKE_STRIPE_LIVE_SHORT)

JWT_TOKEN = '''
const token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";

fetch('/api/protected', {
    headers: {
        'Authorization': `Bearer ${token}`
    }
});
'''

# Internal domain examples
INTERNAL_DOMAINS = '''
const config = {
    production: 'https://api.example.com',
    staging: 'https://staging.internal.example.com',
    development: 'http://localhost:3000',
    internal: 'https://api.corp.internal'
};

const s3Bucket = 's3://my-company-private-data';
const gcsUrl = 'https://storage.googleapis.com/internal-bucket';
'''

# Feature flag examples
FEATURE_FLAGS = '''
import { useLaunchDarkly } from 'launchdarkly-react';

const { flags } = useLaunchDarkly();

if (flags.newCheckoutFlow) {
    showNewCheckout();
}

if (window.__FEATURE_FLAGS__.adminPanel) {
    renderAdminPanel();
}

const isDevMode = process.env.NODE_ENV === 'development';
'''

# Debug examples
DEBUG_CODE = '''
// Debug endpoints
fetch('/debug/state');
fetch('/internal/admin/users');
fetch('/api/_health');

// Console logging
console.log('User token:', userToken);
console.debug('API Response:', response);

// Debugger
function processPayment(data) {
    debugger;  // Remove before production
    return stripe.charge(data);
}

// Dev check
if (process.env.NODE_ENV === 'development') {
    window.__DEV_TOOLS__ = true;
}
'''

# Complex example with multiple findings
COMPLEX_APP = '''
import axios from 'axios';
import { LaunchDarkly } from '@launchdarkly/js-client-sdk';

const API_KEY = '__STRIPE_LIVE_ALT__';
const INTERNAL_API = 'https://internal-api.corp.example.com';

const client = new LaunchDarkly('sdk-key-123');

const api = axios.create({
    baseURL: process.env.NODE_ENV === 'production'
        ? 'https://api.example.com'
        : 'http://localhost:3000',
    headers: {
        'X-API-Key': API_KEY
    }
});

async function fetchUsers() {
    const showAdminPanel = await client.variation('admin-panel', false);

    if (showAdminPanel) {
        const adminData = await api.get('/internal/admin/users');
        console.log('Admin data:', adminData);
    }

    return api.get('/api/v1/users');
}

// Health check
fetch('/debug/health');
'''.replace('__STRIPE_LIVE_ALT__', FAKE_STRIPE_LIVE_ALT)
