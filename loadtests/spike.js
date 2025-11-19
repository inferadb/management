/**
 * Load Test: Spike Test
 *
 * Tests system behavior under sudden traffic spikes.
 * Simulates realistic traffic patterns with burst capability.
 *
 * Usage:
 *   k6 run loadtests/spike.js
 */

import http from 'k6/http';
import { check, sleep } from 'k6';
import { Rate } from 'k6/metrics';

// Custom metrics
const errorRate = new Rate('errors');

// Configuration
const BASE_URL = __ENV.BASE_URL || 'http://localhost:3000';

export const options = {
  stages: [
    { duration: '10s', target: 10 },    // Warm up to 10 users
    { duration: '10s', target: 10 },    // Stay at 10 users
    { duration: '10s', target: 200 },   // Spike to 200 users
    { duration: '30s', target: 200 },   // Sustain spike
    { duration: '10s', target: 10 },    // Drop back to 10
    { duration: '10s', target: 10 },    // Recover
    { duration: '10s', target: 500 },   // Large spike to 500 users
    { duration: '30s', target: 500 },   // Sustain large spike
    { duration: '20s', target: 0 },     // Ramp down
  ],
  thresholds: {
    'http_req_duration': ['p(95)<2000', 'p(99)<5000'], // More lenient during spikes
    'http_req_failed': ['rate<0.10'],                   // Allow up to 10% errors during spike
    'errors': ['rate<0.10'],
  },
};

export default function () {
  const testId = `spike_${__VU}_${__ITER}_${Date.now()}`;
  const email = `${testId}@loadtest.example.com`;
  const password = 'SecureTestPassword123!';
  const name = `Spike Test User ${testId}`;

  // Test 1: Registration (write-heavy)
  const registerPayload = JSON.stringify({
    email: email,
    password: password,
    name: name,
  });

  const registerRes = http.post(
    `${BASE_URL}/v1/auth/register`,
    registerPayload,
    {
      headers: { 'Content-Type': 'application/json' },
      tags: { name: 'Register' },
    }
  );

  const registerSuccess = check(registerRes, {
    'spike_register: status 2xx or 429': (r) => r.status === 201 || r.status === 429,
  });

  errorRate.add(!registerSuccess);

  // If rate limited, sleep and retry
  if (registerRes.status === 429) {
    const retryAfter = parseInt(registerRes.headers['Retry-After'] || '5');
    console.log(`Rate limited, retry after ${retryAfter}s`);
    sleep(retryAfter);
    return;
  }

  if (registerRes.status !== 201) {
    sleep(1);
    return;
  }

  const registerData = JSON.parse(registerRes.body);
  const sessionToken = registerData.session_token;
  const orgId = registerData.organization.id;

  // Short delay
  sleep(0.2);

  // Test 2: Read-heavy operations
  const authHeaders = {
    'Cookie': `infera_session=${sessionToken}`,
    'Content-Type': 'application/json',
  };

  // Profile read
  const profileRes = http.get(`${BASE_URL}/v1/users/me`, {
    headers: authHeaders,
    tags: { name: 'GetProfile' },
  });

  check(profileRes, {
    'spike_profile: status 2xx': (r) => r.status >= 200 && r.status < 300,
  });

  sleep(0.1);

  // List organizations
  const orgsRes = http.get(`${BASE_URL}/v1/organizations`, {
    headers: authHeaders,
    tags: { name: 'ListOrgs' },
  });

  check(orgsRes, {
    'spike_orgs: status 2xx': (r) => r.status >= 200 && r.status < 300,
  });

  sleep(0.1);

  // List vaults
  const vaultsRes = http.get(`${BASE_URL}/v1/organizations/${orgId}/vaults`, {
    headers: authHeaders,
    tags: { name: 'ListVaults' },
  });

  check(vaultsRes, {
    'spike_vaults: status 2xx': (r) => r.status >= 200 && r.status < 300,
  });

  sleep(0.5);

  // Test 3: Health check (should always work)
  const healthRes = http.get(`${BASE_URL}/v1/health`, {
    tags: { name: 'Health' },
  });

  check(healthRes, {
    'spike_health: always available': (r) => r.status === 200,
  });

  sleep(0.5);
}
