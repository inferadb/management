/**
 * Load Test: Vault and Token Management
 *
 * Tests vault creation, access grants, and token generation under load.
 *
 * Usage:
 *   k6 run loadtests/vaults.js
 *   k6 run --vus 50 --duration 1m loadtests/vaults.js
 */

import http from 'k6/http';
import { check, sleep } from 'k6';
import { Rate, Trend } from 'k6/metrics';

// Custom metrics
const vaultCreateErrorRate = new Rate('vault_create_errors');
const tokenGenErrorRate = new Rate('token_gen_errors');
const vaultCreateLatency = new Trend('vault_create_latency');
const tokenGenLatency = new Trend('token_gen_latency');

// Configuration
const BASE_URL = __ENV.BASE_URL || 'http://localhost:3000';

export const options = {
  stages: [
    { duration: '30s', target: 10 },   // Ramp up to 10 users
    { duration: '1m', target: 30 },    // Ramp up to 30 users
    { duration: '1m', target: 50 },    // Ramp up to 50 users
    { duration: '1m', target: 50 },    // Stay at 50 users
    { duration: '30s', target: 0 },    // Ramp down
  ],
  thresholds: {
    'http_req_duration': ['p(95)<1000', 'p(99)<2000'],
    'http_req_failed': ['rate<0.05'],
    'vault_create_errors': ['rate<0.05'],
    'token_gen_errors': ['rate<0.05'],
  },
};

export default function () {
  const testId = `vaulttest_${__VU}_${__ITER}_${Date.now()}`;
  const email = `${testId}@loadtest.example.com`;
  const password = 'SecureTestPassword123!';
  const name = `Vault Test User ${testId}`;

  // Step 1: Register user
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

  if (registerRes.status !== 201) {
    console.error(`Register failed: ${registerRes.status}`);
    sleep(1);
    return;
  }

  const registerData = JSON.parse(registerRes.body);
  const sessionToken = registerData.session_token;
  const orgId = registerData.organization.id;

  const authParams = {
    headers: {
      'Cookie': `infera_session=${sessionToken}`,
      'Content-Type': 'application/json',
    },
  };

  sleep(0.5);

  // Step 2: Create Vault
  const vaultPayload = JSON.stringify({
    name: `Load Test Vault ${testId}`,
    description: 'Vault created during load testing',
  });

  const vaultStart = Date.now();
  const vaultRes = http.post(
    `${BASE_URL}/v1/organizations/${orgId}/vaults`,
    vaultPayload,
    Object.assign({}, authParams, { tags: { name: 'CreateVault' } })
  );
  const vaultDuration = Date.now() - vaultStart;

  vaultCreateLatency.add(vaultDuration);

  const vaultSuccess = check(vaultRes, {
    'vault_create: status is 201': (r) => r.status === 201,
    'vault_create: has id': (r) => JSON.parse(r.body).id !== undefined,
    'vault_create: has name': (r) => JSON.parse(r.body).name !== undefined,
  });

  vaultCreateErrorRate.add(!vaultSuccess);

  if (!vaultSuccess) {
    console.error(`Vault creation failed: ${vaultRes.status} - ${vaultRes.body}`);
    sleep(1);
    return;
  }

  const vaultData = JSON.parse(vaultRes.body);
  const vaultId = vaultData.id;

  sleep(0.5);

  // Step 3: List Vaults
  const listVaultsRes = http.get(
    `${BASE_URL}/v1/organizations/${orgId}/vaults`,
    Object.assign({}, authParams, { tags: { name: 'ListVaults' } })
  );

  check(listVaultsRes, {
    'list_vaults: status is 200': (r) => r.status === 200,
    'list_vaults: has data array': (r) => JSON.parse(r.body).data !== undefined,
  });

  sleep(0.5);

  // Step 4: Get Vault Details
  const getVaultRes = http.get(
    `${BASE_URL}/v1/organizations/${orgId}/vaults/${vaultId}`,
    Object.assign({}, authParams, { tags: { name: 'GetVault' } })
  );

  check(getVaultRes, {
    'get_vault: status is 200': (r) => r.status === 200,
    'get_vault: has correct id': (r) => JSON.parse(r.body).id === vaultId,
  });

  sleep(0.5);

  // Step 5: Create Client for Token Generation
  const clientPayload = JSON.stringify({
    name: `Load Test Client ${testId}`,
    vault_id: vaultId,
  });

  const clientRes = http.post(
    `${BASE_URL}/v1/organizations/${orgId}/clients`,
    clientPayload,
    Object.assign({}, authParams, { tags: { name: 'CreateClient' } })
  );

  if (clientRes.status !== 201) {
    console.error(`Client creation failed: ${clientRes.status}`);
    sleep(1);
    return;
  }

  const clientData = JSON.parse(clientRes.body);
  const clientId = clientData.id;

  sleep(0.5);

  // Step 6: Generate Client Certificate
  const certPayload = JSON.stringify({
    name: `Load Test Certificate ${testId}`,
  });

  const certRes = http.post(
    `${BASE_URL}/v1/organizations/${orgId}/clients/${clientId}/certificates`,
    certPayload,
    Object.assign({}, authParams, { tags: { name: 'CreateCertificate' } })
  );

  check(certRes, {
    'cert_create: status is 201': (r) => r.status === 201,
    'cert_create: has private_key_pem': (r) => JSON.parse(r.body).private_key_pem !== undefined,
  });

  sleep(0.5);

  // Step 7: Generate Vault Token
  const tokenStart = Date.now();
  const tokenRes = http.post(
    `${BASE_URL}/v1/organizations/${orgId}/vaults/${vaultId}/tokens`,
    JSON.stringify({ ttl: 3600 }),
    Object.assign({}, authParams, { tags: { name: 'GenerateToken' } })
  );
  const tokenDuration = Date.now() - tokenStart;

  tokenGenLatency.add(tokenDuration);

  const tokenSuccess = check(tokenRes, {
    'token_gen: status is 201': (r) => r.status === 201,
    'token_gen: has access_token': (r) => JSON.parse(r.body).access_token !== undefined,
    'token_gen: has refresh_token': (r) => JSON.parse(r.body).refresh_token !== undefined,
    'token_gen: has token_type': (r) => JSON.parse(r.body).token_type === 'Bearer',
    'token_gen: has expires_in': (r) => JSON.parse(r.body).expires_in !== undefined,
  });

  tokenGenErrorRate.add(!tokenSuccess);

  if (!tokenSuccess) {
    console.error(`Token generation failed: ${tokenRes.status} - ${tokenRes.body}`);
  }

  // Step 8: Refresh Token (if generation succeeded)
  if (tokenSuccess) {
    const tokenData = JSON.parse(tokenRes.body);
    const refreshToken = tokenData.refresh_token;

    sleep(1);

    const refreshPayload = JSON.stringify({
      refresh_token: refreshToken,
    });

    const refreshRes = http.post(
      `${BASE_URL}/v1/tokens/refresh`,
      refreshPayload,
      {
        headers: { 'Content-Type': 'application/json' },
        tags: { name: 'RefreshToken' },
      }
    );

    check(refreshRes, {
      'token_refresh: status is 200': (r) => r.status === 200,
      'token_refresh: has new access_token': (r) => JSON.parse(r.body).access_token !== undefined,
      'token_refresh: has new refresh_token': (r) => JSON.parse(r.body).refresh_token !== undefined,
    });
  }

  sleep(1);
}
