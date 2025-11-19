/**
 * Load Test: Authentication Endpoints
 *
 * Tests user registration, login, and session management under load.
 *
 * Usage:
 *   k6 run loadtests/auth.js
 *   k6 run --vus 100 --duration 30s loadtests/auth.js
 */

import http from 'k6/http';
import { check, sleep } from 'k6';
import { Rate, Trend } from 'k6/metrics';

// Custom metrics
const registerErrorRate = new Rate('register_errors');
const loginErrorRate = new Rate('login_errors');
const registerLatency = new Trend('register_latency');
const loginLatency = new Trend('login_latency');

// Configuration
const BASE_URL = __ENV.BASE_URL || 'http://localhost:3000';

// Test stages for gradual ramp-up
export const options = {
  stages: [
    { duration: '30s', target: 20 },   // Ramp up to 20 users
    { duration: '1m', target: 50 },    // Ramp up to 50 users
    { duration: '2m', target: 100 },   // Ramp up to 100 users
    { duration: '1m', target: 100 },   // Stay at 100 users
    { duration: '30s', target: 0 },    // Ramp down to 0 users
  ],
  thresholds: {
    'http_req_duration': ['p(95)<500', 'p(99)<1000'], // 95% < 500ms, 99% < 1s
    'http_req_failed': ['rate<0.05'],                  // Error rate < 5%
    'register_errors': ['rate<0.05'],
    'login_errors': ['rate<0.05'],
  },
};

export default function () {
  const testId = `user_${__VU}_${__ITER}_${Date.now()}`;
  const email = `${testId}@loadtest.example.com`;
  const password = 'SecureTestPassword123!';
  const name = `Load Test User ${testId}`;

  // Test 1: User Registration
  const registerPayload = JSON.stringify({
    email: email,
    password: password,
    name: name,
  });

  const registerParams = {
    headers: {
      'Content-Type': 'application/json',
    },
    tags: { name: 'Register' },
  };

  const registerStart = Date.now();
  const registerRes = http.post(
    `${BASE_URL}/v1/auth/register`,
    registerPayload,
    registerParams
  );
  const registerDuration = Date.now() - registerStart;

  registerLatency.add(registerDuration);

  const registerSuccess = check(registerRes, {
    'register: status is 201': (r) => r.status === 201,
    'register: has user object': (r) => JSON.parse(r.body).user !== undefined,
    'register: has organization': (r) => JSON.parse(r.body).organization !== undefined,
    'register: has session_token': (r) => JSON.parse(r.body).session_token !== undefined,
  });

  registerErrorRate.add(!registerSuccess);

  if (!registerSuccess) {
    console.error(`Register failed for ${email}: ${registerRes.status} - ${registerRes.body}`);
    sleep(1);
    return;
  }

  // Extract session token from response
  const registerData = JSON.parse(registerRes.body);
  const sessionToken = registerData.session_token;

  // Small delay between registration and login
  sleep(0.5);

  // Test 2: User Login
  const loginPayload = JSON.stringify({
    email: email,
    password: password,
  });

  const loginParams = {
    headers: {
      'Content-Type': 'application/json',
    },
    tags: { name: 'Login' },
  };

  const loginStart = Date.now();
  const loginRes = http.post(
    `${BASE_URL}/v1/auth/login/password`,
    loginPayload,
    loginParams
  );
  const loginDuration = Date.now() - loginStart;

  loginLatency.add(loginDuration);

  const loginSuccess = check(loginRes, {
    'login: status is 200': (r) => r.status === 200,
    'login: has user object': (r) => JSON.parse(r.body).user !== undefined,
    'login: has organizations': (r) => JSON.parse(r.body).organizations !== undefined,
    'login: has session_token': (r) => JSON.parse(r.body).session_token !== undefined,
  });

  loginErrorRate.add(!loginSuccess);

  if (!loginSuccess) {
    console.error(`Login failed for ${email}: ${loginRes.status} - ${loginRes.body}`);
  }

  // Test 3: Get Current User Profile (authenticated request)
  const profileParams = {
    headers: {
      'Cookie': `infera_session=${sessionToken}`,
    },
    tags: { name: 'GetProfile' },
  };

  const profileRes = http.get(`${BASE_URL}/v1/users/me`, profileParams);

  check(profileRes, {
    'profile: status is 200': (r) => r.status === 200,
    'profile: has user data': (r) => JSON.parse(r.body).id !== undefined,
  });

  // Test 4: List User Sessions
  const sessionsRes = http.get(`${BASE_URL}/v1/users/sessions`, profileParams);

  check(sessionsRes, {
    'sessions: status is 200': (r) => r.status === 200,
    'sessions: is array': (r) => Array.isArray(JSON.parse(r.body)),
    'sessions: has at least 2 sessions': (r) => JSON.parse(r.body).length >= 2, // From register + login
  });

  // Test 5: Logout
  const logoutRes = http.post(`${BASE_URL}/v1/auth/logout`, null, profileParams);

  check(logoutRes, {
    'logout: status is 200': (r) => r.status === 200,
  });

  sleep(1); // Think time between iterations
}
