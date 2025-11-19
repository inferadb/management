/**
 * Load Test: Organization Management
 *
 * Tests organization creation, member management, and team operations.
 *
 * Usage:
 *   k6 run loadtests/organizations.js
 */

import http from 'k6/http';
import { check, sleep } from 'k6';
import { Rate, Trend } from 'k6/metrics';

// Custom metrics
const orgCreateErrorRate = new Rate('org_create_errors');
const teamCreateErrorRate = new Rate('team_create_errors');
const orgCreateLatency = new Trend('org_create_latency');
const teamCreateLatency = new Trend('team_create_latency');

// Configuration
const BASE_URL = __ENV.BASE_URL || 'http://localhost:3000';

export const options = {
  stages: [
    { duration: '30s', target: 10 },
    { duration: '1m', target: 25 },
    { duration: '1m', target: 25 },
    { duration: '30s', target: 0 },
  ],
  thresholds: {
    'http_req_duration': ['p(95)<800', 'p(99)<1500'],
    'http_req_failed': ['rate<0.05'],
    'org_create_errors': ['rate<0.05'],
    'team_create_errors': ['rate<0.05'],
  },
};

export default function () {
  const testId = `orgtest_${__VU}_${__ITER}_${Date.now()}`;
  const email = `${testId}@loadtest.example.com`;
  const password = 'SecureTestPassword123!';
  const name = `Org Test User ${testId}`;

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
  const defaultOrgId = registerData.organization.id;

  const authParams = {
    headers: {
      'Cookie': `infera_session=${sessionToken}`,
      'Content-Type': 'application/json',
    },
  };

  sleep(0.5);

  // Step 2: List Organizations
  const listOrgsRes = http.get(
    `${BASE_URL}/v1/organizations`,
    Object.assign({}, authParams, { tags: { name: 'ListOrganizations' } })
  );

  check(listOrgsRes, {
    'list_orgs: status is 200': (r) => r.status === 200,
    'list_orgs: is array': (r) => Array.isArray(JSON.parse(r.body)),
    'list_orgs: has default org': (r) => JSON.parse(r.body).length >= 1,
  });

  sleep(0.5);

  // Step 3: Create Additional Organization
  const orgPayload = JSON.stringify({
    name: `Load Test Organization ${testId}`,
    tier: 'free',
  });

  const orgStart = Date.now();
  const orgRes = http.post(
    `${BASE_URL}/v1/organizations`,
    orgPayload,
    Object.assign({}, authParams, { tags: { name: 'CreateOrganization' } })
  );
  const orgDuration = Date.now() - orgStart;

  orgCreateLatency.add(orgDuration);

  const orgSuccess = check(orgRes, {
    'org_create: status is 201': (r) => r.status === 201,
    'org_create: has id': (r) => JSON.parse(r.body).id !== undefined,
    'org_create: has name': (r) => JSON.parse(r.body).name !== undefined,
    'org_create: has tier': (r) => JSON.parse(r.body).tier === 'free',
  });

  orgCreateErrorRate.add(!orgSuccess);

  if (!orgSuccess) {
    console.error(`Organization creation failed: ${orgRes.status} - ${orgRes.body}`);
    sleep(1);
    return;
  }

  const orgData = JSON.parse(orgRes.body);
  const newOrgId = orgData.id;

  sleep(0.5);

  // Step 4: Get Organization Details
  const getOrgRes = http.get(
    `${BASE_URL}/v1/organizations/${newOrgId}`,
    Object.assign({}, authParams, { tags: { name: 'GetOrganization' } })
  );

  check(getOrgRes, {
    'get_org: status is 200': (r) => r.status === 200,
    'get_org: has correct id': (r) => JSON.parse(r.body).id === newOrgId,
  });

  sleep(0.5);

  // Step 5: Update Organization
  const updateOrgPayload = JSON.stringify({
    name: `Updated Organization ${testId}`,
  });

  const updateOrgRes = http.patch(
    `${BASE_URL}/v1/organizations/${newOrgId}`,
    updateOrgPayload,
    Object.assign({}, authParams, { tags: { name: 'UpdateOrganization' } })
  );

  check(updateOrgRes, {
    'update_org: status is 200': (r) => r.status === 200,
    'update_org: name updated': (r) => JSON.parse(r.body).name.includes('Updated'),
  });

  sleep(0.5);

  // Step 6: List Organization Members
  const listMembersRes = http.get(
    `${BASE_URL}/v1/organizations/${newOrgId}/members`,
    Object.assign({}, authParams, { tags: { name: 'ListMembers' } })
  );

  check(listMembersRes, {
    'list_members: status is 200': (r) => r.status === 200,
    'list_members: has data': (r) => JSON.parse(r.body).data !== undefined,
    'list_members: has owner': (r) => JSON.parse(r.body).data.length >= 1,
  });

  sleep(0.5);

  // Step 7: Create Team
  const teamPayload = JSON.stringify({
    name: `Load Test Team ${testId}`,
    description: 'Team created during load testing',
  });

  const teamStart = Date.now();
  const teamRes = http.post(
    `${BASE_URL}/v1/organizations/${newOrgId}/teams`,
    teamPayload,
    Object.assign({}, authParams, { tags: { name: 'CreateTeam' } })
  );
  const teamDuration = Date.now() - teamStart;

  teamCreateLatency.add(teamDuration);

  const teamSuccess = check(teamRes, {
    'team_create: status is 201': (r) => r.status === 201,
    'team_create: has id': (r) => JSON.parse(r.body).id !== undefined,
    'team_create: has name': (r) => JSON.parse(r.body).name !== undefined,
  });

  teamCreateErrorRate.add(!teamSuccess);

  if (teamSuccess) {
    const teamData = JSON.parse(teamRes.body);
    const teamId = teamData.id;

    sleep(0.5);

    // Step 8: List Teams
    const listTeamsRes = http.get(
      `${BASE_URL}/v1/organizations/${newOrgId}/teams`,
      Object.assign({}, authParams, { tags: { name: 'ListTeams' } })
    );

    check(listTeamsRes, {
      'list_teams: status is 200': (r) => r.status === 200,
      'list_teams: has data': (r) => JSON.parse(r.body).data !== undefined,
    });

    sleep(0.5);

    // Step 9: Get Team Details
    const getTeamRes = http.get(
      `${BASE_URL}/v1/organizations/${newOrgId}/teams/${teamId}`,
      Object.assign({}, authParams, { tags: { name: 'GetTeam' } })
    );

    check(getTeamRes, {
      'get_team: status is 200': (r) => r.status === 200,
      'get_team: has correct id': (r) => JSON.parse(r.body).id === teamId,
    });
  }

  sleep(1);
}
