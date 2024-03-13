/*
 * Copyright 2024 The Backstage Authors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
import { createRouter } from '@backstage/plugin-permission-backend';
import { type BackstageIdentityResponse } from '@backstage/plugin-auth-node';
import {
  type PermissionPolicy,
  type PolicyQuery,
} from '@backstage/plugin-permission-node';
import {
  AuthorizeResult,
  type PermissionAttributes,
  type PolicyDecision,
} from '@backstage/plugin-permission-common';
import {
  coreServices,
  createBackendPlugin,
} from '@backstage/backend-plugin-api';

import { decodeJwt } from 'jose';
import { loggerToWinstonLogger } from '@backstage/backend-common';
import { opaServiceRef, type OpaService } from '@backstage/plugin-opa-node';

export type PolicyClaims = { [claim: string]: unknown };
export type PolicyEvaluationIdentity = {
  user?: string;
  claims?: PolicyClaims;
};

export type PolicyEvaluationInput = {
  permission: {
    name: string;
    attributes: PermissionAttributes;
    type?: string;
    resourceType?: string;
    resourceRef?: string;
  };
  identity?: PolicyEvaluationIdentity;
};

export class OpaClient {
  // private readonly config: Config;
  // private readonly logger: LoggerService;
  private readonly opa: OpaService;

  constructor(
    // config: Config,
    // logger: LoggerService,
    opa: OpaService,
  ) {
    // this.logger = logger;
    // this.config = config;
    this.opa = opa;
  }

  async evaluatePolicy(input: PolicyEvaluationInput): Promise<any> {
    // splitting the OPA package name and sanitizing it to match package name enforced rules
    const packageName = input.permission.name.split('.')[0].replace('-', '_');
    const results = await this.opa.query(packageName, input);

    return results?.result;
  }
}

export const getPolicydentity = async (
  user?: BackstageIdentityResponse,
): Promise<PolicyEvaluationIdentity> => {
  if (!user) {
    return {};
  }

  // TODO: validate token (expiration, encoded using current backend secret....)
  const decoded = decodeJwt(user.token);
  const { iss, sub, aud, iat, exp, jti, nbf, ...claims } = decoded;
  return {
    user: user.identity.userEntityRef,
    claims: {
      default: claims.ent,
      ...claims,
    },
  };
};

export const policyEvaluator = (opaClient: OpaClient) => {
  return async (
    request: PolicyQuery,
    user?: BackstageIdentityResponse,
  ): Promise<PolicyDecision> => {
    const identity = await getPolicydentity(user);
    const input: PolicyEvaluationInput = {
      permission: {
        name: request.permission.name,
        attributes: request.permission.attributes,
        type: request.permission.type,
        resourceType:
          request.permission.type === 'resource'
            ? request.permission.resourceType
            : undefined,
      },
      identity: identity,
    };

    const response = await opaClient.evaluatePolicy(input);

    if (response.decision.result === 'CONDITIONAL') {
      return {
        result: AuthorizeResult.CONDITIONAL,
        pluginId: response.decision.pluginId,
        resourceType: response.decision.resourceType,
        conditions: response.decision.conditions,
      };
    }

    if (response.decision.result !== 'ALLOW') {
      return { result: AuthorizeResult.DENY };
    }

    return { result: AuthorizeResult.ALLOW };
  };
};

export const opaPermissionPlugin = createBackendPlugin({
  pluginId: 'permission',
  register(env) {
    env.registerInit({
      deps: {
        logger: coreServices.logger,
        config: coreServices.rootConfig,
        http: coreServices.httpRouter,
        discovery: coreServices.discovery,
        identity: coreServices.identity,
        opaService: opaServiceRef,
      },
      async init({ config, logger, http, discovery, identity, opaService }) {
        const opaClient = new OpaClient(opaService);
        const genericPolicyEvaluator = policyEvaluator(opaClient);
        class PermissionsHandler implements PermissionPolicy {
          async handle(
            request: PolicyQuery,
            user?: BackstageIdentityResponse,
          ): Promise<PolicyDecision> {
            return await genericPolicyEvaluator(request, user);
          }
        }
        const router = await createRouter({
          logger: loggerToWinstonLogger(logger),
          config,
          discovery,
          identity,
          policy: new PermissionsHandler(),
        });

        http.use(router);
      },
    });
  },
});
