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
import {
  coreServices,
  createBackendModule,
} from '@backstage/backend-plugin-api';
import {
  AuthorizeResult,
  type ConditionalPolicyDecision,
  type PermissionCriteria,
  type PermissionCondition,
} from '@backstage/plugin-permission-common';
import {
  type NextFunction,
  type Request,
  type RequestHandler,
  type Response,
} from 'express';
import { NotAllowedError } from '@backstage/errors';
import { opaServiceRef } from './opa-service';
import { decodeJwt } from 'jose';
import { RESOURCE_TYPE_CATALOG_ENTITY } from '@backstage/plugin-catalog-common';
import { createConditionAuthorizer } from '@backstage/plugin-permission-node';
import { permissionRules } from '@backstage/plugin-catalog-backend';
import { CatalogClient } from '@backstage/catalog-client';

export const shieldFactory = (pluginId: string) =>
  createBackendModule({
    pluginId,
    moduleId: `${pluginId}.shield`,
    register(env) {
      env.registerInit({
        deps: {
          httpRouter: coreServices.httpRouter,
          logger: coreServices.logger,
          opaService: opaServiceRef,
          tokenManager: coreServices.tokenManager,
          discovery: coreServices.discovery,
          identity: coreServices.identity,
        },
        async init({
          httpRouter,
          opaService,
          discovery,
          tokenManager,
          logger,
          identity,
        }) {
          const getIdentity = async (req: Request) => {
            const currentIdentity = await identity.getIdentity({
              request: req,
            });
            if (!currentIdentity || !currentIdentity?.token) {
              return {};
            }

            const decoded = decodeJwt(currentIdentity.token);
            const { iss, sub, aud, iat, exp, jti, nbf, ...claims } = decoded;
            return {
              user: sub,
              claims: {
                default: claims.ent,
                ...claims,
              },
            };
          };

          const catalog = new CatalogClient({ discoveryApi: discovery });

          const authorizer = createConditionAuthorizer(
            Object.values(permissionRules),
          );

          const pathAuthorizeMiddleware: RequestHandler = async (
            req: Request,
            _: Response,
            next: NextFunction,
          ) => {
            const transformedIdentity = await getIdentity(req);
            const path = req.path;

            const query = {
              path,
              transformedIdentity,
            };

            const result = (await opaService.query(
              `shield.${pluginId}`,
              query,
            )) as any;

            logger.debug(
              '#### going to evaluate decision: ',
              result?.result?.decision?.result,
            );

            switch (result?.result?.decision?.result) {
              case AuthorizeResult.ALLOW:
                next();
                break;
              case AuthorizeResult.CONDITIONAL: {
                logger.debug('#### evaluating conditional decision');
                const fakeConditions = {
                  anyOf: [
                    {
                      resourceType: 'catalog-entity',
                      rule: 'IS_ENTITY_OWNER',
                      params: { claims: ['group:default/backstage'] },
                    },
                  ],
                } as PermissionCriteria<PermissionCondition>;

                // copied payload what we return from OPA for catalog
                const fakeConditionalDecision = {
                  result: AuthorizeResult.CONDITIONAL,
                  pluginId: 'test',
                  resourceType: RESOURCE_TYPE_CATALOG_ENTITY,
                  conditions: fakeConditions,
                } as ConditionalPolicyDecision;

                const catalogResource = await catalog.getEntityByRef(
                  // the parsed resource ref from URL will be returned by OPA
                  {
                    kind: 'component',
                    namespace: 'default',
                    name: 'backstage',
                  },
                  {
                    token: (await tokenManager.getToken()).token,
                  },
                );

                const condDecision = authorizer(
                  fakeConditionalDecision,
                  catalogResource,
                );
                if (condDecision) {
                  logger.debug('###### condition evaluated successfully');
                  next();
                } else {
                  logger.debug('###### condition evaluation failed');
                  next(new NotAllowedError('Not Allowed'));
                }
                break;
              }
              default:
                next(new NotAllowedError('Not Allowed'));
                break;
            }
            httpRouter.use(pathAuthorizeMiddleware);
          };
        },
      });
    },
  });
