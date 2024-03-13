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
  createServiceRef,
  createServiceFactory,
  coreServices,
  type LoggerService,
} from '@backstage/backend-plugin-api';
import type { Config } from '@backstage/config';
import { NotFoundError, ResponseError } from '@backstage/errors';

export interface OpaService {
  query(packageName: string, data: any): Promise<any>;
}

export const opaServiceRef = createServiceRef<OpaService>({
  scope: 'root',
  id: 'opa.global',
});

class DefaultOpaService implements OpaService {
  private readonly packagePrefix: string;
  private readonly baseUrl: string;
  private readonly logger: LoggerService;

  constructor(config: Config, logger: LoggerService) {
    this.baseUrl = config.getString('opaClient.baseUrl');
    this.packagePrefix =
      config.getOptionalString('opaClient.packagePrefix') || '';
    this.logger = logger.child({
      service: opaServiceRef.id,
    });
  }

  async query(packageName: string, data: any): Promise<any> {
    const packageNameParse = packageName.split('.');
    const packagePrefixPath = this.packagePrefix.split('.');
    const packagePath = [...packagePrefixPath, ...packageNameParse].join('/');
    const requestUrl = `${this.baseUrl}/v1/data/${packagePath}`;
    this.logger.debug(
      `Sending request to OPA: ${requestUrl}, ${JSON.stringify(data)}`,
    );

    const response = await fetch(requestUrl, {
      method: 'POST',
      body: JSON.stringify({
        input: data,
      }),
    });

    if (!response.ok) {
      const err = await ResponseError.fromResponse(response);
      this.logger.error('Error during OPA policy evaluation:', err.cause);
      throw err;
    }

    const results = await response.json();

    if (Object.keys(results).length === 0) {
      this.logger.error(
        `Empty results received for request path: ${packagePath}`,
        data,
      );
      throw new NotFoundError('Missing permission handler');
    }

    this.logger.debug(
      `Received response from OPA server: ${JSON.stringify(results)}`,
    );
    return results;
  }
}

export const opaServiceFactory = createServiceFactory({
  service: opaServiceRef,
  deps: { config: coreServices.rootConfig, logger: coreServices.rootLogger },
  factory({ config, logger }) {
    return new DefaultOpaService(config, logger);
  },
});
