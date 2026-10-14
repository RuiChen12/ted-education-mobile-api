import type { INestApplication } from '@nestjs/common';
import { jest } from '@jest/globals';

import { AppLoggerService } from '../../src/common/logging/logger.service';
import { RequestContextMiddleware } from '../../src/common/middleware/request-context.middleware';

/**
 * Registers request context middleware for E2E tests.
 *
 * Suppresses request log output during regression tests
 * while keeping request ID generation and tracking active.
 */
export function registerRequestContext(
  app: INestApplication,
): void {
  const logger = new AppLoggerService();

  jest.spyOn(logger, 'logHttpRequest').mockImplementation(() => {
    // Suppress log output in regression tests.
  });

  const middleware = new RequestContextMiddleware(logger);

  app.use(middleware.use.bind(middleware));
}
