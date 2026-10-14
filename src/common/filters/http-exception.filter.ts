import {
  ArgumentsHost,
  Catch,
  ExceptionFilter,
  HttpException,
  HttpStatus,
} from '@nestjs/common';
import type { Response } from 'express';

import type { RequestWithContext } from '../types/request-context.types';

type ApiErrorCode =
  | 'VALIDATION_ERROR'
  | 'BAD_REQUEST'
  | 'RESOURCE_NOT_FOUND'
  | 'UNAUTHORIZED'
  | 'FORBIDDEN'
  | 'CONFLICT'
  | 'HTTP_ERROR'
  | 'INTERNAL_SERVER_ERROR';

type ApiErrorResponse = {
  error: {
    code: ApiErrorCode;
    message: string;
    status: number;
    path: string;
    timestamp: string;
    requestId: string;
  };
};

@Catch()
export class HttpExceptionFilter implements ExceptionFilter {
  catch(exception: unknown, host: ArgumentsHost): void {
    const context = host.switchToHttp();
    const request = context.getRequest<RequestWithContext>();
    const response = context.getResponse<Response>();

    const status =
      exception instanceof HttpException
        ? exception.getStatus()
        : HttpStatus.INTERNAL_SERVER_ERROR;

    const code = this.getErrorCode(status, exception);
    const message = this.getSafeMessage(code);

    // The request ID is created by RequestContextMiddleware.
    // Never generate a second ID inside the exception filter.
    // Preserve the original HTTP status if the ID is missing.
    const requestId = request.requestId ?? '';

    const errorResponse: ApiErrorResponse = {
      error: {
        code,
        message,
        status,
        path: request.path,
        timestamp: new Date().toISOString(),
        requestId,
      },
    };

    response.status(status).json(errorResponse);
  }

  private getErrorCode(
    status: number,
    exception: unknown,
  ): ApiErrorCode {
    if (
      status === HttpStatus.BAD_REQUEST &&
      exception instanceof HttpException
    ) {
      const exceptionResponse = exception.getResponse();

      if (
        typeof exceptionResponse === 'object' &&
        exceptionResponse !== null &&
        'code' in exceptionResponse &&
        exceptionResponse.code === 'VALIDATION_ERROR'
      ) {
        return 'VALIDATION_ERROR';
      }
    }

    switch (status) {
      case HttpStatus.BAD_REQUEST:
        return 'BAD_REQUEST';

      case HttpStatus.UNAUTHORIZED:
        return 'UNAUTHORIZED';

      case HttpStatus.FORBIDDEN:
        return 'FORBIDDEN';

      case HttpStatus.NOT_FOUND:
        return 'RESOURCE_NOT_FOUND';

      case HttpStatus.CONFLICT:
        return 'CONFLICT';

      case HttpStatus.INTERNAL_SERVER_ERROR:
        return 'INTERNAL_SERVER_ERROR';

      default:
        return status >= 500
          ? 'INTERNAL_SERVER_ERROR'
          : 'HTTP_ERROR';
    }
  }

  private getSafeMessage(code: ApiErrorCode): string {
    switch (code) {
      case 'VALIDATION_ERROR':
        return 'Invalid request parameters.';

      case 'BAD_REQUEST':
        return 'The request is invalid.';

      case 'UNAUTHORIZED':
        return 'Authentication is required.';

      case 'FORBIDDEN':
        return 'Access is denied.';

      case 'RESOURCE_NOT_FOUND':
        return 'The requested resource was not found.';

      case 'CONFLICT':
        return 'The request conflicts with the current state.';

      case 'HTTP_ERROR':
        return 'The request could not be completed.';

      case 'INTERNAL_SERVER_ERROR':
      default:
        return 'An internal error occurred.';
    }
  }
}
