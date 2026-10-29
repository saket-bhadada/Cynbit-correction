import type { NextFunction, Request, RequestHandler, Response } from 'express';
import { z, type ZodError, type ZodTypeAny } from 'zod';
import { AppError, type ValidationIssue } from './errorHandler';

/**
 * Strips non-printable ASCII control characters (except standard whitespace: \t, \n, \r)
 * and normalizes leading/trailing whitespace to defend downstream sinks and logs.
 */
export function stripControlCharacters(input: string): string {
  // Remove C0 control chars 0x00-0x08, 0x0B, 0x0C, 0x0E-0x1F and DEL (0x7F)
  return input.replace(/[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F]/g, '').trim();
}

/**
 * Reusable Zod helper for bounded, control-char-sanitized text inputs.
 */
export function sanitizedString(minLength: number, maxLength: number) {
  return z
    .string()
    .transform(stripControlCharacters)
    .pipe(
      z
        .string()
        .min(minLength, `Must contain at least ${minLength} character(s).`)
        .max(maxLength, `Must not exceed ${maxLength} characters.`),
    );
}

/**
 * Converts a ZodError into RFC 6901 JSON Pointer entries suitable for RFC 9457 `errors`.
 */
export function formatZodIssues(location: string, error: ZodError): ValidationIssue[] {
  return error.issues.map((issue) => {
    const pointerSegments = [
      location,
      ...issue.path.map((segment) =>
        String(segment).replace(/~/g, '~0').replace(/\//g, '~1'),
      ),
    ];
    return {
      pointer: `/${pointerSegments.join('/')}`,
      detail: issue.message,
      code: issue.code,
    };
  });
}

export interface RequestValidationSchemas {
  body?: ZodTypeAny;
  query?: ZodTypeAny;
  params?: ZodTypeAny;
  headers?: ZodTypeAny;
}

/**
 * Strict ingestion-boundary validation middleware powered by Zod.
 * - Parses and coerces `params`, `query`, `headers`, and `body` against explicit schemas.
 * - Replaces `req.body`, `req.query`, and `req.params` with sanitized, validated outputs.
 * - Rejects invalid or unexpected fields with a 422 RFC 9457 Problem Details payload.
 */
export function validateRequest(schemas: RequestValidationSchemas): RequestHandler {
  return (req: Request, _res: Response, next: NextFunction): void => {
    const aggregatedIssues: ValidationIssue[] = [];

    if (schemas.params) {
      const parsed = schemas.params.safeParse(req.params);
      if (!parsed.success) {
        aggregatedIssues.push(...formatZodIssues('params', parsed.error));
      } else {
        req.params = parsed.data as Request['params'];
      }
    }

    if (schemas.query) {
      const parsed = schemas.query.safeParse(req.query);
      if (!parsed.success) {
        aggregatedIssues.push(...formatZodIssues('query', parsed.error));
      } else {
        req.query = parsed.data as Request['query'];
      }
    }

    if (schemas.headers) {
      const parsed = schemas.headers.safeParse(req.headers);
      if (!parsed.success) {
        aggregatedIssues.push(...formatZodIssues('headers', parsed.error));
      }
    }

    if (schemas.body) {
      const parsed = schemas.body.safeParse(req.body);
      if (!parsed.success) {
        aggregatedIssues.push(...formatZodIssues('body', parsed.error));
      } else {
        req.body = parsed.data;
      }
    }

    if (aggregatedIssues.length > 0) {
      next(
        new AppError({
          status: 422,
          code: 'validation-failed',
          title: 'Request Validation Failed',
          detail: 'One or more request fields failed schema validation.',
          errors: aggregatedIssues,
        }),
      );
      return;
    }

    next();
  };
}

/**
 * Enforces `Content-Type: application/json` on state-mutating HTTP methods (`POST`, `PUT`, `PATCH`),
 * blocking CSRF via HTML form-encoded submissions (`application/x-www-form-urlencoded`, `text/plain`).
 */
export const requireJsonContentType: RequestHandler = (
  req: Request,
  _res: Response,
  next: NextFunction,
): void => {
  const writeMethods = new Set(['POST', 'PUT', 'PATCH']);
  if (!writeMethods.has(req.method.toUpperCase())) {
    next();
    return;
  }

  if (!req.is('application/json')) {
    next(
      new AppError({
        status: 415,
        code: 'unsupported-media-type',
        title: 'Unsupported Media Type',
        detail: 'Requests mutating state must specify Content-Type: application/json.',
      }),
    );
    return;
  }

  next();
};

/**
 * Route-granular payload size check inspecting `Content-Length` and serialized body byte length
 * to reject oversized payloads early with HTTP 413 Content Too Large.
 */
export function enforcePayloadSize(maxBytes: number): RequestHandler {
  return (req: Request, _res: Response, next: NextFunction): void => {
    const contentLengthHeader = req.header('content-length');
    if (contentLengthHeader) {
      const declaredBytes = Number.parseInt(contentLengthHeader, 10);
      if (!Number.isNaN(declaredBytes) && declaredBytes > maxBytes) {
        next(
          new AppError({
            status: 413,
            code: 'payload-too-large',
            title: 'Content Too Large',
            detail: `Request payload exceeds the ${maxBytes}-byte limit for this endpoint.`,
          }),
        );
        return;
      }
    }

    if (req.body !== undefined && req.body !== null) {
      const bodyBytes = Buffer.byteLength(JSON.stringify(req.body), 'utf8');
      if (bodyBytes > maxBytes) {
        next(
          new AppError({
            status: 413,
            code: 'payload-too-large',
            title: 'Content Too Large',
            detail: `Request payload exceeds the ${maxBytes}-byte limit for this endpoint.`,
          }),
        );
        return;
      }
    }

    next();
  };
}
