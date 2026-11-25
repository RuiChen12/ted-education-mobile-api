export const JWT_ISSUER = 'ted-education-api';
export const JWT_AUDIENCE = 'ted-mobile';
export const JWT_ALGORITHM = 'HS256' as const;

export const JWT_ACCESS_DURATION = '15m' as const;
export const JWT_ACCESS_SECONDS = 900;


export const UUID_V4_PATTERN =
  /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}(?![\s\S])/i;

export const REFRESH_TOKEN_PATTERN =
  /^([0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12})\.([A-Za-z0-9_-]{43})(?![\s\S])/i;

export function isSessionVersion(
  value: unknown,
): value is number {
  return (
    typeof value === 'number' &&
    Number.isSafeInteger(value) &&
    value >= 0 &&
    value <= 2147483647
  );
}
