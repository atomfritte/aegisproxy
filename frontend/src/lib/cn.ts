/** Joins truthy class names: cn('a', cond && 'b') */
export function cn(...parts: Array<string | false | null | undefined | 0>): string {
  return parts.filter(Boolean).join(' ');
}
