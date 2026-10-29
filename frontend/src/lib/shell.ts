/** POSIX shell single-quoting: the value stays one literal word whatever it contains. */
export function shellQuote(s: string): string {
  return `'${s.replace(/'/g, `'\\''`)}'`;
}

/** Text for a `# comment` line of a snippet: control characters (a newline would end the comment) become spaces. */
export function commentText(s: string): string {
  // eslint-disable-next-line no-control-regex
  return s.replace(/[\u0000-\u001f\u007f-\u009f\u2028\u2029]+/g, ' ');
}
