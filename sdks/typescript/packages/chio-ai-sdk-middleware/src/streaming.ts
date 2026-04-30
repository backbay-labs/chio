export function isReadableStreamLike(value: unknown): value is ReadableStream<unknown> {
  return value instanceof ReadableStream
    || (
      value != null
      && typeof value === "object"
      && "getReader" in value
      && typeof (value as { getReader?: unknown }).getReader === "function"
    );
}

export function isAsyncIterable(value: unknown): value is AsyncIterable<unknown> {
  return (
    value != null
    && typeof value === "object"
    && Symbol.asyncIterator in value
    && typeof (value as { [Symbol.asyncIterator]?: unknown })[Symbol.asyncIterator] === "function"
  );
}
