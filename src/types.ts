export type { Tuple, FilterTuple, FilterTupleExclude };

type Tuple<T = any> = [T, ...T[]] | [];

type FilterTupleExclude<T extends readonly any[], E> = T extends [
  infer F,
  ...infer R
]
  ? [F] extends [E]
    ? FilterTuple<R, E>
    : [F, ...FilterTuple<R, E>]
  : [];

type FilterTuple<T extends readonly any[], E> = T extends [infer F, ...infer R]
  ? [F] extends [E]
    ? [F, ...FilterTuple<R, E>]
    : FilterTuple<R, E>
  : [];
