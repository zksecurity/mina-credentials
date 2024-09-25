export type { Tuple, Flatten, FilterTuple, FilterTupleExclude };

type Tuple<T = any> = [T, ...T[]] | [];

type Flatten<T> = T extends []
  ? []
  : T extends [infer T0]
  ? [...Flatten<T0>]
  : T extends [infer T0, ...infer Ts]
  ? [...Flatten<T0>, ...Flatten<Ts>]
  : [T];

type FilterTupleExclude<T extends readonly any[], E> = T extends [
  infer F,
  ...infer R
]
  ? [F] extends [E]
    ? FilterTupleExclude<R, E>
    : [F, ...FilterTupleExclude<R, E>]
  : [];

type FilterTuple<T extends readonly any[], E> = T extends [infer F, ...infer R]
  ? [F] extends [E]
    ? [F, ...FilterTuple<R, E>]
    : FilterTuple<R, E>
  : [];
