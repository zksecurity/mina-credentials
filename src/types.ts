export type {
  Tuple,
  Flatten,
  FilterTuple,
  ExcludeFromTuple,
  ExcludeFromRecord,
  Constructor,
  JSONValue,
};

type Tuple<T = any> = [T, ...T[]] | [];

type Flatten<T> = T extends []
  ? []
  : T extends [infer T0]
  ? [...Flatten<T0>]
  : T extends [infer T0, ...infer Ts]
  ? [...Flatten<T0>, ...Flatten<Ts>]
  : [T];

type ExcludeFromTuple<T extends readonly any[], E> = T extends [
  infer F,
  ...infer R
]
  ? [F] extends [E]
    ? ExcludeFromTuple<R, E>
    : [F, ...ExcludeFromTuple<R, E>]
  : [];

type FilterTuple<T extends readonly any[], E> = T extends [infer F, ...infer R]
  ? [F] extends [E]
    ? [F, ...FilterTuple<R, E>]
    : FilterTuple<R, E>
  : [];

type ExcludeFromRecord<T, E> = {
  [P in keyof T as T[P] extends E ? never : P]: T[P];
};

type Constructor<T> = new (...args: any) => T;

type JSONValue =
  | string
  | number
  | boolean
  | null
  | JSONValue[]
  | { [key: string]: JSONValue };
