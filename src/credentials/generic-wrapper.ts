/**
 * Generic subclasses
 */

class AnimalBase<T = any, Animal = any> {
  // some shape depending on generic type
  property: T;

  constructor(animal: { property: T }) {
    this.property = animal.property;
  }

  // some method depending on a concrete argument
  get default(): T {
    throw Error('needs subclass');
  }

  // returns a function wrapping the base type in a _generic_ subclass
  get Constructor(): (a: AnimalBase<T>) => Animal {
    throw Error('needs subclass');
  }

  // some method depending _on the generic subclass_
  copy(newDefault: T): Animal {
    let NewAnimal = Animal(newDefault);
    return this.Constructor(new NewAnimal(this));
  }
}

// adding _generic_ static methods
function AnimalBaseFactory<T, Animal>(): typeof AnimalBase<T, Animal> & {
  from(t: T): Animal;
} {
  return class Animal_ extends AnimalBase<T, Animal> {
    static from(t: T): Animal {
      return this.prototype.Constructor(new this({ property: t }));
    }
  };
}

// concretize the base class into a _generic_ subclass -- needed to fix the second generic argument!
// (note how the type is recursive but it works just fine)
class GenericAnimal<T> extends AnimalBase<T, GenericAnimal<T>> {}

function Animal<T>(
  defaultProp: T
): typeof GenericAnimal<T> &
  ReturnType<typeof AnimalBaseFactory<T, GenericAnimal<T>>> {
  return class Animal_ extends AnimalBaseFactory<T, GenericAnimal<T>>() {
    get Constructor(): (a: AnimalBase<T>) => GenericAnimal<T> {
      return (a) => new (Animal<T>(a.default))(a);
    }
    get default(): T {
      return defaultProp;
    }
  };
}

type T = 'one' | 'two' | 'three';
const one = 'one';
const two = 'two';
const three = 'three';

const MyAnimal = Animal<T>(one);

let animal = new MyAnimal({ property: two });
let animal2 = MyAnimal.from(two);
console.log(animal.property === animal2.property);

let a = animal.copy(two);
let b = a.copy(one);
console.log(a.property === b.property);
console.log(a.default !== b.default);

class DogBase extends AnimalBaseFactory<'one' | 'three', DogBase>() {
  bark() {
    return this.property;
  }
}

function Dog(defaultProp: 'one' | 'three'): typeof DogBase {
  return class Dog_ extends DogBase {
    get Constructor(): (a: AnimalBase<'one' | 'three'>) => DogBase {
      return (a) => new (Dog(a.default))(a);
    }
    get default() {
      return defaultProp;
    }
  };
}

const MyDog = Dog(one);

let c = MyDog.from(three);
let d = c.copy(three);
console.log(c.bark() === d.bark());
console.log(c.default !== d.default);
