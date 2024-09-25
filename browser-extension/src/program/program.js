import { Field, PublicKey, Signature, ZkProgram } from 'o1js';

let zkProgram = ZkProgram({
  name: 'AgeCheck',
  publicInput: Field,
  publicOutput: PublicKey,
  methods: {
    verifyAge: {
      privateInputs: [Field, PublicKey, Signature],
      async method(minAge, age, issuerPubKey, signature) {
        const validSignature = signature.verify(issuerPubKey, [age]);
        validSignature.assertTrue();

        age.assertGreaterThanOrEqual(minAge);

        return issuerPubKey;
      },
    },
  },
});

export { zkProgram };
